// Package mtproto implements the obfuscated2 handshake a Telegram client speaks
// to an MTProxy and the matching one the proxy speaks to a data centre, after
// TcpConnection::prepareConnectionStartPrefix and TcpConnection::Protocol in
// tdesktop (Telegram/SourceFiles/mtproto/connection_tcp.cpp).
//
// Handshake layout, 64 bytes:
//
//	[0:56]   random, constrained by isGoodStartNonce
//	[8:40]   key material for the sender's direction
//	[40:56]  IV for the sender's direction
//	[56:60]  protocol tag
//	[60:62]  data-centre id, little-endian int16
//	[62:64]  random
//
// The first 56 bytes travel in the clear and the last 8 encrypted: the sender
// encrypts the whole block with its send key, then overwrites the first 56
// bytes with the plaintext copy.
package mtproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const HandshakeSize = 64

// Transport tags, chosen in TcpConnection::Protocol::Create: a bare 16-byte
// secret yields Abridged, a dd-prefixed secret yields PaddedIntermediate.
const (
	Abridged           uint32 = 0xEFEFEFEF
	Intermediate       uint32 = 0xEEEEEEEE
	PaddedIntermediate uint32 = 0xDDDDDDDD
)

var (
	ErrHandshakeSize = errors.New("mtproto: handshake must be 64 bytes")
	ErrProtocolTag   = errors.New("mtproto: unknown transport tag")
)

// KnownProtocol doubles as secret verification: the tag is the first field
// that must decrypt to something meaningful, so a wrong secret shows up here
// as an unknown tag, which is how a real MTProxy tells a client from a scanner.
func KnownProtocol(tag uint32) bool {
	switch tag {
	case Abridged, Intermediate, PaddedIntermediate:
		return true
	}
	return false
}

func ProtocolName(tag uint32) string {
	switch tag {
	case Abridged:
		return "abridged"
	case Intermediate:
		return "intermediate"
	case PaddedIntermediate:
		return "padded-intermediate"
	}
	return fmt.Sprintf("0x%08X", tag)
}

type keys struct {
	key [32]byte
	iv  [16]byte
}

func (k keys) stream() (cipher.Stream, error) {
	block, err := aes.NewCipher(k.key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, k.iv[:]), nil
}

// deriveKey mirrors Protocol::prepareKey. With no secret the key material is
// used verbatim (Version0); with a secret it is SHA-256 of the material
// followed by the secret (Version1 and VersionD).
func deriveKey(material, secret []byte) [32]byte {
	var out [32]byte
	if len(secret) == 0 {
		copy(out[:], material)
		return out
	}
	h := sha256.New()
	h.Write(material)
	h.Write(secret)
	sum := h.Sum(nil)
	copy(out[:], sum)
	return out
}

// directions derives both key sets from one preamble: the sender's direction
// reads bytes 8..56 forwards, the receiver's reads them reversed, so both
// sides get both keys from the same bytes and neither keystream is reusable.
func directions(handshake []byte, secret []byte) (forward, backward keys) {
	forward.key = deriveKey(handshake[8:40], secret)
	copy(forward.iv[:], handshake[40:56])

	reversed := make([]byte, 48)
	copy(reversed, handshake[8:56])
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	backward.key = deriveKey(reversed[0:32], secret)
	copy(backward.iv[:], reversed[32:48])
	return forward, backward
}

type ClientHello struct {
	Protocol uint32
	// DCID is raw: negative for the media cluster, +10000 for the test cluster.
	DCID    int16
	Decrypt cipher.Stream
	Encrypt cipher.Stream
}

// AcceptClient parses a client preamble. secret is the 16-byte obfuscation key
// (a dd-prefixed secret contributes only its tail). ErrProtocolTag means a
// wrong secret or a probe; do not reveal the difference to the peer.
func AcceptClient(handshake []byte, secret []byte) (*ClientHello, error) {
	if len(handshake) != HandshakeSize {
		return nil, ErrHandshakeSize
	}
	// Running the stream over all 64 bytes recovers the encrypted tail and
	// leaves the counter where the client's counter is.
	fromClient, toClient := directions(handshake, secret)
	decrypt, err := fromClient.stream()
	if err != nil {
		return nil, err
	}
	plain := make([]byte, HandshakeSize)
	decrypt.XORKeyStream(plain, handshake)

	tag := binary.LittleEndian.Uint32(plain[56:60])
	if !KnownProtocol(tag) {
		return nil, ErrProtocolTag
	}
	encrypt, err := toClient.stream()
	if err != nil {
		return nil, err
	}
	return &ClientHello{
		Protocol: tag,
		DCID:     int16(binary.LittleEndian.Uint16(plain[60:62])),
		Decrypt:  decrypt,
		Encrypt:  encrypt,
	}, nil
}

type ServerHello struct {
	Wire    []byte
	Encrypt cipher.Stream
	Decrypt cipher.Stream
}

// NewHandshake mints an outbound preamble: with an empty secret to dial a data
// centre, with a secret to impersonate a client.
func NewHandshake(protocol uint32, dcID int16, secret []byte) (*ServerHello, error) {
	if !KnownProtocol(protocol) {
		return nil, ErrProtocolTag
	}
	nonce := make([]byte, HandshakeSize)
	for {
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		if goodStartNonce(nonce) {
			break
		}
	}
	binary.LittleEndian.PutUint32(nonce[56:60], protocol)
	binary.LittleEndian.PutUint16(nonce[60:62], uint16(dcID))

	ours, theirs := directions(nonce, secret)
	encrypt, err := ours.stream()
	if err != nil {
		return nil, err
	}
	decrypt, err := theirs.stream()
	if err != nil {
		return nil, err
	}

	wire := make([]byte, HandshakeSize)
	copy(wire, nonce[:56])
	encrypted := make([]byte, HandshakeSize)
	encrypt.XORKeyStream(encrypted, nonce)
	copy(wire[56:], encrypted[56:])

	return &ServerHello{Wire: wire, Encrypt: encrypt, Decrypt: decrypt}, nil
}

// goodStartNonce is AbstractSocket::IsGoodStartNonce from tdesktop: excluded
// prefixes would make the preamble look like HTTP, a TLS record, or a tag.
func goodStartNonce(nonce []byte) bool {
	if len(nonce) < 8 {
		return false
	}
	if nonce[0] == 0xEF {
		return false
	}
	first := binary.LittleEndian.Uint32(nonce[0:4])
	second := binary.LittleEndian.Uint32(nonce[4:8])
	switch first {
	case 0x44414548, // "HEAD"
		0x54534F50, // "POST"
		0x20544547, // "GET "
		0xEEEEEEEE,
		0xDDDDDDDD,
		0x02010316: // TLS record header
		return false
	}
	return second != 0
}
