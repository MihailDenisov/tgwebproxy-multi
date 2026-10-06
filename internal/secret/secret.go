// Package secret parses MTProxy secrets and computes the bridge capability.
// Reference: MTP::ProxyData (Telegram/SourceFiles/mtproto/mtproto_proxy_data.cpp)
// for the accepted secret shapes and MTP::WebProxyBridgeCapability for the
// capability, both in tdesktop.
package secret

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// capabilityContext is the domain-separation prefix from
// ComputeWebProxyBridgeCapability. The trailing newline is part of it.
const capabilityContext = "tdesktop-web-proxy-bridge-v1\n"

var (
	// ErrFakeTLS reports an ee-prefixed secret. Telegram Desktop marks those
	// Unsupported for the Web proxy type: the HTTPS carrier already provides
	// the camouflage that fake-TLS exists for.
	ErrFakeTLS  = errors.New("secret: fake-TLS (ee) secrets are not supported by the WEB proxy type")
	ErrShape    = errors.New("secret: must be 16 bytes, or 17 bytes starting with dd")
	ErrEncoding = errors.New("secret: not valid hex or base64url")
)

type Secret struct {
	raw []byte
}

// Parse accepts hex or unpadded base64url, and exactly the shapes the client
// considers Valid for a Web proxy: 16 bytes, or 17 bytes with a 0xDD
// (padded-intermediate) prefix. Anything else is rejected here rather than
// discovered later as a client that silently refuses to connect.
func Parse(text string) (Secret, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return Secret{}, ErrEncoding
	}

	var raw []byte
	if isHex(text) {
		decoded, err := hex.DecodeString(text)
		if err != nil {
			return Secret{}, fmt.Errorf("%w: %v", ErrEncoding, err)
		}
		raw = decoded
	} else {
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(text, "="))
		if err != nil {
			return Secret{}, fmt.Errorf("%w: %v", ErrEncoding, err)
		}
		raw = decoded
	}

	switch {
	case len(raw) >= 21 && raw[0] == 0xEE:
		return Secret{}, ErrFakeTLS
	case len(raw) == 16:
	case len(raw) == 17 && raw[0] == 0xDD:
	default:
		return Secret{}, ErrShape
	}
	return Secret{raw: raw}, nil
}

func Generate() (Secret, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return Secret{}, err
	}
	return Secret{raw: raw}, nil
}

func isHex(text string) bool {
	if len(text) < 32 || len(text)%2 == 1 {
		return false
	}
	for _, ch := range text {
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'f':
		case ch >= 'A' && ch <= 'F':
		default:
			return false
		}
	}
	return true
}

func (s Secret) Valid() bool { return len(s.raw) > 0 }

// Bytes includes any dd prefix; this is the HMAC key for the capability.
func (s Secret) Bytes() []byte { return s.raw }

// Obfuscation returns the 16 bytes for obfuscated2 key derivation; a dd prefix
// is stripped, matching TcpConnection::Protocol::Create.
func (s Secret) Obfuscation() []byte {
	if len(s.raw) == 17 {
		return s.raw[1:]
	}
	return s.raw
}

// Equal compares two secrets in constant time. It decides whether a live
// session survives a reload, which is close enough to the credential path to
// be worth keeping constant time.
func (s Secret) Equal(other Secret) bool {
	return subtle.ConstantTimeCompare(s.raw, other.raw) == 1
}

func (s Secret) Hex() string { return hex.EncodeToString(s.raw) }

func (s Secret) Base64URL() string { return base64.RawURLEncoding.EncodeToString(s.raw) }

// Capability is the ?bridge= value: base64url_no_pad(HMAC_SHA256(secret,
// capabilityContext+host)). The host must already be normalised (lowercase
// punycode), because the client hashes its own normalised form.
func (s Secret) Capability(host string) string {
	mac := hmac.New(sha256.New, s.raw)
	mac.Write([]byte(capabilityContext))
	mac.Write([]byte(host))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// CheckCapability is constant time: this comparison is the only thing separating
// a visitor from a proxy user, and a timing oracle would confirm the domain
// hosts a proxy at all.
func (s Secret) CheckCapability(host, provided string) bool {
	if provided == "" {
		return false
	}
	expected := s.Capability(host)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) == 1
}
