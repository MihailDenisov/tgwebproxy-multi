package mtproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func testSecret() []byte {
	return []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
}

func TestHandshakeRoundTrip(t *testing.T) {
	for _, tag := range []uint32{Abridged, Intermediate, PaddedIntermediate} {
		t.Run(ProtocolName(tag), func(t *testing.T) {
			secret := testSecret()
			client, err := NewHandshake(tag, 2, secret)
			if err != nil {
				t.Fatalf("NewHandshake: %v", err)
			}
			if len(client.Wire) != HandshakeSize {
				t.Fatalf("wire length = %d, want %d", len(client.Wire), HandshakeSize)
			}

			server, err := AcceptClient(client.Wire, secret)
			if err != nil {
				t.Fatalf("AcceptClient: %v", err)
			}
			if server.Protocol != tag {
				t.Errorf("protocol = %s, want %s", ProtocolName(server.Protocol), ProtocolName(tag))
			}
			if server.DCID != 2 {
				t.Errorf("dc id = %d, want 2", server.DCID)
			}

			// client -> relay
			up := []byte("request bytes from the client")
			sealed := make([]byte, len(up))
			client.Encrypt.XORKeyStream(sealed, up)
			if bytes.Equal(sealed, up) {
				t.Fatal("client stream did not encrypt")
			}
			opened := make([]byte, len(sealed))
			server.Decrypt.XORKeyStream(opened, sealed)
			if !bytes.Equal(opened, up) {
				t.Fatalf("client->relay mismatch: %q", opened)
			}

			// relay -> client
			down := []byte("response bytes from the data centre")
			sealed = make([]byte, len(down))
			server.Encrypt.XORKeyStream(sealed, down)
			opened = make([]byte, len(sealed))
			client.Decrypt.XORKeyStream(opened, sealed)
			if !bytes.Equal(opened, down) {
				t.Fatalf("relay->client mismatch: %q", opened)
			}
		})
	}
}

func TestHandshakeCarriesDCIDSign(t *testing.T) {
	secret := testSecret()
	for _, want := range []int16{1, 2, 5, -2, -5, 10001, -10002} {
		client, err := NewHandshake(Abridged, want, secret)
		if err != nil {
			t.Fatalf("NewHandshake(%d): %v", want, err)
		}
		server, err := AcceptClient(client.Wire, secret)
		if err != nil {
			t.Fatalf("AcceptClient(%d): %v", want, err)
		}
		if server.DCID != want {
			t.Errorf("dc id = %d, want %d", server.DCID, want)
		}
	}
}

func TestWireKeepsFirst56BytesInClear(t *testing.T) {
	client, err := NewHandshake(Abridged, 1, testSecret())
	if err != nil {
		t.Fatal(err)
	}
	server, err := AcceptClient(client.Wire, testSecret())
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(client.Wire[56:60]) == Abridged {
		t.Fatal("protocol tag must not appear in the clear on the wire")
	}
	if server.Protocol != Abridged {
		t.Fatal("tag must decrypt back to the requested protocol")
	}
}

func TestAcceptClientRejectsWrongSecret(t *testing.T) {
	client, err := NewHandshake(Abridged, 1, testSecret())
	if err != nil {
		t.Fatal(err)
	}
	wrong := testSecret()
	wrong[0] ^= 0xFF
	if _, err := AcceptClient(client.Wire, wrong); !errors.Is(err, ErrProtocolTag) {
		t.Fatalf("error = %v, want %v", err, ErrProtocolTag)
	}
}

func TestAcceptClientRejectsGarbage(t *testing.T) {
	if _, err := AcceptClient(make([]byte, 63), testSecret()); !errors.Is(err, ErrHandshakeSize) {
		t.Fatalf("short handshake error = %v, want %v", err, ErrHandshakeSize)
	}
	if _, err := AcceptClient(make([]byte, HandshakeSize), testSecret()); !errors.Is(err, ErrProtocolTag) {
		t.Fatalf("zero handshake error = %v, want %v", err, ErrProtocolTag)
	}
}

func TestNewHandshakeRejectsUnknownTag(t *testing.T) {
	if _, err := NewHandshake(0x12345678, 1, nil); !errors.Is(err, ErrProtocolTag) {
		t.Fatalf("error = %v, want %v", err, ErrProtocolTag)
	}
}

func TestGeneratedNoncesAreGood(t *testing.T) {
	// The client rejects peer preambles failing isGoodStartNonce.
	for i := 0; i < 2000; i++ {
		hello, err := NewHandshake(Abridged, 1, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !goodStartNonce(hello.Wire) {
			t.Fatalf("generated a bad start nonce: % x", hello.Wire[:8])
		}
	}
}

func TestGoodStartNonceRules(t *testing.T) {
	base := make([]byte, HandshakeSize)
	for i := range base {
		base[i] = byte(i + 1)
	}
	if !goodStartNonce(base) {
		t.Fatal("baseline nonce should be good")
	}

	bad := func(mutate func([]byte)) bool {
		n := append([]byte(nil), base...)
		mutate(n)
		return goodStartNonce(n)
	}
	cases := map[string]func([]byte){
		"leading ef":   func(n []byte) { n[0] = 0xEF },
		"HEAD":         func(n []byte) { copy(n, "HEAD") },
		"POST":         func(n []byte) { copy(n, "POST") },
		"GET ":         func(n []byte) { copy(n, "GET ") },
		"intermediate": func(n []byte) { binary.LittleEndian.PutUint32(n[0:4], 0xEEEEEEEE) },
		"padded":       func(n []byte) { binary.LittleEndian.PutUint32(n[0:4], 0xDDDDDDDD) },
		"tls record":   func(n []byte) { binary.LittleEndian.PutUint32(n[0:4], 0x02010316) },
		"zero second":  func(n []byte) { binary.LittleEndian.PutUint32(n[4:8], 0) },
	}
	for name, mutate := range cases {
		if bad(mutate) {
			t.Errorf("%s must be rejected", name)
		}
	}
}

func TestDeriveKeyWithoutSecretIsVerbatim(t *testing.T) {
	// Version0::prepareKey copies the material; only Version1 hashes it.
	material := make([]byte, 32)
	for i := range material {
		material[i] = byte(i)
	}
	got := deriveKey(material, nil)
	if !bytes.Equal(got[:], material) {
		t.Fatalf("key = % x, want verbatim material", got)
	}
	hashed := deriveKey(material, testSecret())
	if bytes.Equal(hashed[:], material) {
		t.Fatal("key with a secret must be hashed")
	}
}
