package secret

import (
	"errors"
	"testing"
)

// Vectors lifted from the debug assertions in MTP::WebProxyBridgeCapability
// (tdesktop), the only public ground truth for the capability formula.
func TestCapabilityVectorsFromTdesktop(t *testing.T) {
	const host = "proxy.example.com"
	cases := []struct {
		secret string
		want   string
	}{
		{"000102030405060708090a0b0c0d0e0f", "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk"},
		{"dd000102030405060708090a0b0c0d0e0f", "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA"},
	}
	for _, c := range cases {
		s, err := Parse(c.secret)
		if err != nil {
			t.Fatalf("Parse(%s): %v", c.secret, err)
		}
		if got := s.Capability(host); got != c.want {
			t.Errorf("Capability(%s) = %s, want %s", c.secret, got, c.want)
		}
		if !s.CheckCapability(host, c.want) {
			t.Errorf("CheckCapability rejected its own capability for %s", c.secret)
		}
		if s.CheckCapability(host, c.want[:len(c.want)-1]+"X") {
			t.Errorf("CheckCapability accepted a corrupted capability for %s", c.secret)
		}
		if s.CheckCapability("other.example.com", c.want) {
			t.Errorf("capability must be bound to the host, %s", c.secret)
		}
	}
}

func TestCapabilityKeyIncludesDDPrefix(t *testing.T) {
	// The dd byte is part of the HMAC key, unlike the obfuscation key.
	plain, err := Parse("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	padded, err := Parse("dd000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	if plain.Capability("h.example.com") == padded.Capability("h.example.com") {
		t.Fatal("dd prefix must change the capability")
	}
}

func TestObfuscationKeyStripsDD(t *testing.T) {
	padded, err := Parse("dd000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	key := padded.Obfuscation()
	if len(key) != 16 {
		t.Fatalf("obfuscation key length = %d, want 16", len(key))
	}
	if key[0] != 0x00 {
		t.Fatalf("dd prefix must be stripped, got % x", key[:2])
	}
	if len(padded.Bytes()) != 17 {
		t.Fatal("Bytes must keep the dd prefix")
	}
}

func TestParseShapes(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr error
	}{
		{"16 byte hex", "000102030405060708090a0b0c0d0e0f", nil},
		{"16 byte hex uppercase", "000102030405060708090A0B0C0D0E0F", nil},
		{"17 byte dd hex", "dd000102030405060708090a0b0c0d0e0f", nil},
		{"16 byte base64url", "AAECAwQFBgcICQoLDA0ODw", nil},
		{"fake tls", "ee000102030405060708090a0b0c0d0e0f6578616d706c652e636f6d", ErrFakeTLS},
		{"17 byte without dd", "ab000102030405060708090a0b0c0d0e0f", ErrShape},
		{"too short", "0001020304", ErrShape},
		{"garbage", "not-a-secret!!", ErrEncoding},
		{"empty", "", ErrEncoding},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(c.in)
			if c.wantErr == nil {
				if err != nil {
					t.Fatalf("Parse: unexpected error %v", err)
				}
				return
			}
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("Parse error = %v, want %v", err, c.wantErr)
			}
		})
	}
}

func TestEncodingRoundTrip(t *testing.T) {
	s, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	fromHex, err := Parse(s.Hex())
	if err != nil {
		t.Fatalf("Parse(Hex): %v", err)
	}
	fromB64, err := Parse(s.Base64URL())
	if err != nil {
		t.Fatalf("Parse(Base64URL): %v", err)
	}
	host := "proxy.example.com"
	if fromHex.Capability(host) != s.Capability(host) {
		t.Fatal("hex round trip changed the secret")
	}
	if fromB64.Capability(host) != s.Capability(host) {
		t.Fatal("base64url round trip changed the secret")
	}
}
