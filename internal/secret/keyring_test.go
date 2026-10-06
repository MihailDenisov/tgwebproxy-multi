package secret

import (
	"testing"
	"time"
)

func mustParse(t *testing.T, text string) Secret {
	t.Helper()
	s, err := Parse(text)
	if err != nil {
		t.Fatalf("Parse(%s): %v", text, err)
	}
	return s
}

func testEntries(t *testing.T) []Entry {
	t.Helper()
	return []Entry{
		{Secret: mustParse(t, "000102030405060708090a0b0c0d0e0f"), Label: "phone"},
		{Secret: mustParse(t, "dd0f0e0d0c0b0a09080706050403020100"), Label: "laptop"},
		{Secret: mustParse(t, "0f0e0d0c0b0a09080706050403020100"), Label: "tablet"},
	}
}

// Every entry must be reachable whatever its position: a ring that only ever
// matched its first entry would pass a single-secret test.
func TestMatchFindsEveryEntry(t *testing.T) {
	const host = "proxy.example.com"
	entries := testEntries(t)
	ring, err := NewKeyring(host, entries)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	for _, want := range entries {
		got, ok := ring.Match(want.Secret.Capability(host))
		if !ok {
			t.Fatalf("capability of %s did not match", want.Label)
		}
		if got.Label != want.Label {
			t.Errorf("matched %s, want %s", got.Label, want.Label)
		}
		if !got.Secret.Equal(want.Secret) {
			t.Errorf("matched the wrong secret for %s", want.Label)
		}
	}
}

func TestMatchRejects(t *testing.T) {
	const host = "proxy.example.com"
	entries := testEntries(t)
	ring, err := NewKeyring(host, entries)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	other := mustParse(t, "ffffffffffffffffffffffffffffffff")
	for _, provided := range []string{
		"",
		"definitely-not-a-capability",
		other.Capability(host),
		// The right secret bound to the wrong host must not match either.
		entries[0].Secret.Capability("other.example.com"),
	} {
		if entry, ok := ring.Match(provided); ok {
			t.Errorf("Match(%q) accepted it as %s", provided, entry.Label)
		}
	}
}

func TestNewKeyringRejectsBadInput(t *testing.T) {
	good := testEntries(t)
	if _, err := NewKeyring("", good); err == nil {
		t.Error("empty host must be rejected")
	}
	if _, err := NewKeyring("proxy.example.com", nil); err == nil {
		t.Error("empty keyring must be rejected")
	}
	duplicate := []Entry{good[0], {Secret: good[0].Secret, Label: "copy"}}
	if _, err := NewKeyring("proxy.example.com", duplicate); err == nil {
		t.Error("duplicate secret must be rejected")
	}
}

func TestContains(t *testing.T) {
	entries := testEntries(t)
	ring, err := NewKeyring("proxy.example.com", entries[:2])
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	if !ring.Contains(entries[0]) {
		t.Error("Contains must find a member")
	}
	if ring.Contains(entries[2]) {
		t.Error("Contains must reject a non-member")
	}
	if !ring.Contains(Entry{Secret: entries[0].Secret, Label: "renamed"}) {
		t.Error("Contains must compare secrets, not labels")
	}
}


func TestPolicyRejectsDisabledAndExpired(t *testing.T) {
	const host = "proxy.example.com"
	base := testEntries(t)[0]

	disabled := base
	disabled.Disabled = true
	ring, err := NewKeyring(host, []Entry{disabled})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ring.Match(disabled.Secret.Capability(host)); ok {
		t.Error("disabled client must not authenticate")
	}

	expired := base
	expired.ExpiresUnix = time.Now().Add(-time.Minute).Unix()
	ring, err = NewKeyring(host, []Entry{expired})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ring.Match(expired.Secret.Capability(host)); ok {
		t.Error("expired client must not authenticate")
	}

	future := base
	future.ExpiresUnix = time.Now().Add(time.Hour).Unix()
	ring, err = NewKeyring(host, []Entry{future})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ring.Match(future.Secret.Capability(host)); !ok {
		t.Error("unexpired client must authenticate")
	}
}
