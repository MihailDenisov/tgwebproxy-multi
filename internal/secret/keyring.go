package secret

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"time"
)

// Entry is one configured secret and the name an operator gave it. The label
// is for logs and metrics; it is not a credential.
type Entry struct {
	Secret      Secret
	Label       string
	Disabled    bool
	ExpiresUnix int64
	QuotaBytes  int64
}

func (e Entry) Active(now time.Time) bool {
	if e.Disabled {
		return false
	}
	return e.ExpiresUnix <= 0 || now.Unix() < e.ExpiresUnix
}

// Keyring matches a supplied bridge capability against every configured
// secret. Capabilities are bound to the host, so a ring serves one host.
type Keyring struct {
	host    string
	entries []Entry
	caps    []string
}

func NewKeyring(host string, entries []Entry) (*Keyring, error) {
	if host == "" {
		return nil, errors.New("secret: keyring needs a host")
	}
	if len(entries) == 0 {
		return nil, errors.New("secret: keyring needs at least one secret")
	}
	k := &Keyring{
		host:    host,
		entries: make([]Entry, 0, len(entries)),
		caps:    make([]string, 0, len(entries)),
	}
	for i, e := range entries {
		if !e.Secret.Valid() {
			return nil, fmt.Errorf("secret: entry %d has no secret", i)
		}
		if k.Contains(e) {
			return nil, fmt.Errorf("secret: entry %d (%s) repeats an earlier secret", i, e.Label)
		}
		k.entries = append(k.entries, e)
		k.caps = append(k.caps, e.Secret.Capability(host))
	}
	return k, nil
}

// Match compares provided against every capability without an early exit, so
// the time it takes reveals neither which entry matched nor whether one did.
// All capabilities are the same length, so length leaks nothing either.
func (k *Keyring) Match(provided string) (Entry, bool) {
	if provided == "" {
		return Entry{}, false
	}
	found, index := 0, 0
	for i, capability := range k.caps {
		eq := subtle.ConstantTimeCompare([]byte(capability), []byte(provided))
		index = subtle.ConstantTimeSelect(eq, i, index)
		found |= eq
	}
	if found != 1 {
		return Entry{}, false
	}
	entry := k.entries[index]
	if !entry.Active(time.Now()) {
		return Entry{}, false
	}
	return entry, true
}

// Contains reports membership by secret, ignoring the label: renaming an entry
// across a reload must not look like revoking it.
func (k *Keyring) Contains(e Entry) bool {
	for _, existing := range k.entries {
		if existing.Secret.Equal(e.Secret) && existing.Active(time.Now()) {
			return true
		}
	}
	return false
}

func (k *Keyring) Entries() []Entry {
	out := make([]Entry, len(k.entries))
	copy(out, k.entries)
	return out
}

func (k *Keyring) Host() string { return k.host }

func (k *Keyring) Len() int { return len(k.entries) }
