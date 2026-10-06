package httpfront

import (
	"errors"
	"fmt"

	"tgwebproxy/internal/secret"
)

// ClientDomain is one management snapshot. Entries are copied and safe for callers to inspect.
type ClientDomain struct {
	Domain  string
	Entries []secret.Entry
}

// ClientSnapshot returns the currently active desired client configuration.
func (h *Handler) ClientSnapshot() []ClientDomain {
	state := h.live.Load()
	out := make([]ClientDomain, 0, len(state.byHost))
	for _, d := range state.order() {
		out = append(out, ClientDomain{Domain: d.name, Entries: d.keyring.Entries()})
	}
	return out
}

// ReplaceClients atomically swaps the clients for one already configured domain.
// Domains themselves remain static because capabilities and the public TLS routing
// are bound to the hostname.
func (h *Handler) ReplaceClients(domain string, entries []secret.Entry) error {
	if len(entries) == 0 {
		return errors.New("httpfront: a domain must keep at least one client")
	}
	current := h.live.Load()
	existing, ok := current.byHost[domain]
	if !ok {
		return fmt.Errorf("httpfront: unknown domain %q", domain)
	}
	keyring, err := secret.NewKeyring(domain, entries)
	if err != nil {
		return err
	}

	next := &liveState{
		byHost:     make(map[string]*domainState, len(current.byHost)),
		maxStreams: current.maxStreams,
	}
	for name, d := range current.byHost {
		if name == domain {
			d = &domainState{name: d.name, keyring: keyring, cover: d.cover}
		}
		next.byHost[name] = d
		if current.fallback == existing && name == domain {
			next.fallback = d
		}
	}
	if next.fallback == nil {
		next.fallback = current.fallback
	}
	h.live.Store(next)
	if dropped := h.sessions.revokeMissing(next); len(dropped) > 0 {
		h.log.Info("client policy changed, sessions closed", "labels", dropped)
	}
	return nil
}
