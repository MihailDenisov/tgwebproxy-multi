package httpfront

import (
	"sync"

	"tgwebproxy/internal/secret"
)

// sessionRegistry tracks live relay sessions so that removing a secret from
// the configuration can disconnect the sessions it authorised.
type sessionRegistry struct {
	mu   sync.Mutex
	next uint64
	live map[uint64]liveSession
}

type liveSession struct {
	domain string
	entry  secret.Entry
	stop   func()
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{live: make(map[uint64]liveSession)}
}

func (s *sessionRegistry) add(domain string, entry secret.Entry, stop func()) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	id := s.next
	s.live[id] = liveSession{domain: domain, entry: entry, stop: stop}
	return id
}

func (s *sessionRegistry) remove(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.live, id)
}

// revokeMissing stops every session whose secret is no longer configured for
// its own domain, and returns the labels it stopped. Membership is by secret,
// so a renamed entry survives.
func (s *sessionRegistry) revokeMissing(state *liveState) []string {
	s.mu.Lock()
	var (
		stops   []func()
		dropped []string
	)
	for id, session := range s.live {
		if domain, served := state.byHost[session.domain]; served && domain.keyring.Contains(session.entry) {
			continue
		}
		stops = append(stops, session.stop)
		dropped = append(dropped, session.entry.Label)
		delete(s.live, id)
	}
	s.mu.Unlock()

	// Stopping outside the lock: stop closes a socket, which wakes a reader
	// that calls remove and would deadlock on the same mutex.
	for _, stop := range stops {
		stop()
	}
	return dropped
}
