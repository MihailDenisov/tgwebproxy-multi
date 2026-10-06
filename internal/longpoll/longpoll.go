// Package longpoll carries the transport over ordinary HTTP requests, for
// networks where a WebSocket does not survive.
//
// A session is two numbered streams of messages. The page POSTs uplink
// batches and holds a GET open for the downlink; the relay above sees the
// same message-oriented pipe it would get from a socket.
//
// Numbering is the whole design. An HTTP request can be retried by anything
// between the page and the relay, and a duplicated uplink batch would inject
// the same MTProto bytes twice and corrupt the stream. Every request therefore
// carries its sequence number, a repeat of the previous number is answered
// from the last result instead of being applied again, and anything else is
// refused.
package longpoll

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"
)

const (
	// TokenBytes is the length of a session token. It is a bearer credential
	// for one session, issued by the relay inside the bridge page.
	TokenBytes = 32
	// PollHold is how long a downlink request waits before answering empty.
	// Long enough to be cheap, short enough to look like a slow page rather
	// than an abandoned connection.
	PollHold = 25 * time.Second
	// IdleLifetime drops a session nothing has touched. The page reconnects
	// by loading a fresh bridge page, so nothing is lost but memory.
	IdleLifetime = 2 * time.Minute
	// MaxPending bounds the downlink queue of one session.
	MaxPending = 256
)

var (
	ErrUnknownSession = errors.New("longpoll: unknown session")
	ErrSequence       = errors.New("longpoll: unexpected sequence number")
	ErrClosed         = errors.New("longpoll: session closed")
)

// NewToken mints a session token.
func NewToken() (string, error) {
	raw := make([]byte, TokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Session is one client's transport. It satisfies the relay's message pipe.
type Session struct {
	token string

	mu     sync.Mutex
	wake   *sync.Cond
	closed bool

	// up holds messages the page has delivered but the relay has not read.
	up [][]byte
	// nextUp is the sequence number the next uplink request must carry.
	nextUp uint64

	// down holds messages the relay has written but no poll has collected.
	down [][]byte
	// nextDown is the cursor the next downlink request must carry.
	nextDown uint64
	// lastDown is the batch handed to cursor nextDown-1, kept so that a
	// retried poll gets the same bytes rather than losing them.
	lastDown [][]byte

	touched time.Time
}

func newSession(token string) *Session {
	s := &Session{token: token, touched: time.Now()}
	s.wake = sync.NewCond(&s.mu)
	return s
}

func (s *Session) Token() string { return s.token }

// ReadMessage returns one uplink message, blocking until one arrives.
func (s *Session) ReadMessage() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.up) == 0 && !s.closed {
		s.wake.Wait()
	}
	if len(s.up) == 0 {
		return nil, io.EOF
	}
	msg := s.up[0]
	s.up[0] = nil
	s.up = s.up[1:]
	return msg, nil
}

// WriteMessage queues one downlink message for the next poll.
func (s *Session) WriteMessage(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if len(s.down) >= MaxPending {
		// The page has stopped collecting. Dropping the session is the only
		// honest answer: silently discarding a frame would desynchronise a
		// stream, and growing without bound would be worse.
		s.closeLocked()
		return ErrClosed
	}
	s.down = append(s.down, data)
	s.wake.Broadcast()
	return nil
}

func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
	return nil
}

func (s *Session) closeLocked() {
	if s.closed {
		return
	}
	s.closed = true
	s.wake.Broadcast()
}

func (s *Session) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Deliver applies one uplink batch. A repeat of the previous sequence number
// is accepted and ignored, which is what makes a retried POST safe.
func (s *Session) Deliver(seq uint64, messages [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	s.touched = time.Now()
	switch {
	case seq == s.nextUp:
	case seq+1 == s.nextUp:
		return nil // already applied
	default:
		return ErrSequence
	}
	s.up = append(s.up, messages...)
	s.nextUp++
	s.wake.Broadcast()
	return nil
}

// Collect returns the downlink batch for cursor, waiting up to hold for
// something to send. A repeat of the previous cursor returns the same batch.
func (s *Session) Collect(cursor uint64, hold time.Duration) ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	s.touched = time.Now()

	if cursor+1 == s.nextDown {
		return s.lastDown, nil
	}
	if cursor != s.nextDown {
		return nil, ErrSequence
	}

	if len(s.down) == 0 {
		s.waitLocked(hold)
		if s.closed {
			return nil, ErrClosed
		}
	}
	if len(s.down) == 0 {
		// Nothing to send: the cursor does not move, and the page polls again.
		return nil, nil
	}
	batch := s.down
	s.down = nil
	s.lastDown = batch
	s.nextDown++
	return batch, nil
}

// waitLocked releases the lock for at most d while waiting to be woken.
func (s *Session) waitLocked(d time.Duration) {
	timer := time.AfterFunc(d, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.wake.Broadcast()
	})
	defer timer.Stop()

	deadline := time.Now().Add(d)
	for len(s.down) == 0 && !s.closed && time.Now().Before(deadline) {
		s.wake.Wait()
	}
}

// Manager owns the live sessions.
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	// lifetime is read only by Run, and set before it starts.
	lifetime time.Duration
}

// NewManager starts no goroutine: the caller owns the reaper's lifetime by
// calling Run, so nothing outlives the process that created it.
func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
		lifetime: IdleLifetime,
	}
}

// Create registers a session under a freshly minted token.
func (m *Manager) Create() (*Session, error) {
	token, err := NewToken()
	if err != nil {
		return nil, err
	}
	session := newSession(token)
	m.mu.Lock()
	m.sessions[token] = session
	m.mu.Unlock()
	return session, nil
}

func (m *Manager) Get(token string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[token]
	if !ok {
		return nil, ErrUnknownSession
	}
	return session, nil
}

func (m *Manager) Remove(token string) {
	m.mu.Lock()
	session, ok := m.sessions[token]
	delete(m.sessions, token)
	m.mu.Unlock()
	if ok {
		session.Close()
	}
}

func (m *Manager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// Shutdown closes every session.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	all := make([]*Session, 0, len(m.sessions))
	for token, session := range m.sessions {
		all = append(all, session)
		delete(m.sessions, token)
	}
	m.mu.Unlock()
	for _, session := range all {
		session.Close()
	}
}

// Run drops sessions nothing has touched, until the context is cancelled.
func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(m.lifetime / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.Shutdown()
			return
		case <-ticker.C:
			m.reapOnce(time.Now())
		}
	}
}

func (m *Manager) reapOnce(now time.Time) {
	m.mu.Lock()
	var dead []*Session
	for token, session := range m.sessions {
		session.mu.Lock()
		idle := now.Sub(session.touched)
		closed := session.closed
		session.mu.Unlock()
		if closed || idle > m.lifetime {
			dead = append(dead, session)
			delete(m.sessions, token)
		}
	}
	m.mu.Unlock()
	for _, session := range dead {
		session.Close()
	}
}
