// Package twin drives a relay the way Telegram Desktop 7.1.1 does. Every rule
// it enforces has a matching rejection in Transport::Private::processRelayFrame
// or WebviewCarrier::handleBinary. The e2e test and the probe command share it.
package twin

import (
	"crypto/cipher"
	"fmt"
	"sync"
	"time"

	"tgwebproxy/internal/frame"
	"tgwebproxy/internal/mtproto"
	"tgwebproxy/internal/secret"
)

type Transport interface {
	Send([]byte) error
	Receive() ([]byte, error)
	Close() error
}

type Twin struct {
	transport Transport
	secret    secret.Secret

	mu       sync.Mutex
	streams  map[uint32]*Stream
	welcomed bool
	nextID   uint32
}

type Stream struct {
	id      uint32
	encrypt cipher.Stream
	decrypt cipher.Stream
	// credit mirrors the client's per-stream receiveWindow.
	credit  int64
	inbound chan []byte
	closed  chan struct{}
	once    sync.Once
}

func (t *Twin) Transport() Transport { return t.transport }

func NewTwin(transport Transport, sec secret.Secret) *Twin {
	return &Twin{
		transport: transport,
		secret:    sec,
		streams:   make(map[uint32]*Stream),
		nextID:    1,
	}
}

func (t *Twin) Handshake() error {
	hello, err := frame.Marshal(frame.Hello, 0, []byte{frame.HelloVersion})
	if err != nil {
		return err
	}
	if err := t.transport.Send(hello); err != nil {
		return err
	}
	msg, err := t.transport.Receive()
	if err != nil {
		return fmt.Errorf("waiting for welcome: %w", err)
	}
	frames, err := frame.Parse(msg)
	if err != nil {
		return fmt.Errorf("welcome message: %w", err)
	}
	// WebviewCarrier::handleBinary requires the very first binary message to
	// be exactly one empty Welcome on stream 0 and nothing else.
	if len(frames) != 1 {
		return fmt.Errorf("welcome message carried %d frames, want 1", len(frames))
	}
	f := frames[0]
	if f.Type != frame.Welcome || f.StreamID != 0 || len(f.Payload) != 0 {
		return fmt.Errorf("bad welcome: %v on stream %d with %d bytes",
			f.Type, f.StreamID, len(f.Payload))
	}
	t.mu.Lock()
	t.welcomed = true
	t.mu.Unlock()
	return nil
}

func (t *Twin) Open(protocol uint32, dcID int16) (*Stream, error) {
	t.mu.Lock()
	id := t.nextID
	t.nextID++
	hello, err := mtproto.NewHandshake(protocol, dcID, t.secret.Obfuscation())
	if err != nil {
		t.mu.Unlock()
		return nil, err
	}
	st := &Stream{
		id:      id,
		encrypt: hello.Encrypt,
		decrypt: hello.Decrypt,
		credit:  frame.InitialWindow,
		inbound: make(chan []byte, 64),
		closed:  make(chan struct{}),
	}
	t.streams[id] = st
	t.mu.Unlock()

	open, err := frame.Marshal(frame.Open, id, nil)
	if err != nil {
		return nil, err
	}
	if err := t.transport.Send(open); err != nil {
		return nil, err
	}
	if err := t.sendData(st, hello.Wire); err != nil {
		return nil, err
	}
	return st, nil
}

func (t *Twin) Write(st *Stream, plain []byte) error {
	sealed := make([]byte, len(plain))
	st.encrypt.XORKeyStream(sealed, plain)
	return t.sendData(st, sealed)
}

func (t *Twin) sendData(st *Stream, payload []byte) error {
	msg, err := frame.Marshal(frame.Data, st.id, payload)
	if err != nil {
		return err
	}
	return t.transport.Send(msg)
}

func (t *Twin) Read(st *Stream, timeout time.Duration) ([]byte, error) {
	select {
	case chunk, ok := <-st.inbound:
		if !ok {
			return nil, fmt.Errorf("stream %d closed", st.id)
		}
		return chunk, nil
	case <-st.closed:
		return nil, fmt.Errorf("stream %d closed by the relay", st.id)
	case <-time.After(timeout):
		return nil, fmt.Errorf("stream %d: timed out", st.id)
	}
}

// Pump returns the first client-rule violation it sees, or the transport error.
func (t *Twin) Pump() error {
	for {
		msg, err := t.transport.Receive()
		if err != nil {
			return err
		}
		frames, err := frame.Parse(msg)
		if err != nil {
			return fmt.Errorf("relay sent an unparsable message: %w", err)
		}
		// A relay message may carry a batch: Telegram's reference relay packs
		// up to 4096 frames into one, and its bridge page hands the message to
		// the client whole.
		if len(frames) == 0 {
			return fmt.Errorf("relay sent an empty message")
		}
		for _, f := range frames {
			if err := t.handle(f); err != nil {
				return err
			}
		}
	}
}

func (t *Twin) handle(f frame.Frame) error {
	if !f.Type.SendableByRelay() {
		return fmt.Errorf("relay sent %v, which the client has no handler for", f.Type)
	}
	if f.StreamID == 0 {
		switch f.Type {
		case frame.Ping:
			if len(f.Payload) > frame.MaxPingPayload {
				return fmt.Errorf("ping payload of %d bytes", len(f.Payload))
			}
			pong, err := frame.Marshal(frame.Pong, 0, f.Payload)
			if err != nil {
				return err
			}
			return t.transport.Send(pong)
		case frame.Welcome:
			return fmt.Errorf("relay sent a second welcome")
		case frame.Bye:
			return fmt.Errorf("relay said goodbye")
		default:
			return fmt.Errorf("relay sent %v on stream 0", f.Type)
		}
	}

	t.mu.Lock()
	st := t.streams[f.StreamID]
	t.mu.Unlock()
	if st == nil {
		// The client tolerates late frames only for streams it just closed.
		return nil
	}

	switch f.Type {
	case frame.Data:
		if len(f.Payload) == 0 {
			return fmt.Errorf("relay sent an empty data frame")
		}
		if int64(len(f.Payload)) > st.credit {
			return fmt.Errorf("relay overran the send window on stream %d: %d bytes with %d credit",
				st.id, len(f.Payload), st.credit)
		}
		st.credit -= int64(len(f.Payload))
		plain := make([]byte, len(f.Payload))
		st.decrypt.XORKeyStream(plain, f.Payload)
		select {
		case st.inbound <- plain:
		case <-st.closed:
		}
		// Hand the credit straight back, as WebProxySocket::read does.
		grant := uint32(len(f.Payload))
		st.credit += int64(grant)
		msg, err := frame.Marshal(frame.Window, st.id, frame.WindowPayload(grant))
		if err != nil {
			return err
		}
		return t.transport.Send(msg)
	case frame.Window:
		if _, ok := frame.ReadWindow(f.Payload); !ok {
			return fmt.Errorf("relay sent a malformed window frame")
		}
		return nil
	case frame.Close:
		if len(f.Payload) != 0 {
			return fmt.Errorf("relay sent a close frame with a payload")
		}
		st.once.Do(func() { close(st.closed) })
		t.mu.Lock()
		delete(t.streams, f.StreamID)
		t.mu.Unlock()
		return nil
	default:
		return fmt.Errorf("relay sent %v on stream %d", f.Type, f.StreamID)
	}
}
