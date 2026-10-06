// Package relay is the server half of the Telegram WEB-proxy transport: one
// session per bridge connection, many MTProto streams multiplexed inside it.
// The client half is Transport in tdesktop (web_proxy_transport.cpp); a single
// unexpected frame makes it drop the whole transport and every stream in it.
package relay

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"tgwebproxy/internal/dc"
	"tgwebproxy/internal/frame"
	"tgwebproxy/internal/mtproto"
	"tgwebproxy/internal/secret"
)

// MessageConn is the message-oriented transport a session runs over: a
// WebSocket in production, an in-memory pair in tests.
type MessageConn interface {
	ReadMessage() ([]byte, error)
	WriteMessage(data []byte) error
	// Close must unblock any pending ReadMessage.
	Close() error
}

type Upstream struct {
	Conn io.ReadWriteCloser
	Name string
}

type DialFunc func(ctx context.Context, protocol uint32, dcID int16) (*Upstream, error)

// Reporter receives counts for the admin listener. The relay never formats a
// metric itself, so it keeps no opinion about how they are exported.
type Reporter interface {
	StreamOpened()
	StreamClosed()
	// MessageWritten reports one transport message and how many more were
	// already queued behind it. The second number is what batching would
	// collapse, measured without changing what goes on the wire.
	MessageWritten(alsoQueued int)
	UpstreamDialFailed()
	ProtocolError()
	BytesUp(n int)
	BytesDown(n int)
}

type nopReporter struct{}

func (nopReporter) StreamOpened()       {}
func (nopReporter) MessageWritten(int)  {}
func (nopReporter) StreamClosed()       {}
func (nopReporter) UpstreamDialFailed() {}
func (nopReporter) ProtocolError()      {}
func (nopReporter) BytesUp(int)         {}
func (nopReporter) BytesDown(int)       {}

type Options struct {
	// Secret is the proxy secret; only its obfuscation half is used here.
	Secret secret.Secret
	// Dial opens upstreams. Defaults to dialling Telegram directly.
	Dial DialFunc
	// Logger receives session diagnostics. Never the peer.
	Logger       *slog.Logger
	MaxStreams   int
	PingInterval time.Duration
	// IdleTimeout closes a transport that has produced nothing for this long.
	// It also bounds the initial Hello.
	IdleTimeout time.Duration
	DialTimeout time.Duration
	// Metrics receives counts. Nil means no accounting.
	Metrics Reporter
}

func (o Options) withDefaults() Options {
	if o.Dial == nil {
		o.Dial = DialTelegram(o.DialTimeout)
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.MaxStreams <= 0 {
		o.MaxStreams = 64
	}
	if o.PingInterval <= 0 {
		o.PingInterval = 30 * time.Second
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 90 * time.Second
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 10 * time.Second
	}
	if o.Metrics == nil {
		o.Metrics = nopReporter{}
	}
	return o
}

// DialTelegram is the production dialer: resolve the DC id from the handshake
// and open an obfuscated connection to it.
func DialTelegram(timeout time.Duration) DialFunc {
	return func(ctx context.Context, protocol uint32, dcID int16) (*Upstream, error) {
		target, err := dc.Resolve(dcID)
		if err != nil {
			return nil, err
		}
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		conn, err := mtproto.DialDC(ctx, target, protocol, dcID, nil)
		if err != nil {
			return nil, err
		}
		return &Upstream{Conn: conn, Name: target.String()}, nil
	}
}

// ErrProtocol marks a peer that violated the transport contract. The peer is
// never told which rule it broke.
var ErrProtocol = errors.New("relay: protocol error")

// errBye is a clean close requested by the peer; Serve reports it as nil.
var errBye = errors.New("relay: bye")

func protoErrf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrProtocol, fmt.Sprintf(format, args...))
}

const closedStreamMemory = 4096

type session struct {
	conn MessageConn
	opts Options

	ctx    context.Context
	cancel context.CancelFunc

	out     chan []byte
	writeWG sync.WaitGroup

	mu      sync.Mutex
	streams map[uint32]*stream
	closed  map[uint32]struct{}
	closedQ []uint32

	activity atomic.Int64
	streamWG sync.WaitGroup
}

// Serve runs one session to completion. It returns nil on a clean close and an
// error describing why the transport was dropped otherwise.
func Serve(ctx context.Context, conn MessageConn, opts Options) error {
	opts = opts.withDefaults()
	ctx, cancel := context.WithCancel(ctx)
	s := &session{
		conn:    conn,
		opts:    opts,
		ctx:     ctx,
		cancel:  cancel,
		out:     make(chan []byte, 256),
		streams: make(map[uint32]*stream),
		closed:  make(map[uint32]struct{}),
	}
	s.touch()

	s.writeWG.Add(1)
	go s.writeLoop()
	go s.watchdog()

	err := s.readLoop()
	if err != nil && errors.Is(err, ErrProtocol) {
		opts.Metrics.ProtocolError()
	}

	s.cancel()
	s.shutdownStreams()
	s.writeWG.Wait()
	_ = conn.Close()
	s.streamWG.Wait()
	return err
}

func (s *session) readLoop() error {
	// Handshake. Transport::Private::startBrowser sends Hello with a single
	// version byte and expects Welcome within 30 seconds.
	first, err := s.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("read hello: %w", err)
	}
	frames, err := frame.Parse(first)
	if err != nil {
		return protoErrf("hello message: %v", err)
	}
	if len(frames) != 1 {
		return protoErrf("hello message carried %d frames", len(frames))
	}
	hello := frames[0]
	if hello.Type != frame.Hello || hello.StreamID != 0 {
		return protoErrf("first frame was %v on stream %d", hello.Type, hello.StreamID)
	}
	if len(hello.Payload) != 1 || hello.Payload[0] != frame.HelloVersion {
		return protoErrf("unsupported hello payload % x", hello.Payload)
	}
	if err := s.send(frame.Welcome, 0, nil); err != nil {
		return err
	}
	s.opts.Logger.Info("session established")

	for {
		msg, err := s.conn.ReadMessage()
		if err != nil {
			if s.ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.touch()
		parsed, err := frame.Parse(msg)
		if err != nil {
			return protoErrf("%v", err)
		}
		for _, f := range parsed {
			if err := s.handle(f); err != nil {
				if errors.Is(err, errBye) {
					return nil
				}
				return err
			}
		}
	}
}

func (s *session) handle(f frame.Frame) error {
	if f.StreamID == 0 {
		return s.handleControl(f)
	}
	return s.handleStream(f)
}

func (s *session) handleControl(f frame.Frame) error {
	switch f.Type {
	case frame.Pong:
		return nil
	case frame.Ping:
		if len(f.Payload) > frame.MaxPingPayload {
			return protoErrf("ping payload %d bytes", len(f.Payload))
		}
		// Deliberately unanswered. Telegram Desktop never sends Ping, and it
		// has no handler for Pong: replying would be the protocol error that
		// tears down the whole transport. Tolerate the frame, say nothing.
		return nil
	case frame.Bye:
		s.opts.Logger.Info("peer said goodbye")
		return errBye
	default:
		return protoErrf("control frame %v", f.Type)
	}
}

func (s *session) handleStream(f frame.Frame) error {
	switch f.Type {
	case frame.Open:
		if len(f.Payload) != 0 {
			return protoErrf("open with %d byte payload", len(f.Payload))
		}
		return s.openStream(f.StreamID)
	case frame.Data:
		if len(f.Payload) == 0 {
			// The client rejects empty Data frames outright; so do we.
			return protoErrf("empty data frame")
		}
		st := s.lookup(f.StreamID)
		if st == nil {
			return s.toleratePostClose(f)
		}
		return st.acceptFromClient(f.Payload)
	case frame.Window:
		amount, ok := frame.ReadWindow(f.Payload)
		if !ok {
			return protoErrf("malformed window frame")
		}
		st := s.lookup(f.StreamID)
		if st == nil {
			return s.toleratePostClose(f)
		}
		st.credit.add(amount)
		return nil
	case frame.Close:
		if len(f.Payload) != 0 {
			return protoErrf("close with %d byte payload", len(f.Payload))
		}
		st := s.lookup(f.StreamID)
		if st == nil {
			return s.toleratePostClose(f)
		}
		s.forget(f.StreamID)
		st.shutdown(false)
		return nil
	default:
		return protoErrf("stream frame %v", f.Type)
	}
}

// toleratePostClose accepts frames that were already in flight when a stream
// closed, and rejects frames for a stream that never existed. The client keeps
// the same grace list (_closedStreams) for exactly this race.
func (s *session) toleratePostClose(f frame.Frame) error {
	s.mu.Lock()
	_, known := s.closed[f.StreamID]
	s.mu.Unlock()
	if known {
		return nil
	}
	return protoErrf("%v for unknown stream %d", f.Type, f.StreamID)
}

func (s *session) openStream(id uint32) error {
	s.mu.Lock()
	if _, exists := s.streams[id]; exists {
		s.mu.Unlock()
		return protoErrf("stream %d opened twice", id)
	}
	if _, gone := s.closed[id]; gone {
		s.mu.Unlock()
		return protoErrf("stream %d reopened after close", id)
	}
	if len(s.streams) >= s.opts.MaxStreams {
		s.mu.Unlock()
		// Refuse this stream without punishing the rest of the session.
		s.opts.Logger.Warn("stream limit reached", "limit", s.opts.MaxStreams)
		s.rememberClosed(id)
		return s.send(frame.Close, id, nil)
	}
	st := newStream(s, id)
	s.streams[id] = st
	s.mu.Unlock()

	s.streamWG.Add(1)
	go func() {
		defer s.streamWG.Done()
		st.run()
	}()
	return nil
}

func (s *session) lookup(id uint32) *stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

func (s *session) forget(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.streams, id)
	s.rememberClosedLocked(id)
}

func (s *session) rememberClosed(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rememberClosedLocked(id)
}

func (s *session) rememberClosedLocked(id uint32) {
	if _, exists := s.closed[id]; exists {
		return
	}
	s.closed[id] = struct{}{}
	s.closedQ = append(s.closedQ, id)
	if len(s.closedQ) > closedStreamMemory {
		oldest := s.closedQ[0]
		s.closedQ = s.closedQ[1:]
		delete(s.closed, oldest)
	}
}

func (s *session) shutdownStreams() {
	s.mu.Lock()
	all := make([]*stream, 0, len(s.streams))
	for id, st := range s.streams {
		all = append(all, st)
		delete(s.streams, id)
	}
	s.mu.Unlock()
	for _, st := range all {
		st.shutdown(false)
	}
}

// send queues one frame as its own transport message.
//
// The client accepts batches — Telegram's reference relay packs up to 4096
// frames per message — so this is our choice, not a requirement: it keeps the
// bridge page a byte-for-byte forwarder with no need to parse frames. Batching
// is a throughput optimisation to make with measurements, not on principle.
func (s *session) send(t frame.Type, streamID uint32, payload []byte) error {
	if !t.SendableByRelay() {
		return fmt.Errorf("relay: refusing to send %v, the client has no handler for it", t)
	}
	msg, err := frame.Marshal(t, streamID, payload)
	if err != nil {
		return err
	}
	select {
	case s.out <- msg:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

// writeLoop serialises transport writes.
//
// The channel is never closed: stream goroutines can outlive the reader, and
// a send racing a close would panic. Cancelling the context is the only stop
// signal, and send() watches the same context.
func (s *session) writeLoop() {
	defer s.writeWG.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case msg := <-s.out:
			s.opts.Metrics.MessageWritten(len(s.out))
			if err := s.conn.WriteMessage(msg); err != nil {
				s.opts.Logger.Debug("write failed", "error", err)
				s.cancel()
				_ = s.conn.Close()
				return
			}
		}
	}
}

func (s *session) watchdog() {
	ticker := time.NewTicker(s.opts.PingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if time.Since(s.lastActivity()) > s.opts.IdleTimeout {
				s.opts.Logger.Info("transport idle, closing")
				s.cancel()
				_ = s.conn.Close()
				return
			}
			probe := make([]byte, 8)
			if _, err := rand.Read(probe); err != nil {
				continue
			}
			if err := s.send(frame.Ping, 0, probe); err != nil {
				return
			}
		}
	}
}

func (s *session) touch() { s.activity.Store(time.Now().UnixNano()) }

func (s *session) lastActivity() time.Time { return time.Unix(0, s.activity.Load()) }
