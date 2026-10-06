package relay

import (
	"io"
	"log/slog"
	"sync"
	"sync/atomic"

	"tgwebproxy/internal/frame"
	"tgwebproxy/internal/mtproto"
)

// grantFlush is how much consumed data accumulates before the relay returns
// window credit to the client. The client uses the same idea in the other
// direction (kWindowFlushBytes); batching keeps one Window frame from riding
// along with every single chunk.
const grantFlush = 64 * 1024

// stream is one MTProto connection tunnelled inside the transport.
//
// Two goroutines own it: `run` carries client bytes upstream, `pump` carries
// data-centre bytes back. Everything they share is either immutable after the
// handshake or guarded below.
type stream struct {
	session *session
	id      uint32
	log     *slog.Logger

	queue  *chunkQueue
	credit *credit
	// inflight counts bytes taken from the client that have not been paid
	// back with a Window frame yet. It may never exceed the client's initial
	// allowance; if it does, the client has broken its own flow control.
	inflight     atomic.Int64
	pendingGrant atomic.Int64

	closeOnce sync.Once
	done      chan struct{}

	upMu     sync.Mutex
	upstream io.Closer
}

func newStream(s *session, id uint32) *stream {
	return &stream{
		session: s,
		id:      id,
		log:     s.opts.Logger.With("stream", id),
		queue:   newChunkQueue(),
		credit:  newCredit(frame.InitialWindow),
		done:    make(chan struct{}),
	}
}

// acceptFromClient is called on the session's reader goroutine. It must never
// block, and it must copy: the payload aliases the transport read buffer.
func (st *stream) acceptFromClient(payload []byte) error {
	if st.inflight.Add(int64(len(payload))) > frame.InitialWindow {
		return protoErrf("stream %d exceeded its send window", st.id)
	}
	chunk := make([]byte, len(payload))
	copy(chunk, payload)
	st.queue.push(chunk)
	return nil
}

func (st *stream) run() {
	defer st.shutdown(true)

	header, leftover, ok := st.collectHandshake()
	if !ok {
		return
	}
	hello, err := mtproto.AcceptClient(header, st.session.opts.Secret.Obfuscation())
	if err != nil {
		// Wrong secret or a probe: the peer learns nothing beyond the close.
		st.log.Warn("rejected stream handshake", "error", err)
		return
	}

	upstream, err := st.session.opts.Dial(st.session.ctx, hello.Protocol, hello.DCID)
	if err != nil {
		st.session.opts.Metrics.UpstreamDialFailed()
		st.log.Warn("upstream dial failed", "error", err, "dc", hello.DCID)
		return
	}
	st.upMu.Lock()
	st.upstream = upstream.Conn
	st.upMu.Unlock()
	select {
	case <-st.done:
		_ = upstream.Conn.Close()
		return
	default:
	}
	st.session.opts.Metrics.StreamOpened()
	defer st.session.opts.Metrics.StreamClosed()
	st.log.Info("stream open",
		"upstream", upstream.Name,
		"transport", mtproto.ProtocolName(hello.Protocol))

	go st.pump(upstream.Conn, hello)

	// The client's handshake and its first request usually arrive in one
	// chunk, so the leftover has to go upstream before anything else.
	if len(leftover) > 0 {
		hello.Decrypt.XORKeyStream(leftover, leftover)
		if !st.writeUpstream(upstream.Conn, leftover) {
			return
		}
	}
	for {
		chunk, ok := st.queue.pop()
		if !ok {
			return
		}
		hello.Decrypt.XORKeyStream(chunk, chunk)
		if !st.writeUpstream(upstream.Conn, chunk) {
			return
		}
	}
}

func (st *stream) writeUpstream(upstream io.Writer, chunk []byte) bool {
	if _, err := upstream.Write(chunk); err != nil {
		st.log.Debug("upstream write failed", "error", err)
		return false
	}
	st.session.opts.Metrics.BytesUp(len(chunk))
	return st.grant(len(chunk))
}

// grant batches window credit until grantFlush or until the queue drains.
func (st *stream) grant(consumed int) bool {
	pending := st.pendingGrant.Add(int64(consumed))
	if pending < grantFlush && !st.queue.empty() {
		return true
	}
	amount := st.pendingGrant.Swap(0)
	if amount <= 0 {
		return true
	}
	st.inflight.Add(-amount)
	// A single grant can never exceed the initial window, so the 32-bit
	// field cannot overflow.
	if err := st.session.send(frame.Window, st.id, frame.WindowPayload(uint32(amount))); err != nil {
		return false
	}
	return true
}

func (st *stream) collectHandshake() (header, leftover []byte, ok bool) {
	buf := make([]byte, 0, mtproto.HandshakeSize)
	for len(buf) < mtproto.HandshakeSize {
		chunk, more := st.queue.pop()
		if !more {
			return nil, nil, false
		}
		buf = append(buf, chunk...)
	}
	header = buf[:mtproto.HandshakeSize]
	leftover = buf[mtproto.HandshakeSize:]
	return header, leftover, true
}

// pump carries data-centre bytes back to the client.
//
// Credit is reserved before the read, so a client that stops draining stops
// us from reading the upstream socket, and the backpressure lands on
// Telegram's side instead of in our heap.
func (st *stream) pump(upstream io.Reader, hello *mtproto.ClientHello) {
	defer st.shutdown(true)

	buf := make([]byte, frame.DataChunk)
	for {
		reserved := st.credit.take(len(buf))
		if reserved == 0 {
			return
		}
		n, err := upstream.Read(buf[:reserved])
		if n > 0 {
			st.credit.giveBack(reserved - n)
			hello.Encrypt.XORKeyStream(buf[:n], buf[:n])
			if sendErr := st.session.send(frame.Data, st.id, buf[:n]); sendErr != nil {
				return
			}
			st.session.opts.Metrics.BytesDown(n)
		} else {
			st.credit.giveBack(reserved)
		}
		if err != nil {
			if err != io.EOF {
				st.log.Debug("upstream read failed", "error", err)
			}
			return
		}
	}
}

func (st *stream) shutdown(notify bool) {
	st.closeOnce.Do(func() {
		close(st.done)
		st.queue.close()
		st.credit.close()

		st.upMu.Lock()
		upstream := st.upstream
		st.upstream = nil
		st.upMu.Unlock()
		if upstream != nil {
			_ = upstream.Close()
		}

		if notify {
			st.session.forget(st.id)
			_ = st.session.send(frame.Close, st.id, nil)
		}
		st.log.Debug("stream closed")
	})
}
