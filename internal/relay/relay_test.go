package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"tgwebproxy/internal/frame"
	"tgwebproxy/internal/mtproto"
	"tgwebproxy/internal/secret"
)

// pipeConn is one end of a message-oriented pipe standing in for the
// WebSocket the bridge page would provide.
type pipeConn struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}
	// once is shared by both ends: closing either one tears down the pipe.
	once *sync.Once
}

func newPipe() (*pipeConn, *pipeConn) {
	a2b := make(chan []byte, 64)
	b2a := make(chan []byte, 64)
	closed := make(chan struct{})
	once := &sync.Once{}
	left := &pipeConn{in: b2a, out: a2b, closed: closed, once: once}
	right := &pipeConn{in: a2b, out: b2a, closed: closed, once: once}
	return left, right
}

func (p *pipeConn) ReadMessage() ([]byte, error) {
	select {
	case msg := <-p.in:
		return msg, nil
	case <-p.closed:
		return nil, io.EOF
	}
}

func (p *pipeConn) WriteMessage(data []byte) error {
	cp := append([]byte(nil), data...)
	select {
	case p.out <- cp:
		return nil
	case <-p.closed:
		return io.ErrClosedPipe
	}
}

func (p *pipeConn) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

// readFrame reads one transport message and asserts it holds exactly one
// frame, the way the relay is supposed to emit them.
func (p *pipeConn) readFrame(t *testing.T) frame.Frame {
	t.Helper()
	done := make(chan struct{})
	var msg []byte
	var err error
	go func() {
		msg, err = p.ReadMessage()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a frame")
	}
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	frames, parseErr := frame.Parse(msg)
	if parseErr != nil {
		t.Fatalf("Parse: %v", parseErr)
	}
	if len(frames) != 1 {
		t.Fatalf("relay sent %d frames in one message, want 1", len(frames))
	}
	return frames[0]
}

func (p *pipeConn) writeFrame(t *testing.T, ty frame.Type, id uint32, payload []byte) {
	t.Helper()
	msg, err := frame.Marshal(ty, id, payload)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := p.WriteMessage(msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
}

// echoDialer stands in for Telegram: it speaks the same obfuscated2 handshake
// a real data centre expects, then echoes plaintext back uppercased so the
// test can tell direction.
func echoDialer(t *testing.T, transform func([]byte) []byte) DialFunc {
	return func(ctx context.Context, protocol uint32, dcID int16) (*Upstream, error) {
		ours, theirs := net.Pipe()
		go func() {
			defer theirs.Close()
			header := make([]byte, mtproto.HandshakeSize)
			if _, err := io.ReadFull(theirs, header); err != nil {
				return
			}
			// A data centre uses no secret: the key material is verbatim.
			hello, err := mtproto.AcceptClient(header, nil)
			if err != nil {
				return
			}
			if hello.Protocol != protocol || hello.DCID != dcID {
				t.Errorf("upstream handshake carried %s/%d, want %s/%d",
					mtproto.ProtocolName(hello.Protocol), hello.DCID,
					mtproto.ProtocolName(protocol), dcID)
				return
			}
			plain := mtproto.NewStream(theirs, hello.Decrypt, hello.Encrypt)
			buf := make([]byte, 4096)
			for {
				n, err := plain.Read(buf)
				if n > 0 {
					if _, werr := plain.Write(transform(buf[:n])); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
		stream, err := mtproto.HandshakeOver(ours, protocol, dcID, nil)
		if err != nil {
			return nil, err
		}
		return &Upstream{Conn: stream, Name: "fake-dc"}, nil
	}
}

func upper(b []byte) []byte { return []byte(strings.ToUpper(string(b))) }

func testSecret(t *testing.T) secret.Secret {
	t.Helper()
	s, err := secret.Parse("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func startRelay(t *testing.T, opts Options) (*pipeConn, func() error) {
	t.Helper()
	client, server := newPipe()
	if opts.Secret.Valid() == false {
		opts.Secret = testSecret(t)
	}
	result := make(chan error, 1)
	go func() { result <- Serve(context.Background(), server, opts) }()
	var (
		stopOnce sync.Once
		stopErr  error
	)
	stop := func() error {
		stopOnce.Do(func() {
			client.Close()
			select {
			case stopErr = <-result:
			case <-time.After(5 * time.Second):
				stopErr = errors.New("relay did not stop")
			}
		})
		return stopErr
	}
	t.Cleanup(func() { _ = stop() })
	return client, stop
}

func handshake(t *testing.T, client *pipeConn) {
	t.Helper()
	client.writeFrame(t, frame.Hello, 0, []byte{frame.HelloVersion})
	welcome := client.readFrame(t)
	if welcome.Type != frame.Welcome {
		t.Fatalf("first reply was %v, want Welcome", welcome.Type)
	}
	if welcome.StreamID != 0 {
		t.Fatalf("Welcome on stream %d, want 0", welcome.StreamID)
	}
	if len(welcome.Payload) != 0 {
		t.Fatalf("Welcome carried %d bytes; the client requires an empty payload",
			len(welcome.Payload))
	}
}

func TestHandshakeThenEcho(t *testing.T) {
	client, _ := startRelay(t, Options{Dial: echoDialer(t, upper)})
	handshake(t, client)

	sec := testSecret(t)
	twin, err := mtproto.NewHandshake(mtproto.Abridged, 2, sec.Obfuscation())
	if err != nil {
		t.Fatal(err)
	}

	client.writeFrame(t, frame.Open, 1, nil)
	client.writeFrame(t, frame.Data, 1, twin.Wire)

	payload := []byte("mtproto packet bytes")
	sealed := make([]byte, len(payload))
	twin.Encrypt.XORKeyStream(sealed, payload)
	client.writeFrame(t, frame.Data, 1, sealed)

	// The relay may interleave Window grants with the echoed data.
	var got []byte
	deadline := time.Now().Add(5 * time.Second)
	for len(got) < len(payload) && time.Now().Before(deadline) {
		f := client.readFrame(t)
		switch f.Type {
		case frame.Data:
			if f.StreamID != 1 {
				t.Fatalf("data on stream %d, want 1", f.StreamID)
			}
			opened := make([]byte, len(f.Payload))
			twin.Decrypt.XORKeyStream(opened, f.Payload)
			got = append(got, opened...)
		case frame.Window, frame.Ping:
		default:
			t.Fatalf("unexpected frame %v", f.Type)
		}
	}
	if !bytes.Equal(got, upper(payload)) {
		t.Fatalf("echo = %q, want %q", got, upper(payload))
	}
}

func TestWindowIsReturnedAfterConsumption(t *testing.T) {
	client, _ := startRelay(t, Options{Dial: echoDialer(t, func(b []byte) []byte { return nil })})
	handshake(t, client)

	sec := testSecret(t)
	twin, err := mtproto.NewHandshake(mtproto.Abridged, 2, sec.Obfuscation())
	if err != nil {
		t.Fatal(err)
	}
	client.writeFrame(t, frame.Open, 1, nil)
	client.writeFrame(t, frame.Data, 1, twin.Wire)

	// Push enough to cross the grant threshold in one go.
	bulk := make([]byte, grantFlush+1)
	sealed := make([]byte, len(bulk))
	twin.Encrypt.XORKeyStream(sealed, bulk)
	client.writeFrame(t, frame.Data, 1, sealed)

	deadline := time.Now().Add(5 * time.Second)
	var granted uint64
	for granted == 0 && time.Now().Before(deadline) {
		f := client.readFrame(t)
		if f.Type == frame.Window {
			amount, ok := frame.ReadWindow(f.Payload)
			if !ok {
				t.Fatalf("relay sent a malformed window payload % x", f.Payload)
			}
			granted += uint64(amount)
		}
	}
	// The handshake bytes are consumed too, so the grant covers both.
	if granted < uint64(len(bulk)) {
		t.Fatalf("granted %d bytes, want at least %d", granted, len(bulk))
	}
}

func TestUpstreamCloseClosesStream(t *testing.T) {
	dial := func(ctx context.Context, protocol uint32, dcID int16) (*Upstream, error) {
		ours, theirs := net.Pipe()
		go func() {
			header := make([]byte, mtproto.HandshakeSize)
			io.ReadFull(theirs, header)
			theirs.Close()
		}()
		stream, err := mtproto.HandshakeOver(ours, protocol, dcID, nil)
		if err != nil {
			return nil, err
		}
		return &Upstream{Conn: stream, Name: "closing-dc"}, nil
	}
	client, _ := startRelay(t, Options{Dial: dial})
	handshake(t, client)

	sec := testSecret(t)
	twin, err := mtproto.NewHandshake(mtproto.Abridged, 2, sec.Obfuscation())
	if err != nil {
		t.Fatal(err)
	}
	client.writeFrame(t, frame.Open, 1, nil)
	client.writeFrame(t, frame.Data, 1, twin.Wire)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f := client.readFrame(t)
		if f.Type == frame.Close && f.StreamID == 1 {
			if len(f.Payload) != 0 {
				t.Fatalf("Close carried %d bytes, the client requires none", len(f.Payload))
			}
			return
		}
	}
	t.Fatal("relay never closed the stream")
}

func TestBadSecretClosesStreamQuietly(t *testing.T) {
	client, _ := startRelay(t, Options{Dial: echoDialer(t, upper)})
	handshake(t, client)

	wrong, err := secret.Parse("ffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatal(err)
	}
	twin, err := mtproto.NewHandshake(mtproto.Abridged, 2, wrong.Obfuscation())
	if err != nil {
		t.Fatal(err)
	}
	client.writeFrame(t, frame.Open, 1, nil)
	client.writeFrame(t, frame.Data, 1, twin.Wire)

	f := client.readFrame(t)
	if f.Type != frame.Close || f.StreamID != 1 {
		t.Fatalf("got %v on stream %d, want Close on 1", f.Type, f.StreamID)
	}
}

// The client has no handler for Pong, so answering its Ping would be the
// protocol error that tears the transport down. The frame is tolerated and
// left unanswered, and the session must survive it.
func TestClientPingIsToleratedButUnanswered(t *testing.T) {
	client, _ := startRelay(t, Options{Dial: echoDialer(t, upper)})
	handshake(t, client)

	client.writeFrame(t, frame.Ping, 0, []byte("are you there"))

	// Nothing may come back, but the session must still work afterwards.
	client.writeFrame(t, frame.Open, 1, nil)
	hello, err := mtproto.NewHandshake(mtproto.Abridged, 2, testSecret(t).Obfuscation())
	if err != nil {
		t.Fatal(err)
	}
	client.writeFrame(t, frame.Data, 1, hello.Wire)
	sealed := make([]byte, len("ping-survivor"))
	hello.Encrypt.XORKeyStream(sealed, []byte("ping-survivor"))
	client.writeFrame(t, frame.Data, 1, sealed)

	// Window frames returning credit may arrive first; the payload is what
	// matters here.
	var got frame.Frame
	for i := 0; i < 4; i++ {
		got = client.readFrame(t)
		if got.Type == frame.Data {
			break
		}
		if got.Type != frame.Window {
			t.Fatalf("after a Ping the relay sent %v on stream %d", got.Type, got.StreamID)
		}
	}
	if got.Type != frame.Data || got.StreamID != 1 {
		t.Fatalf("no Data came back after a Ping, last frame was %v", got.Type)
	}
	plain := make([]byte, len(got.Payload))
	hello.Decrypt.XORKeyStream(plain, got.Payload)
	if string(plain) != "PING-SURVIVOR" {
		t.Fatalf("round trip after a Ping returned %q", plain)
	}
}

func TestProtocolViolations(t *testing.T) {
	cases := []struct {
		name string
		play func(t *testing.T, c *pipeConn)
	}{
		{"no hello", func(t *testing.T, c *pipeConn) {
			c.writeFrame(t, frame.Open, 1, nil)
		}},
		{"wrong hello version", func(t *testing.T, c *pipeConn) {
			c.writeFrame(t, frame.Hello, 0, []byte{0x02})
		}},
		{"hello on a stream", func(t *testing.T, c *pipeConn) {
			c.writeFrame(t, frame.Hello, 7, []byte{frame.HelloVersion})
		}},
		{"empty data", func(t *testing.T, c *pipeConn) {
			handshake(t, c)
			c.writeFrame(t, frame.Open, 1, nil)
			c.writeFrame(t, frame.Data, 1, nil)
		}},
		{"data for unknown stream", func(t *testing.T, c *pipeConn) {
			handshake(t, c)
			c.writeFrame(t, frame.Data, 9, []byte("x"))
		}},
		{"open twice", func(t *testing.T, c *pipeConn) {
			handshake(t, c)
			c.writeFrame(t, frame.Open, 1, nil)
			c.writeFrame(t, frame.Open, 1, nil)
		}},
		{"open with payload", func(t *testing.T, c *pipeConn) {
			handshake(t, c)
			c.writeFrame(t, frame.Open, 1, []byte("x"))
		}},
		{"malformed window", func(t *testing.T, c *pipeConn) {
			handshake(t, c)
			c.writeFrame(t, frame.Open, 1, nil)
			c.writeFrame(t, frame.Window, 1, []byte{0, 0, 1})
		}},
		{"welcome from the client", func(t *testing.T, c *pipeConn) {
			handshake(t, c)
			c.writeFrame(t, frame.Welcome, 0, nil)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, stop := startRelay(t, Options{Dial: echoDialer(t, upper)})
			c.play(t, client)
			// Let the session reach its verdict before closing the transport.
			time.Sleep(50 * time.Millisecond)
			client.Close()
			err := stop()
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("Serve error = %v, want a protocol error", err)
			}
		})
	}
}

// stallDialer completes the upstream handshake and then stops reading, so
// nothing the client sends can ever be acknowledged with a Window frame.
func stallDialer(t *testing.T) DialFunc {
	return func(ctx context.Context, protocol uint32, dcID int16) (*Upstream, error) {
		ours, theirs := net.Pipe()
		go func() {
			header := make([]byte, mtproto.HandshakeSize)
			if _, err := io.ReadFull(theirs, header); err != nil {
				return
			}
			<-ctx.Done()
			theirs.Close()
		}()
		stream, err := mtproto.HandshakeOver(ours, protocol, dcID, nil)
		if err != nil {
			return nil, err
		}
		return &Upstream{Conn: stream, Name: "stalled-dc"}, nil
	}
}

func TestOverWindowIsAProtocolError(t *testing.T) {
	// The client may never send more than its allowance. If it does, its own
	// accounting is broken and nothing else it says can be trusted, so the
	// whole transport goes.
	client, stop := startRelay(t, Options{Dial: stallDialer(t)})
	handshake(t, client)

	sec := testSecret(t)
	twin, err := mtproto.NewHandshake(mtproto.Abridged, 2, sec.Obfuscation())
	if err != nil {
		t.Fatal(err)
	}
	client.writeFrame(t, frame.Open, 1, nil)
	client.writeFrame(t, frame.Data, 1, twin.Wire)

	// The relay may notice the overrun and drop the transport mid-loop, so a
	// failed write here is a success, not a test error.
	chunk := make([]byte, frame.MaxPayload)
	for sent := 0; sent <= frame.InitialWindow; sent += len(chunk) {
		msg, err := frame.Marshal(frame.Data, 1, chunk)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.WriteMessage(msg); err != nil {
			break
		}
	}
	time.Sleep(200 * time.Millisecond)
	client.Close()
	if err := stop(); !errors.Is(err, ErrProtocol) {
		t.Fatalf("Serve error = %v, want a protocol error", err)
	}
}

func TestStreamLimitRefusesInsteadOfKilling(t *testing.T) {
	client, _ := startRelay(t, Options{Dial: echoDialer(t, upper), MaxStreams: 1})
	handshake(t, client)
	client.writeFrame(t, frame.Open, 1, nil)
	client.writeFrame(t, frame.Open, 2, nil)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f := client.readFrame(t)
		if f.Type == frame.Close && f.StreamID == 2 {
			return
		}
	}
	t.Fatal("relay never refused the extra stream")
}
