package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"tgwebproxy/internal/httpfront"
	"tgwebproxy/internal/mtproto"
	"tgwebproxy/internal/relay"
	"tgwebproxy/internal/secret"
	"tgwebproxy/internal/twin"
)

const domain = "proxy.example.com"

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: domain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{domain},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// fakeDC speaks the data-centre side of obfuscated2 and echoes plaintext
// through transform.
func fakeDC(t *testing.T, transform func([]byte) []byte) (addr string, connections *atomic.Int64) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	counter := &atomic.Int64{}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			counter.Add(1)
			go func() {
				defer conn.Close()
				header := make([]byte, mtproto.HandshakeSize)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				hello, err := mtproto.AcceptClient(header, nil)
				if err != nil {
					return
				}
				stream := mtproto.NewStream(conn, hello.Decrypt, hello.Encrypt)
				buf := make([]byte, 64*1024)
				for {
					n, err := stream.Read(buf)
					if n > 0 {
						if _, werr := stream.Write(transform(buf[:n])); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return listener.Addr().String(), counter
}

func dcDialer(addr string) relay.DialFunc {
	return func(ctx context.Context, protocol uint32, dcID int16) (*relay.Upstream, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		stream, err := mtproto.HandshakeOver(conn, protocol, dcID, nil)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return &relay.Upstream{Conn: stream, Name: "test-dc " + addr}, nil
	}
}

// wsTransport serialises writes: the twin writes from two goroutines (test
// traffic and the pump's Window/Pong replies), as the real client does.
type wsTransport struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
}

func (w *wsTransport) Send(data []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return w.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (w *wsTransport) Receive() ([]byte, error) {
	kind, data, err := w.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	if kind != websocket.BinaryMessage {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}

func (w *wsTransport) Close() error { return w.conn.Close() }

type bed struct {
	server *httptest.Server
	secret secret.Secret
	pool   *x509.CertPool
}

func newBed(t *testing.T, transform func([]byte) []byte) (*bed, *atomic.Int64) {
	t.Helper()
	sec, err := secret.Parse("dd000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	addr, connections := fakeDC(t, transform)

	keys, err := secret.NewKeyring(domain, []secret.Entry{{Secret: sec, Label: "e2e"}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := httpfront.New(httpfront.Config{
		Domains: []httpfront.Domain{{Name: domain, Keyring: keys}},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Relay: relay.Options{
			Dial:         dcDialer(addr),
			MaxStreams:   8,
			PingInterval: time.Second,
			IdleTimeout:  30 * time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	cert, pool := selfSigned(t)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	t.Cleanup(server.Close)

	return &bed{server: server, secret: sec, pool: pool}, connections
}

// connect performs the browser's half: bridge page, then socket from its Origin.
func (b *bed) connect(t *testing.T) *twin.Twin {
	t.Helper()
	capability := b.secret.Capability(domain)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: b.pool, ServerName: domain},
	}}
	resp, err := client.Get(b.server.URL + "/?bridge=" + url.QueryEscape(capability))
	if err != nil {
		t.Fatalf("fetch bridge page: %v", err)
	}
	page, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(page, []byte("WebSocket")) {
		t.Fatal("bridge page does not open a socket")
	}

	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{RootCAs: b.pool, ServerName: domain},
		HandshakeTimeout: 10 * time.Second,
	}
	endpoint := "wss" + strings.TrimPrefix(b.server.URL, "https") +
		"/?bridge=" + url.QueryEscape(capability)
	conn, _, err := dialer.Dial(endpoint, http.Header{"Origin": {"https://" + domain}})
	if err != nil {
		t.Fatalf("dial relay socket: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	tw := twin.NewTwin(&wsTransport{conn: conn}, b.secret)
	if err := tw.Handshake(); err != nil {
		t.Fatalf("transport handshake: %v", err)
	}
	return tw
}

func runPump(t *testing.T, tw *twin.Twin) func() {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- tw.Pump() }()
	return func() {
		tw.Transport().Close()
		select {
		case err := <-done:
			if err == nil {
				return
			}
			if isTransportClosed(err) {
				return
			}
			t.Errorf("client twin rejected the relay: %v", err)
		case <-time.After(5 * time.Second):
			t.Error("client twin did not stop")
		}
	}
}

func isTransportClosed(err error) bool {
	text := err.Error()
	for _, marker := range []string{
		"use of closed network connection",
		"close 1000",
		"close 1006",
		"unexpected EOF",
		"EOF",
		"broken pipe",
		"connection reset",
		"abnormal closure",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func upper(b []byte) []byte { return bytes.ToUpper(b) }

func identity(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func TestFullPathRoundTrip(t *testing.T) {
	bed, connections := newBed(t, upper)
	tw := bed.connect(t)
	stop := runPump(t, tw)
	defer stop()

	stream, err := tw.Open(mtproto.PaddedIntermediate, 2)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := tw.Write(stream, []byte("mtproto request")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := tw.Read(stream, 10*time.Second)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "MTPROTO REQUEST" {
		t.Fatalf("round trip = %q", got)
	}
	if connections.Load() != 1 {
		t.Fatalf("data centre saw %d connections, want 1", connections.Load())
	}
}

// A running client always multiplexes: one stream per DC plus downloads.
func TestManyStreamsInOneTransport(t *testing.T) {
	bed, connections := newBed(t, upper)
	tw := bed.connect(t)
	stop := runPump(t, tw)
	defer stop()

	const count = 5
	streams := make([]*twin.Stream, 0, count)
	for i := 0; i < count; i++ {
		st, err := tw.Open(mtproto.Abridged, int16(1+i%5))
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		streams = append(streams, st)
	}
	for i, st := range streams {
		if err := tw.Write(st, []byte{byte('a' + i)}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	for i, st := range streams {
		got, err := tw.Read(st, 10*time.Second)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		want := []byte{byte('A' + i)}
		if !bytes.Equal(got, want) {
			t.Fatalf("stream %d = %q, want %q", i, got, want)
		}
	}
	if connections.Load() != count {
		t.Fatalf("data centre saw %d connections, want %d", connections.Load(), count)
	}
}

// Larger than one frame and than the initial window, so both the 64 KiB
// slicing and the Window round trip must work.
func TestBulkTransferCrossesTheWindow(t *testing.T) {
	bed, _ := newBed(t, identity)
	tw := bed.connect(t)
	stop := runPump(t, tw)
	defer stop()

	stream, err := tw.Open(mtproto.Abridged, 2)
	if err != nil {
		t.Fatal(err)
	}

	payload := make([]byte, 6<<20) // 6 MiB, above the 4 MiB initial window
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	go func() {
		for offset := 0; offset < len(payload); offset += 128 << 10 {
			end := offset + (128 << 10)
			if end > len(payload) {
				end = len(payload)
			}
			if err := tw.Write(stream, payload[offset:end]); err != nil {
				return
			}
		}
	}()

	received := make([]byte, 0, len(payload))
	deadline := time.Now().Add(60 * time.Second)
	for len(received) < len(payload) && time.Now().Before(deadline) {
		chunk, err := tw.Read(stream, 30*time.Second)
		if err != nil {
			t.Fatalf("read after %d bytes: %v", len(received), err)
		}
		received = append(received, chunk...)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("echoed %d bytes of %d, and they %s",
			len(received), len(payload),
			map[bool]string{true: "match", false: "differ"}[bytes.Equal(received, payload[:min(len(received), len(payload))])])
	}
}

func TestPingKeepsTheTransportAlive(t *testing.T) {
	bed, _ := newBed(t, upper)
	tw := bed.connect(t)
	stop := runPump(t, tw)
	defer stop()

	stream, err := tw.Open(mtproto.Abridged, 1)
	if err != nil {
		t.Fatal(err)
	}
	// The bed pings once a second.
	time.Sleep(3 * time.Second)
	if err := tw.Write(stream, []byte("still here")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := tw.Read(stream, 10*time.Second)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "STILL HERE" {
		t.Fatalf("round trip = %q", got)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// The relay above the carrier cannot tell a socket from a sequence of HTTP
// requests, and the client twin enforces the same rules over both. This is the
// long-poll path end to end: bridge page, numbered uplink, held downlink,
// MTProto handshake and a round trip to a data centre.
func TestLongPollCarriesTheWholeStack(t *testing.T) {
	bed, connections := newBed(t, upper)

	transport, err := twin.DialPoll(twin.DialOptions{
		BaseURL:    bed.server.URL,
		Domain:     domain,
		Capability: bed.secret.Capability(domain),
		TLSConfig:  &tls.Config{RootCAs: bed.pool, ServerName: domain},
		Timeout:    20 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial the fallback carrier: %v", err)
	}
	defer transport.Close()

	tw := twin.NewTwin(transport, bed.secret)
	if err := tw.Handshake(); err != nil {
		t.Fatalf("transport handshake over long poll: %v", err)
	}
	stop := runPump(t, tw)
	defer stop()

	stream, err := tw.Open(mtproto.PaddedIntermediate, 2)
	if err != nil {
		t.Fatalf("open a stream: %v", err)
	}
	if err := tw.Write(stream, []byte("carried over http")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := tw.Read(stream, 15*time.Second)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "CARRIED OVER HTTP" {
		t.Fatalf("round trip returned %q", got)
	}
	if n := connections.Load(); n != 1 {
		t.Errorf("the relay opened %d upstream connections, want 1", n)
	}
}
