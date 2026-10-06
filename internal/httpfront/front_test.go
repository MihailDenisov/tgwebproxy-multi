package httpfront

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"tgwebproxy/internal/frame"
	"tgwebproxy/internal/relay"
	"tgwebproxy/internal/secret"
)

const testDomain = "proxy.example.com"

func testHandler(t *testing.T, cfg func(*Config)) (*Handler, secret.Secret) {
	t.Helper()
	sec, err := secret.Parse("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := secret.NewKeyring(testDomain, []secret.Entry{{Secret: sec, Label: "test"}})
	if err != nil {
		t.Fatal(err)
	}
	c := Config{
		Domains: []Domain{{Name: testDomain, Keyring: keys}},
		Logger:  quietLogger(),
	}
	if cfg != nil {
		cfg(&c)
	}
	h, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return h, sec
}

func fetch(t *testing.T, h *Handler, target string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func bodyOf(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Any difference in status, headers or bytes is a way to fingerprint the relay.
func TestWrongCapabilityIsIndistinguishable(t *testing.T) {
	h, sec := testHandler(t, nil)
	valid := sec.Capability(testDomain)

	plain := fetch(t, h, "/")
	plainBody := bodyOf(t, plain)

	probes := []string{
		"/?bridge=",
		"/?bridge=obviously-wrong",
		"/?bridge=" + valid[:len(valid)-1] + "X", // one byte off
		"/?bridge=" + url.QueryEscape(valid+"extra"),
		"/?other=1",
	}
	for _, probe := range probes {
		t.Run(probe, func(t *testing.T) {
			resp := fetch(t, h, probe)
			if resp.StatusCode != plain.StatusCode {
				t.Fatalf("status %d, want %d", resp.StatusCode, plain.StatusCode)
			}
			if got := bodyOf(t, resp); !bytes.Equal(got, plainBody) {
				t.Fatalf("body differs from the plain response")
			}
			for name := range resp.Header {
				if name == "Date" {
					continue
				}
				if strings.Join(resp.Header.Values(name), ",") !=
					strings.Join(plain.Header.Values(name), ",") {
					t.Fatalf("header %s differs from the plain response", name)
				}
			}
			if len(resp.Header) != len(plain.Header) {
				t.Fatalf("header set differs from the plain response")
			}
		})
	}
}

func TestValidCapabilityServesBridge(t *testing.T) {
	h, sec := testHandler(t, nil)
	resp := fetch(t, h, "/?bridge="+url.QueryEscape(sec.Capability(testDomain)))
	body := bodyOf(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !bytes.Contains(body, []byte("TelegramWebProxy")) {
		t.Fatal("bridge page does not reference the WebView carrier")
	}
	if !bytes.Contains(body, []byte("tproxy-init")) {
		t.Fatal("bridge page does not handle the iframe carrier")
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "wss://"+testDomain) {
		t.Fatalf("CSP does not allow the relay socket: %s", csp)
	}
	if !strings.Contains(csp, "nonce-") {
		t.Fatalf("CSP has no script nonce: %s", csp)
	}
	if bytes.Contains(body, []byte("__NONCE__")) {
		t.Fatal("nonce placeholder was not substituted")
	}
}

func TestBridgeNonceChangesPerResponse(t *testing.T) {
	h, sec := testHandler(t, nil)
	target := "/?bridge=" + url.QueryEscape(sec.Capability(testDomain))
	first := fetch(t, h, target).Header.Get("Content-Security-Policy")
	second := fetch(t, h, target).Header.Get("Content-Security-Policy")
	if first == second {
		t.Fatal("script nonce must be per response")
	}
}

func TestCapabilityOnlyWorksOnRoot(t *testing.T) {
	h, sec := testHandler(t, nil)
	cap := url.QueryEscape(sec.Capability(testDomain))
	resp := fetch(t, h, "/elsewhere?bridge="+cap)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if bytes.Contains(bodyOf(t, resp), []byte("TelegramWebProxy")) {
		t.Fatal("bridge served outside the root path")
	}
}

func TestPostNeverBridges(t *testing.T) {
	h, sec := testHandler(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/?bridge="+url.QueryEscape(sec.Capability(testDomain)), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if bytes.Contains(rec.Body.Bytes(), []byte("TelegramWebProxy")) {
		t.Fatal("bridge served for a POST")
	}
}

func TestSiteDirectoryValidation(t *testing.T) {
	sec, err := secret.Parse("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := secret.NewKeyring(testDomain, []secret.Entry{{Secret: sec, Label: "test"}})
	if err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir()
	if _, err := New(Config{Domains: []Domain{{Name: testDomain, Keyring: keys, SiteDir: empty}}, Logger: quietLogger()}); err == nil {
		t.Fatal("a site directory without index.html must be rejected")
	}

	good := t.TempDir()
	if err := os.WriteFile(filepath.Join(good, "index.html"), []byte("<h1>hi</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := New(Config{Domains: []Domain{{Name: testDomain, Keyring: keys, SiteDir: good}}, Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	if got := bodyOf(t, fetch(t, h, "/")); !bytes.Contains(got, []byte("<h1>hi</h1>")) {
		t.Fatalf("cover site not served from the directory: %q", got)
	}
}

func dialRelay(t *testing.T, server *httptest.Server, capability string, origin string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + "/"
	if capability != "" {
		endpoint += "?bridge=" + url.QueryEscape(capability)
	}
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	header := http.Header{}
	if origin != "" {
		header.Set("Origin", origin)
	}
	return dialer.Dial(endpoint, header)
}

func TestWebSocketRequiresCapability(t *testing.T) {
	h, _ := testHandler(t, func(c *Config) {
		c.Relay = relay.Options{Dial: refusingDialer}
	})
	server := httptest.NewServer(h)
	defer server.Close()

	if _, _, err := dialRelay(t, server, "", "https://"+testDomain); err == nil {
		t.Fatal("upgrade without a capability must fail")
	}
	if _, _, err := dialRelay(t, server, "wrong", "https://"+testDomain); err == nil {
		t.Fatal("upgrade with a wrong capability must fail")
	}
}

// The capability is what authenticates an upgrade, never the Origin header. A
// native WebView may omit it entirely, and Telegram's own reference relay
// stopped checking it for that reason, so neither a missing nor a foreign
// origin may keep a legitimate client out.
func TestOriginDoesNotGateTheUpgrade(t *testing.T) {
	h, sec := testHandler(t, func(c *Config) {
		c.Relay = relay.Options{Dial: refusingDialer}
	})
	server := httptest.NewServer(h)
	defer server.Close()

	for _, origin := range []string{"", "https://evil.example.com", "null"} {
		conn, _, err := dialRelay(t, server, sec.Capability(testDomain), origin)
		if err != nil {
			t.Errorf("upgrade with origin %q was refused: %v", origin, err)
			continue
		}
		conn.Close()
	}
}

func TestWebSocketHandshakeEndToEnd(t *testing.T) {
	h, sec := testHandler(t, func(c *Config) {
		c.Relay = relay.Options{Dial: refusingDialer}
	})
	server := httptest.NewServer(h)
	defer server.Close()

	conn, _, err := dialRelay(t, server, sec.Capability(testDomain), "https://"+testDomain)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	hello, err := frame.Marshal(frame.Hello, 0, []byte{frame.HelloVersion})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	kind, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read welcome: %v", err)
	}
	if kind != websocket.BinaryMessage {
		t.Fatalf("welcome arrived as message type %d, want binary", kind)
	}
	frames, err := frame.Parse(data)
	if err != nil {
		t.Fatalf("parse welcome: %v", err)
	}
	if len(frames) != 1 || frames[0].Type != frame.Welcome || len(frames[0].Payload) != 0 {
		t.Fatalf("unexpected welcome: %+v", frames)
	}
}

func TestTextMessageDropsSession(t *testing.T) {
	h, sec := testHandler(t, func(c *Config) {
		c.Relay = relay.Options{Dial: refusingDialer}
	})
	server := httptest.NewServer(h)
	defer server.Close()

	conn, _, err := dialRelay(t, server, sec.Capability(testDomain), "https://"+testDomain)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("a text message must drop the session")
	}
}

func refusingDialer(ctx context.Context, protocol uint32, dcID int16) (*relay.Upstream, error) {
	return nil, context.Canceled
}
