package httpfront

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"tgwebproxy/internal/frame"
	"tgwebproxy/internal/secret"
)

const (
	secretA = "000102030405060708090a0b0c0d0e0f"
	secretB = "0f0e0d0c0b0a09080706050403020100"
)

func ring(t *testing.T, pairs ...[2]string) *secret.Keyring {
	t.Helper()
	entries := make([]secret.Entry, 0, len(pairs))
	for _, p := range pairs {
		s, err := secret.Parse(p[0])
		if err != nil {
			t.Fatalf("Parse(%s): %v", p[0], err)
		}
		entries = append(entries, secret.Entry{Secret: s, Label: p[1]})
	}
	k, err := secret.NewKeyring(testDomain, entries)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return k
}

func capabilityOf(t *testing.T, text string) string {
	t.Helper()
	s, err := secret.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return s.Capability(testDomain)
}

func servesBridge(t *testing.T, h *Handler, capability string) bool {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/?bridge="+url.QueryEscape(capability), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code == http.StatusOK &&
		bytes.Contains(rec.Body.Bytes(), []byte("TelegramWebProxy"))
}

func handlerWith(t *testing.T, keys *secret.Keyring) *Handler {
	t.Helper()
	h, err := New(Config{Domains: []Domain{{Name: testDomain, Keyring: keys}}, Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestEverySecretOpensTheBridge(t *testing.T) {
	keys := ring(t, [2]string{secretA, "phone"}, [2]string{secretB, "laptop"})
	h := handlerWith(t, keys)
	for _, entry := range keys.Entries() {
		if !servesBridge(t, h, entry.Secret.Capability(testDomain)) {
			t.Errorf("%s did not get the bridge page", entry.Label)
		}
	}
}

func TestReloadAddsAndRemovesSecrets(t *testing.T) {
	h := handlerWith(t, ring(t, [2]string{secretA, "phone"}))
	capA, capB := capabilityOf(t, secretA), capabilityOf(t, secretB)

	if servesBridge(t, h, capB) {
		t.Fatal("an unconfigured secret must not work before the reload")
	}
	if err := h.Reload(Live{Domains: []Domain{{Name: testDomain, Keyring: ring(t, [2]string{secretB, "laptop"})}}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !servesBridge(t, h, capB) {
		t.Error("the added secret must work after the reload")
	}
	if servesBridge(t, h, capA) {
		t.Error("the removed secret must stop working after the reload")
	}
}

// A refused reload must leave the relay exactly as it was: reloading is not a
// way to take the relay down.
func TestReloadRefusalKeepsTheRunningConfiguration(t *testing.T) {
	for name, next := range map[string]Live{
		"no domains":       {},
		"unusable siteDir": {Domains: []Domain{{Name: testDomain, Keyring: ring(t, [2]string{secretA, "phone"}), SiteDir: t.TempDir()}}},
		"different domain": {Domains: []Domain{{Name: "other.example.com", Keyring: foreignRing(t)}}},
	} {
		h := handlerWith(t, ring(t, [2]string{secretA, "phone"}))
		if err := h.Reload(next); err == nil {
			t.Errorf("%s: reload must be refused", name)
		}
		if !servesBridge(t, h, capabilityOf(t, secretA)) {
			t.Errorf("%s: the running configuration did not survive", name)
		}
	}
}

func foreignRing(t *testing.T) *secret.Keyring {
	t.Helper()
	s, err := secret.Parse(secretA)
	if err != nil {
		t.Fatal(err)
	}
	k, err := secret.NewKeyring("other.example.com", []secret.Entry{{Secret: s, Label: "elsewhere"}})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// openSession completes the transport handshake and returns the live socket.
func openSession(t *testing.T, server *httptest.Server, capability string) *websocket.Conn {
	t.Helper()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") +
		"/?bridge=" + url.QueryEscape(capability)
	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		HandshakeTimeout: 5 * time.Second,
	}
	conn, _, err := dialer.Dial(endpoint, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	hello, err := frame.Marshal(frame.Hello, 0, []byte{frame.HelloVersion})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, hello); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatalf("welcome: %v", err)
	}
	return conn
}

// stillOpen reports whether the socket is alive. The relay answers nothing on
// its own while a session is idle, so a live session shows up as a read that
// times out, and a closed one as any other error.
func stillOpen(t *testing.T, conn *websocket.Conn) bool {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, _, err := conn.ReadMessage()
	if err == nil {
		return true
	}
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

// Revocation that leaves the current session running for days is not
// revocation, so removing a secret must drop its sessions and only those.
func TestReloadDropsSessionsOfRemovedSecrets(t *testing.T) {
	h := handlerWith(t, ring(t, [2]string{secretA, "phone"}, [2]string{secretB, "laptop"}))
	server := httptest.NewServer(h)
	defer server.Close()

	revoked := openSession(t, server, capabilityOf(t, secretA))
	kept := openSession(t, server, capabilityOf(t, secretB))

	if err := h.Reload(Live{Domains: []Domain{{Name: testDomain, Keyring: ring(t, [2]string{secretB, "laptop"})}}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if stillOpen(t, revoked) {
		t.Error("the revoked session must be closed by the reload")
	}
	if !stillOpen(t, kept) {
		t.Error("a session with a surviving secret must not be disturbed")
	}
}

// Renaming a secret is not revoking it.
func TestReloadKeepsSessionsWhenOnlyTheLabelChanges(t *testing.T) {
	h := handlerWith(t, ring(t, [2]string{secretA, "phone"}))
	server := httptest.NewServer(h)
	defer server.Close()

	conn := openSession(t, server, capabilityOf(t, secretA))
	if err := h.Reload(Live{Domains: []Domain{{Name: testDomain, Keyring: ring(t, [2]string{secretA, "renamed"})}}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !stillOpen(t, conn) {
		t.Error("a renamed secret must not drop its session")
	}
}
