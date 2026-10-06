package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tgwebproxy/internal/httpfront"
	"tgwebproxy/internal/metrics"
	"tgwebproxy/internal/secret"
)

func TestRefusesToListenBeyondLoopback(t *testing.T) {
	registry := metrics.New()
	for _, listen := range []string{":9600", "0.0.0.0:9600", "192.0.2.10:9600", "[::]:9600"} {
		if _, err := New(listen, registry, nil); err == nil {
			t.Errorf("%s was accepted; the admin listener exposes counters that "+
				"identify the relay and must stay on the loopback", listen)
		}
	}
	for _, listen := range []string{"127.0.0.1:9600", "localhost:9600", "[::1]:9600"} {
		if _, err := New(listen, registry, nil); err != nil {
			t.Errorf("%s was refused: %v", listen, err)
		}
	}
}

func serve(t *testing.T, ready ReadyFunc) string {
	t.Helper()
	registry := metrics.New()
	registry.Add("tgwp_sessions_started_total", 3, "domain", "a.example.com", "label", "phone")

	server, err := New("127.0.0.1:0", registry, ready)
	if err != nil {
		t.Fatal(err)
	}
	// Bind explicitly so the test knows the port.
	listener, err := listen(server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go server.http.Serve(listener)
	return "http://" + listener.Addr().String()
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func TestEndpoints(t *testing.T) {
	base := serve(t, func(context.Context) error { return nil })

	if code, body := get(t, base+"/healthz"); code != 200 || !strings.Contains(body, "ok") {
		t.Errorf("healthz = %d %q", code, body)
	}
	if code, body := get(t, base+"/readyz"); code != 200 || !strings.Contains(body, "ok") {
		t.Errorf("readyz = %d %q", code, body)
	}
	code, body := get(t, base+"/metrics")
	if code != 200 {
		t.Fatalf("metrics = %d", code)
	}
	if !strings.Contains(body, `tgwp_sessions_started_total{domain="a.example.com",label="phone"} 3`) {
		t.Errorf("metrics body missing the series:\n%s", body)
	}
}

// Readiness answers the question a process cannot answer from inside itself:
// can this host reach Telegram. An unreachable data centre is not "healthy".
func TestReadyzReportsAnUnreachableDataCentre(t *testing.T) {
	base := serve(t, func(context.Context) error { return errors.New("no route to host") })
	if code, body := get(t, base+"/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("readyz = %d %q, want 503", code, body)
	}
	if code, _ := get(t, base+"/healthz"); code != 200 {
		t.Error("healthz must stay 200: the process itself is fine")
	}
}

// Docker cannot publish a port that a process bound to the container's own
// loopback, so a container that wants these counters needs a socket.
func TestUnixSocketListener(t *testing.T) {
	if _, err := net.Listen("unix", filepath.Join(t.TempDir(), "probe.sock")); err != nil {
		t.Skipf("unix sockets are not available here: %v", err)
	}
	path := filepath.Join(t.TempDir(), "admin.sock")
	registry := metrics.New()
	registry.Add("tgwp_sessions_active", 2, "domain", "a.example.com", "label", "phone")

	server, err := New(path, registry, nil)
	if err != nil {
		t.Fatalf("a socket path must be accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
	var body string
	for i := 0; i < 50; i++ {
		resp, err := client.Get("http://admin/metrics")
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body = string(raw)
		break
	}
	if !strings.Contains(body, "tgwp_sessions_active") {
		t.Errorf("metrics over the socket returned %q", body)
	}

	cancel()
	<-done
	if _, err := os.Stat(path); err == nil {
		t.Error("the socket outlived the server")
	}
}

// The "unix:" prefix is accepted for an address that would otherwise look
// like a host:port.
func TestUnixPrefix(t *testing.T) {
	network, address, err := parseListen("unix:/run/tgwebproxy/admin.sock")
	if err != nil {
		t.Fatal(err)
	}
	if network != "unix" || address != "/run/tgwebproxy/admin.sock" {
		t.Errorf("parseListen = %q %q", network, address)
	}
}


type fakeManager struct {
	domains []httpfront.ClientDomain
}

func (m *fakeManager) ClientSnapshot() []httpfront.ClientDomain {
	return m.domains
}

func (m *fakeManager) ReplaceClients(domain string, entries []secret.Entry) error {
	for i := range m.domains {
		if m.domains[i].Domain == domain {
			m.domains[i].Entries = entries
			return nil
		}
	}
	return errors.New("unknown domain")
}

func TestManagedClientsAPI(t *testing.T) {
	sec, err := secret.Parse("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	manager := &fakeManager{domains: []httpfront.ClientDomain{{
		Domain: "web.example.com",
		Entries: []secret.Entry{{
			Secret: sec, Label: "alice", QuotaBytes: 1024,
		}},
	}}}
	registry := metrics.New()
	registry.Add("tgwp_bytes_up_total", 100, "domain", "web.example.com", "label", "alice")

	server, err := NewManaged("127.0.0.1:0", registry, nil, manager, "test-token")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := listen(server)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go server.http.Serve(listener)
	base := "http://" + listener.Addr().String()

	resp, err := http.Get(base + "/clients")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET = %d, want 401", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, base+"/clients", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var got []clientsPayload
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(got) != 1 || got[0].Clients[0].BytesUp != 100 {
		t.Fatalf("GET clients = status %d payload %+v", resp.StatusCode, got)
	}

	body := []byte(`{"domain":"web.example.com","clients":[{"name":"bob","secret":"0f0e0d0c0b0a09080706050403020100","enabled":true,"expires_unix":2000000000,"quota_bytes":2048}]}`)
	req, _ = http.NewRequest(http.MethodPut, base+"/clients", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT clients = %d", resp.StatusCode)
	}
	entries := manager.domains[0].Entries
	if len(entries) != 1 || entries[0].Label != "bob" || entries[0].Disabled ||
		entries[0].ExpiresUnix != 2000000000 || entries[0].QuotaBytes != 2048 {
		t.Fatalf("manager state = %+v", entries)
	}
}
