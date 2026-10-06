package httpfront

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tgwebproxy/internal/secret"
)

func captureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func diagnoseHandler(t *testing.T, buf *bytes.Buffer, behindProxy bool) (*Handler, secret.Secret) {
	t.Helper()
	sec, err := secret.Parse("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := secret.NewKeyring("proxy.example.com", []secret.Entry{{Secret: sec, Label: "test"}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(Config{
		Domains:     []Domain{{Name: "proxy.example.com", Keyring: keys}},
		Logger:      captureLogger(buf),
		BehindProxy: behindProxy,
		Diagnose:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h, sec
}

// A request that never arrived leaves no line; one with the wrong secret says so.
func TestDiagnoseRecordsWhetherCapabilityMatched(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
		want  string
	}{
		{"valid capability", "", "authorized=true"},
		{"wrong capability", "?bridge=not-the-capability", "authorized=false"},
		{"no capability", "?x=1", "authorized=false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			h, sec := diagnoseHandler(t, &buf, false)

			query := tc.query
			if query == "" {
				query = "?bridge=" + sec.Capability("proxy.example.com")
			}
			req := httptest.NewRequest(http.MethodGet, "/"+query, nil)
			h.ServeHTTP(httptest.NewRecorder(), req)

			logged := buf.String()
			if !strings.Contains(logged, "msg=request") {
				t.Fatalf("no diagnostic line was logged: %q", logged)
			}
			if !strings.Contains(logged, tc.want) {
				t.Errorf("log says %q, want it to contain %q", logged, tc.want)
			}
		})
	}
}

// The capability is a bearer credential; a log that contains it steals the proxy.
func TestDiagnoseNeverLogsTheCapability(t *testing.T) {
	var buf bytes.Buffer
	h, sec := diagnoseHandler(t, &buf, false)

	capability := sec.Capability("proxy.example.com")
	req := httptest.NewRequest(http.MethodGet, "/?bridge="+capability, nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if strings.Contains(buf.String(), capability) {
		t.Fatalf("the capability leaked into the log: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "has_bridge_param=true") {
		t.Errorf("the log should still record that a capability was present: %q", buf.String())
	}
}

func TestPeerLabelUsesForwardedAddressOnlyBehindProxy(t *testing.T) {
	for _, tc := range []struct {
		name        string
		behindProxy bool
		want        string
	}{
		{"behind a front end, forwarded address wins", true, "203.0.113.7"},
		{"exposed directly, the header is not trusted", false, "192.0.2.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			h, _ := diagnoseHandler(t, &buf, tc.behindProxy)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "192.0.2.1:5555"
			req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")

			if got := h.peerLabel(req); got != tc.want {
				t.Errorf("peer label is %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDiagnoseIsOffByDefault(t *testing.T) {
	sec, err := secret.Parse("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := secret.NewKeyring("proxy.example.com", []secret.Entry{{Secret: sec, Label: "test"}})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	h, err := New(Config{
		Domains: []Domain{{Name: "proxy.example.com", Keyring: keys}},
		Logger:  captureLogger(&buf),
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/?bridge="+sec.Capability("proxy.example.com"), nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if strings.Contains(buf.String(), "msg=request") {
		t.Fatalf("a default relay logged a request: %q", buf.String())
	}
}
