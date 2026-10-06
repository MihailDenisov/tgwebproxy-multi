package httpfront

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"tgwebproxy/internal/secret"
)

const otherDomain = "media.example.net"

func ringFor(t *testing.T, host string, pairs ...[2]string) *secret.Keyring {
	t.Helper()
	entries := make([]secret.Entry, 0, len(pairs))
	for _, p := range pairs {
		s, err := secret.Parse(p[0])
		if err != nil {
			t.Fatalf("Parse(%s): %v", p[0], err)
		}
		entries = append(entries, secret.Entry{Secret: s, Label: p[1]})
	}
	k, err := secret.NewKeyring(host, entries)
	if err != nil {
		t.Fatalf("NewKeyring(%s): %v", host, err)
	}
	return k
}

func capabilityFor(t *testing.T, host, text string) string {
	t.Helper()
	s, err := secret.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return s.Capability(host)
}

func bridgeFor(t *testing.T, h *Handler, host, capability string) bool {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/?bridge="+url.QueryEscape(capability), nil)
	req.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return bytes.Contains(rec.Body.Bytes(), []byte("TelegramWebProxy"))
}

func twoDomains(t *testing.T) *Handler {
	t.Helper()
	h, err := New(Config{
		Domains: []Domain{
			{Name: testDomain, Keyring: ringFor(t, testDomain, [2]string{secretA, "phone"})},
			{Name: otherDomain, Keyring: ringFor(t, otherDomain, [2]string{secretB, "laptop"})},
		},
		Logger: quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// A capability is bound to one host. Serving both names from one process must
// not let a capability minted for one open the bridge on the other.
func TestCapabilitiesDoNotCrossDomains(t *testing.T) {
	h := twoDomains(t)

	if !bridgeFor(t, h, testDomain, capabilityFor(t, testDomain, secretA)) {
		t.Error("the first domain did not serve its own bridge")
	}
	if !bridgeFor(t, h, otherDomain, capabilityFor(t, otherDomain, secretB)) {
		t.Error("the second domain did not serve its own bridge")
	}
	if bridgeFor(t, h, otherDomain, capabilityFor(t, testDomain, secretA)) {
		t.Error("a capability for the first domain opened the second")
	}
	if bridgeFor(t, h, testDomain, capabilityFor(t, otherDomain, secretB)) {
		t.Error("a capability for the second domain opened the first")
	}
	// The same secret bound to the other host is still the wrong capability.
	if bridgeFor(t, h, otherDomain, capabilityFor(t, otherDomain, secretA)) {
		t.Error("a secret configured elsewhere was accepted")
	}
}

func TestHostWithPortAndCaseIsMatched(t *testing.T) {
	h := twoDomains(t)
	capability := capabilityFor(t, otherDomain, secretB)
	for _, host := range []string{otherDomain, otherDomain + ":443", "MEDIA.Example.NET", otherDomain + "."} {
		if !bridgeFor(t, h, host, capability) {
			t.Errorf("Host %q did not resolve to its domain", host)
		}
	}
}

// A request for a name we do not serve must look like an ordinary site, not
// like a server that knows it is being probed.
func TestUnknownHostGetsTheFallbackCover(t *testing.T) {
	h := twoDomains(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "someone-elses.example.org"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("unknown host answered %d, want 200", rec.Code)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("TelegramWebProxy")) {
		t.Error("unknown host was served the bridge")
	}
	if bridgeFor(t, h, "someone-elses.example.org", capabilityFor(t, testDomain, secretA)) {
		t.Error("a valid capability opened the bridge on an unserved host")
	}
}

func TestReloadIsPerDomain(t *testing.T) {
	h := twoDomains(t)
	const extra = "112233445566778899aabbccddeeff00"

	err := h.Reload(Live{Domains: []Domain{
		{Name: testDomain, Keyring: ringFor(t, testDomain,
			[2]string{secretA, "phone"}, [2]string{extra, "tablet"})},
		{Name: otherDomain, Keyring: ringFor(t, otherDomain, [2]string{secretB, "laptop"})},
	}})
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if !bridgeFor(t, h, testDomain, capabilityFor(t, testDomain, extra)) {
		t.Error("the secret added to the first domain does not work")
	}
	if bridgeFor(t, h, otherDomain, capabilityFor(t, otherDomain, extra)) {
		t.Error("a secret added to one domain leaked into the other")
	}
	if !bridgeFor(t, h, otherDomain, capabilityFor(t, otherDomain, secretB)) {
		t.Error("the untouched domain stopped working")
	}
}

// Adding or removing a name needs a restart: the ACME host policy is fixed at
// start-up, and a name added here would have no certificate.
func TestReloadCannotChangeTheDomainSet(t *testing.T) {
	h := twoDomains(t)
	cases := map[string][]Domain{
		"dropped": {
			{Name: testDomain, Keyring: ringFor(t, testDomain, [2]string{secretA, "phone"})},
		},
		"replaced": {
			{Name: testDomain, Keyring: ringFor(t, testDomain, [2]string{secretA, "phone"})},
			{Name: "third.example.org", Keyring: ringFor(t, "third.example.org", [2]string{secretB, "laptop"})},
		},
	}
	for name, domains := range cases {
		if err := h.Reload(Live{Domains: domains}); err == nil {
			t.Errorf("%s: reload must be refused", name)
		}
	}
	if !bridgeFor(t, h, otherDomain, capabilityFor(t, otherDomain, secretB)) {
		t.Error("a refused reload disturbed the running configuration")
	}
}

// With one domain there is nothing to route, so a front end that rewrites the
// Host header must not silently stop the relay from working.
func TestSingleDomainAcceptsAnyHost(t *testing.T) {
	h, err := New(Config{
		Domains: []Domain{{Name: testDomain, Keyring: ringFor(t, testDomain, [2]string{secretA, "phone"})}},
		Logger:  quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	capability := capabilityFor(t, testDomain, secretA)
	for _, host := range []string{testDomain, "127.0.0.1:4600", "backend.internal", ""} {
		if !bridgeFor(t, h, host, capability) {
			t.Errorf("Host %q was not served by a single-domain relay", host)
		}
	}
}

// The admin paths live on their own loopback listener. On 443 they must be
// nothing but ordinary URLs, or the relay answers "I am a relay" to anyone who
// asks.
func TestAdminPathsDoNotExistOnThePublicPort(t *testing.T) {
	h := twoDomains(t)
	for _, path := range []string{"/metrics", "/healthz", "/readyz", "/debug/pprof/"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = testDomain
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		body := rec.Body.String()
		if strings.Contains(body, "tgwp_") || strings.Contains(body, "ok\n") {
			t.Errorf("%s leaked an admin response: %q", path, body)
		}
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s answered %d; the built-in cover serves 404 off the root", path, rec.Code)
		}
	}
}
