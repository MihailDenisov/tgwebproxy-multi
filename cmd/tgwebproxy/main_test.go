package main

import (
	"testing"

	"tgwebproxy/internal/config"
	"tgwebproxy/internal/httpfront"
	"tgwebproxy/internal/secret"
)

func mustSecret(t *testing.T, text string) secret.Secret {
	t.Helper()
	s, err := secret.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBuildReloadDomainsPreservesManagedClients(t *testing.T) {
	const domain = "proxy.example.com"
	bootstrap := secret.Entry{Secret: mustSecret(t, "000102030405060708090a0b0c0d0e0f"), Label: "_bootstrap", Disabled: true}
	managed := secret.Entry{Secret: mustSecret(t, "0f0e0d0c0b0a09080706050403020100"), Label: "alice", QuotaBytes: 1234}

	ring, err := secret.NewKeyring(domain, []secret.Entry{bootstrap})
	if err != nil {
		t.Fatal(err)
	}
	h, err := httpfront.New(httpfront.Config{Domains: []httpfront.Domain{{Name: domain, Keyring: ring}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.ReplaceClients(domain, []secret.Entry{managed}); err != nil {
		t.Fatal(err)
	}

	next := &config.Config{Domains: []config.Domain{{Name: domain, Site: "", Entries: []secret.Entry{bootstrap}}}}
	domains, err := buildReloadDomains(next, h, true)
	if err != nil {
		t.Fatal(err)
	}
	got := domains[0].Keyring.Entries()
	if len(got) != 1 || got[0].Label != "alice" || !got[0].Secret.Equal(managed.Secret) || got[0].QuotaBytes != 1234 {
		t.Fatalf("managed clients not preserved: %#v", got)
	}
}

func TestBuildReloadDomainsUsesConfigWhenUnmanaged(t *testing.T) {
	const domain = "proxy.example.com"
	oldEntry := secret.Entry{Secret: mustSecret(t, "000102030405060708090a0b0c0d0e0f"), Label: "old"}
	fresh := secret.Entry{Secret: mustSecret(t, "0f0e0d0c0b0a09080706050403020100"), Label: "fresh"}

	ring, err := secret.NewKeyring(domain, []secret.Entry{oldEntry})
	if err != nil {
		t.Fatal(err)
	}
	h, err := httpfront.New(httpfront.Config{Domains: []httpfront.Domain{{Name: domain, Keyring: ring}}})
	if err != nil {
		t.Fatal(err)
	}
	next := &config.Config{Domains: []config.Domain{{Name: domain, Entries: []secret.Entry{fresh}}}}
	domains, err := buildReloadDomains(next, h, false)
	if err != nil {
		t.Fatal(err)
	}
	got := domains[0].Keyring.Entries()
	if len(got) != 1 || got[0].Label != "fresh" || !got[0].Secret.Equal(fresh.Secret) {
		t.Fatalf("config secret not applied: %#v", got)
	}
}
