package share

import (
	"net/url"
	"strings"
	"testing"

	"tgwebproxy/internal/secret"
)

func TestLinkCarriesBothFields(t *testing.T) {
	sec, err := secret.Parse("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	link := Link("proxy.example.com", sec)
	if !strings.HasPrefix(link, "https://t.me/webproxy?") {
		t.Fatalf("unexpected link: %s", link)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Get("server") != "proxy.example.com" {
		t.Errorf("server = %q", query.Get("server"))
	}
	// The client's Secret field takes hex, so the link must carry hex.
	if query.Get("secret") != "000102030405060708090a0b0c0d0e0f" {
		t.Errorf("secret = %q", query.Get("secret"))
	}
	if uri := TelegramURI("proxy.example.com", sec); !strings.HasPrefix(uri, "tg://webproxy?") {
		t.Errorf("unexpected uri: %s", uri)
	}
}

// A dd-prefixed secret keeps its prefix: it selects the padded-intermediate
// transport, and dropping it would hand the user a different proxy.
func TestLinkKeepsTheDDPrefix(t *testing.T) {
	sec, err := secret.Parse("dd000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(Link("proxy.example.com", sec), "secret=dd0001") {
		t.Errorf("dd prefix lost: %s", Link("proxy.example.com", sec))
	}
}
