package hostname

import "testing"

// Accept/reject pairs from MTP::WebProxyBridgeCapability's debug check in tdesktop.
func TestNormalizeMatchesClientAssertions(t *testing.T) {
	valid := map[string]string{
		" Proxy.Example.COM ":     "proxy.example.com",
		"bücher.example":          "xn--bcher-kva.example",
		"bücher.de":               "xn--bcher-kva.de",
		"xn--strae-oqa.example":   "xn--strae-oqa.example",
		"proxy.example.com":       "proxy.example.com",
		"a.b.c.example":           "a.b.c.example",
		"with-dash.example.co.uk": "with-dash.example.co.uk",
	}
	for in, want := range valid {
		got, err := Normalize(in)
		if err != nil {
			t.Errorf("Normalize(%q): unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}

	invalid := []string{
		"localhost",
		"127.0.0.1",
		"127.1",
		"0x7f.1",
		"0177.0.0.1",
		"1.2.3",
		"site.example:443",
		"site..example",
		"",
		"   ",
		"site.example.",
		"site.example/path",
		"user@site.example",
		"site.example?x=1",
		"site.example#frag",
		"-bad.example",
		"bad-.example",
	}
	for _, in := range invalid {
		if got, err := Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q, want error", in, got)
		}
	}
}

func TestNormalizeIsIdempotent(t *testing.T) {
	first, err := Normalize("Bücher.Example")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Normalize(first)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("not idempotent: %q then %q", first, second)
	}
}
