package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `
domain       = "Proxy.Example.COM"
listen       = "127.0.0.1:4600"
behind_proxy = true
log_level    = "debug"
max_streams  = 32

[[secret]]
value = "000102030405060708090a0b0c0d0e0f"
label = "phone"

[[secret]]
value = "dd0f0e0d0c0b0a09080706050403020100"
label = "laptop"
`

func TestParseSample(t *testing.T) {
	cfg, err := Parse([]byte(sample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// The client hashes its own normalised spelling, so the config must be
	// normalised before any capability is computed from it.
	if len(cfg.Domains) != 1 || cfg.Domains[0].Name != "proxy.example.com" {
		t.Fatalf("domains = %+v, want one normalised name", cfg.Domains)
	}
	if cfg.Listen != "127.0.0.1:4600" || !cfg.BehindProxy {
		t.Errorf("listener settings not carried through: %+v", cfg)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Errorf("log level = %v, want debug", cfg.LogLevel)
	}
	if cfg.MaxStreams != 32 {
		t.Errorf("max_streams = %d, want 32", cfg.MaxStreams)
	}
	entries := cfg.Domains[0].Entries
	if len(entries) != 2 {
		t.Fatalf("got %d secrets, want 2", len(entries))
	}
	if entries[0].Label != "phone" || entries[1].Label != "laptop" {
		t.Errorf("labels not carried through: %+v", entries)
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`
domain = "proxy.example.com"
[[secret]]
value = "000102030405060708090a0b0c0d0e0f"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Listen != ":443" || cfg.PlainListen != ":80" || cfg.CertDir != "certs" {
		t.Errorf("wrong defaults: %+v", cfg)
	}
	if cfg.MaxStreams != 64 || cfg.LogLevel != slog.LevelInfo {
		t.Errorf("wrong defaults: %+v", cfg)
	}
	if cfg.Domains[0].Entries[0].Label == "" {
		t.Error("an unlabelled secret must get a generated label")
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"no domain": `
[[secret]]
value = "000102030405060708090a0b0c0d0e0f"
`,
		"bad domain": `
domain = "127.0.0.1"
[[secret]]
value = "000102030405060708090a0b0c0d0e0f"
`,
		"no secrets": `domain = "proxy.example.com"`,
		"bad secret": `
domain = "proxy.example.com"
[[secret]]
value = "not-a-secret"
`,
		"fake tls secret": `
domain = "proxy.example.com"
[[secret]]
value = "ee000102030405060708090a0b0c0d0e0f7777772e676f6f676c652e636f6d"
`,
		"duplicate label": `
domain = "proxy.example.com"
[[secret]]
value = "000102030405060708090a0b0c0d0e0f"
label = "same"
[[secret]]
value = "0f0e0d0c0b0a09080706050403020100"
label = "same"
`,
		"unknown key": `
domain = "proxy.example.com"
maxstreams = 8
[[secret]]
value = "000102030405060708090a0b0c0d0e0f"
`,
		"bad log level": `
domain = "proxy.example.com"
log_level = "chatty"
[[secret]]
value = "000102030405060708090a0b0c0d0e0f"
`,
	}
	for name, text := range cases {
		if cfg, err := Parse([]byte(text)); err == nil {
			t.Errorf("%s: accepted, got %+v", name, cfg)
		}
	}
}

func TestLoadReportsThePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.toml")
	if err := os.WriteFile(path, []byte("domain = "), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("a malformed file must fail to load")
	} else if !strings.Contains(err.Error(), "relay.toml") {
		t.Errorf("error must name the file, got %v", err)
	}
}

// Changing these at runtime cannot work: the domain is baked into every
// capability and into the ACME host policy, and the listeners are bound.
func TestCheckStaticMatch(t *testing.T) {
	base, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	same, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if err := base.CheckStaticMatch(same); err != nil {
		t.Errorf("identical configs must match: %v", err)
	}

	changed, err := Parse([]byte(strings.Replace(sample,
		`domain       = "Proxy.Example.COM"`,
		`domain       = "other.example.com"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := base.CheckStaticMatch(changed); err == nil ||
		!strings.Contains(err.Error(), "domain") {
		t.Errorf("a changed domain must be reported by name, got %v", err)
	}

	// Changing the secret list is exactly what reload is for.
	reduced, err := Parse([]byte(strings.Split(sample, "[[secret]]")[0] + `
[[secret]]
value = "000102030405060708090a0b0c0d0e0f"
label = "phone"
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := base.CheckStaticMatch(reduced); err != nil {
		t.Errorf("changing the secret list must be allowed: %v", err)
	}
}

const multi = `
listen = "127.0.0.1:4600"

[[host]]
name = "files.example.com"
site = "/srv/files"
  [[host.secret]]
  value = "000102030405060708090a0b0c0d0e0f"
  label = "phone"

[[host]]
name = "Media.Example.NET"
  [[host.secret]]
  value = "0f0e0d0c0b0a09080706050403020100"
  label = "laptop"
  [[host.secret]]
  value = "112233445566778899aabbccddeeff00"
  label = "tablet"
`

func TestParseMultipleHosts(t *testing.T) {
	cfg, err := Parse([]byte(multi))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.DomainNames(); len(got) != 2 ||
		got[0] != "files.example.com" || got[1] != "media.example.net" {
		t.Fatalf("domains = %v, want both, normalised", got)
	}
	if cfg.Domains[0].Site != "/srv/files" || cfg.Domains[1].Site != "" {
		t.Errorf("per-domain site not carried through: %+v", cfg.Domains)
	}
	if len(cfg.Domains[0].Entries) != 1 || len(cfg.Domains[1].Entries) != 2 {
		t.Errorf("secrets not attached to the right domain: %+v", cfg.Domains)
	}
}

// The same secret may serve two domains: the capability differs because the
// host is hashed into it, so this is not a collision.
func TestSameSecretOnTwoHostsIsAllowed(t *testing.T) {
	_, err := Parse([]byte(`
[[host]]
name = "a.example.com"
  [[host.secret]]
  value = "000102030405060708090a0b0c0d0e0f"

[[host]]
name = "b.example.com"
  [[host.secret]]
  value = "000102030405060708090a0b0c0d0e0f"
`))
	if err != nil {
		t.Errorf("one secret on two domains must be allowed: %v", err)
	}
}

func TestMultiHostRejects(t *testing.T) {
	cases := map[string]string{
		"mixed with top level": `
domain = "a.example.com"
[[secret]]
value = "000102030405060708090a0b0c0d0e0f"
[[host]]
name = "b.example.com"
  [[host.secret]]
  value = "0f0e0d0c0b0a09080706050403020100"
`,
		"duplicate host": `
[[host]]
name = "a.example.com"
  [[host.secret]]
  value = "000102030405060708090a0b0c0d0e0f"
[[host]]
name = "A.Example.com"
  [[host.secret]]
  value = "0f0e0d0c0b0a09080706050403020100"
`,
		"host without secrets": `
[[host]]
name = "a.example.com"
`,
		"host without a name": `
[[host]]
  [[host.secret]]
  value = "000102030405060708090a0b0c0d0e0f"
`,
	}
	for name, text := range cases {
		if cfg, err := Parse([]byte(text)); err == nil {
			t.Errorf("%s: accepted, got %+v", name, cfg)
		}
	}
}

func TestCheckStaticMatchGuardsTheDomainSet(t *testing.T) {
	base, err := Parse([]byte(multi))
	if err != nil {
		t.Fatal(err)
	}
	// Changing the secrets of a domain is fine.
	relaxed, err := Parse([]byte(strings.Replace(multi,
		`  [[host.secret]]
  value = "112233445566778899aabbccddeeff00"
  label = "tablet"
`, "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := base.CheckStaticMatch(relaxed); err != nil {
		t.Errorf("changing a domain's secrets must be allowed: %v", err)
	}
	// Dropping a domain is not.
	fewer, err := Parse([]byte(strings.Split(multi, "[[host]]\nname = \"Media.Example.NET\"")[0]))
	if err != nil {
		t.Fatal(err)
	}
	if err := base.CheckStaticMatch(fewer); err == nil {
		t.Error("dropping a domain must need a restart")
	}
}
