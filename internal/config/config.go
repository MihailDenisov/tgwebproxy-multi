// Package config parses the relay's TOML configuration into a validated,
// immutable snapshot. It performs no I/O beyond reading the file and knows
// nothing about signals: reloading is the caller's business.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"tgwebproxy/internal/hostname"
	"tgwebproxy/internal/secret"
)

type file struct {
	Domain      string      `toml:"domain"`
	Site        string      `toml:"site"`
	Secrets     []fileEntry `toml:"secret"`
	Hosts       []fileHost  `toml:"host"`
	Listen      string      `toml:"listen"`
	PlainListen string      `toml:"plain_listen"`
	BehindProxy bool        `toml:"behind_proxy"`
	CertDir     string      `toml:"cert_dir"`
	LogLevel    string      `toml:"log_level"`
	MaxStreams  int         `toml:"max_streams"`
	Diagnose    bool        `toml:"diagnose"`
	Admin       fileAdmin   `toml:"admin"`
}

type fileAdmin struct {
	Listen string `toml:"listen"`
}

type fileEntry struct {
	Value string `toml:"value"`
	Label string `toml:"label"`
}

type fileHost struct {
	Name    string      `toml:"name"`
	Site    string      `toml:"site"`
	Secrets []fileEntry `toml:"secret"`
}

// Domain is one served name with its own secrets and cover site. Capabilities
// are bound to the name, so domains share nothing but the process.
type Domain struct {
	Name    string
	Site    string
	Entries []secret.Entry
}

// Config is a validated snapshot. Everything in it is already normalised, so
// consumers never repeat validation.
type Config struct {
	Domains     []Domain
	Listen      string
	PlainListen string
	CertDir     string
	BehindProxy bool
	Diagnose    bool
	LogLevel    slog.Level
	MaxStreams  int
	// AdminListen serves health and metrics. Empty disables it.
	AdminListen string
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func Parse(data []byte) (*Config, error) {
	var raw file
	meta, err := toml.Decode(string(data), &raw)
	if err != nil {
		return nil, err
	}
	// A typo in a key would otherwise be ignored, leaving the operator to
	// wonder why the setting had no effect.
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		names := make([]string, 0, len(undecoded))
		for _, key := range undecoded {
			names = append(names, key.String())
		}
		return nil, fmt.Errorf("config: unknown key(s): %s", strings.Join(names, ", "))
	}

	cfg := &Config{
		Listen:      ":443",
		PlainListen: ":80",
		CertDir:     "certs",
		LogLevel:    slog.LevelInfo,
		MaxStreams:  64,
		BehindProxy: raw.BehindProxy,
		Diagnose:    raw.Diagnose,
	}
	if raw.Listen != "" {
		cfg.Listen = raw.Listen
	}
	if raw.PlainListen != "" {
		cfg.PlainListen = raw.PlainListen
	}
	if raw.CertDir != "" {
		cfg.CertDir = raw.CertDir
	}
	if raw.MaxStreams != 0 {
		if raw.MaxStreams < 1 {
			return nil, fmt.Errorf("config: max_streams must be positive, got %d", raw.MaxStreams)
		}
		cfg.MaxStreams = raw.MaxStreams
	}
	if raw.LogLevel != "" {
		var level slog.Level
		if err := level.UnmarshalText([]byte(strings.ToLower(raw.LogLevel))); err != nil {
			return nil, fmt.Errorf("config: log_level %q is not one of debug, info, warn, error", raw.LogLevel)
		}
		cfg.LogLevel = level
	}

	cfg.AdminListen = strings.TrimSpace(raw.Admin.Listen)

	cfg.Domains, err = parseDomains(raw)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// parseDomains accepts either the single-domain shape (top-level domain, site
// and [[secret]]) or the multi-domain one ([[host]] blocks). Mixing them is an
// error rather than a merge: which secrets belong to which name would be a
// guess, and guessing wrong hands a client a capability for the wrong domain.
func parseDomains(raw file) ([]Domain, error) {
	single := raw.Domain != "" || len(raw.Secrets) > 0 || raw.Site != ""
	if single && len(raw.Hosts) > 0 {
		return nil, errors.New("config: use either a top-level domain or [[host]] blocks, not both")
	}
	if !single && len(raw.Hosts) == 0 {
		return nil, errors.New("config: a domain is required")
	}

	hosts := raw.Hosts
	if single {
		hosts = []fileHost{{Name: raw.Domain, Site: raw.Site, Secrets: raw.Secrets}}
	}

	domains := make([]Domain, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for i, host := range hosts {
		if host.Name == "" {
			return nil, fmt.Errorf("config: host %d has no name", i+1)
		}
		// The client hashes its normalised spelling of the host into the
		// capability, so the relay must store the same spelling.
		name, err := hostname.Normalize(host.Name)
		if err != nil {
			return nil, fmt.Errorf("config: domain %q: %w", host.Name, err)
		}
		if _, clash := seen[name]; clash {
			return nil, fmt.Errorf("config: domain %q is configured twice", name)
		}
		seen[name] = struct{}{}

		entries, err := parseEntries(name, host.Secrets)
		if err != nil {
			return nil, err
		}
		domains = append(domains, Domain{Name: name, Site: host.Site, Entries: entries})
	}
	return domains, nil
}

func parseEntries(domain string, raw []fileEntry) ([]secret.Entry, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("config: domain %q has no [[secret]]", domain)
	}
	entries := make([]secret.Entry, 0, len(raw))
	labels := make(map[string]struct{}, len(raw))
	for i, entry := range raw {
		parsed, err := secret.Parse(entry.Value)
		if err != nil {
			return nil, fmt.Errorf("config: domain %q, secret %d: %w", domain, i+1, err)
		}
		label := strings.TrimSpace(entry.Label)
		if label == "" {
			label = fmt.Sprintf("secret-%d", i+1)
		}
		if _, clash := labels[label]; clash {
			return nil, fmt.Errorf("config: domain %q uses the label %q twice", domain, label)
		}
		labels[label] = struct{}{}
		entries = append(entries, secret.Entry{Secret: parsed, Label: label})
	}
	return entries, nil
}

// CheckStaticMatch reports the first setting that cannot change while the
// relay runs: the listeners are already bound, and the set of served names is
// fixed by the ACME host policy and by the capabilities already handed out.
// A domain's secrets and cover site are absent from this list — changing those
// is the point of reloading.
func (c *Config) CheckStaticMatch(next *Config) error {
	for _, field := range []struct {
		name       string
		old, fresh string
	}{
		{"listen", c.Listen, next.Listen},
		{"plain_listen", c.PlainListen, next.PlainListen},
		{"cert_dir", c.CertDir, next.CertDir},
		{"admin.listen", c.AdminListen, next.AdminListen},
	} {
		if field.old != field.fresh {
			return fmt.Errorf("config: %s cannot change without a restart (%q -> %q)",
				field.name, field.old, field.fresh)
		}
	}
	if c.BehindProxy != next.BehindProxy {
		return fmt.Errorf("config: behind_proxy cannot change without a restart (%v -> %v)",
			c.BehindProxy, next.BehindProxy)
	}
	if old, fresh := c.DomainNames(), next.DomainNames(); strings.Join(old, ",") != strings.Join(fresh, ",") {
		return fmt.Errorf("config: the set of domains cannot change without a restart (%v -> %v)",
			old, fresh)
	}
	return nil
}

func (c *Config) DomainNames() []string {
	names := make([]string, 0, len(c.Domains))
	for _, d := range c.Domains {
		names = append(names, d.Name)
	}
	return names
}
