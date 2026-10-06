package admin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"tgwebproxy/internal/httpfront"
	"tgwebproxy/internal/secret"
)

// persistentManager decorates the live client manager with an atomic JSON
// snapshot. The TOML remains the bootstrap/static configuration; management
// changes survive process restarts without rewriting operator-owned config.
type persistentManager struct {
	live ClientManager
	path string
}

type stateFile struct {
	Domains []stateDomain `json:"domains"`
}

type stateDomain struct {
	Domain  string        `json:"domain"`
	Clients []stateClient `json:"clients"`
}

type stateClient struct {
	Name        string `json:"name"`
	Secret      string `json:"secret"`
	Disabled    bool   `json:"disabled,omitempty"`
	ExpiresUnix int64  `json:"expires_unix,omitempty"`
	QuotaBytes  int64  `json:"quota_bytes,omitempty"`
}

func newPersistentManager(live ClientManager, path string) (*persistentManager, error) {
	p := &persistentManager{live: live, path: path}
	if path == "" {
		return p, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return p, nil
	}
	if err != nil {
		return nil, fmt.Errorf("admin: read state: %w", err)
	}
	var saved stateFile
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("admin: parse state: %w", err)
	}
	for _, domain := range saved.Domains {
		entries := make([]secret.Entry, 0, len(domain.Clients))
		for _, client := range domain.Clients {
			sec, err := secret.Parse(client.Secret)
			if err != nil {
				return nil, fmt.Errorf("admin: state client %q: %w", client.Name, err)
			}
			entries = append(entries, secret.Entry{
				Secret: sec, Label: client.Name, Disabled: client.Disabled,
				ExpiresUnix: client.ExpiresUnix, QuotaBytes: client.QuotaBytes,
			})
		}
		if err := live.ReplaceClients(domain.Domain, entries); err != nil {
			return nil, fmt.Errorf("admin: apply state for %q: %w", domain.Domain, err)
		}
	}
	return p, nil
}

func (p *persistentManager) ClientSnapshot() []httpfront.ClientDomain {
	return p.live.ClientSnapshot()
}

func (p *persistentManager) ReplaceClients(domain string, entries []secret.Entry) error {
	if p.path == "" {
		return p.live.ReplaceClients(domain, entries)
	}

	// Validate against the live manager before touching disk, then persist the
	// complete desired snapshot atomically. If persistence fails, restore the
	// old live state so memory and disk never intentionally diverge.
	before := p.live.ClientSnapshot()
	if err := p.live.ReplaceClients(domain, entries); err != nil {
		return err
	}
	if err := p.save(); err != nil {
		for _, d := range before {
			if d.Domain == domain {
				_ = p.live.ReplaceClients(domain, d.Entries)
				break
			}
		}
		return err
	}
	return nil
}

func (p *persistentManager) save() error {
	snapshot := p.live.ClientSnapshot()
	state := stateFile{Domains: make([]stateDomain, 0, len(snapshot))}
	for _, domain := range snapshot {
		out := stateDomain{Domain: domain.Domain, Clients: make([]stateClient, 0, len(domain.Entries))}
		for _, entry := range domain.Entries {
			out.Clients = append(out.Clients, stateClient{
				Name: entry.Label, Secret: entry.Secret.Hex(), Disabled: entry.Disabled,
				ExpiresUnix: entry.ExpiresUnix, QuotaBytes: entry.QuotaBytes,
			})
		}
		state.Domains = append(state.Domains, out)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(p.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("admin: create state directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tgwebproxy-state-*")
	if err != nil {
		return fmt.Errorf("admin: create state temp file: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, p.path); err != nil {
		return fmt.Errorf("admin: replace state: %w", err)
	}
	return nil
}
