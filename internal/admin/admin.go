// Package admin serves health and metrics on a private listener.
//
// It is deliberately a second listener rather than a path on 443. A relay
// whose public port answers /metrics is a relay anyone can fingerprint by
// asking, which would undo the capability gate it is built around.
package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tgwebproxy/internal/httpfront"
	"tgwebproxy/internal/metrics"
	"tgwebproxy/internal/secret"
)

// ReadyFunc reports whether the relay can currently reach Telegram.
type ReadyFunc func(ctx context.Context) error

type Server struct {
	http    *http.Server
	network string
	address string
}

// New builds the admin server. The address is either a loopback host:port or
// a filesystem path, which is taken as a Unix socket — anything routable is
// refused, because exposing these counters is never what the operator meant.
//
// The socket form exists for containers: Docker cannot publish a port that a
// process bound to the container's own loopback, so a bind-mounted socket is
// the only way to keep the listener private and still reach it from the host.
func New(listen string, registry *metrics.Registry, ready ReadyFunc) (*Server, error) {
	return NewManaged(listen, registry, ready, nil, "")
}

// ClientManager is implemented by the public handler. The admin server uses it
// only on the private listener; the public WEB endpoint never exposes these APIs.
type ClientManager interface {
	ClientSnapshot() []httpfront.ClientDomain
	ReplaceClients(domain string, entries []secret.Entry) error
}

// NewManaged enables the 3x-ui management API when both manager and token are set.
func NewManaged(listen string, registry *metrics.Registry, ready ReadyFunc, manager ClientManager, token string) (*Server, error) {
	network, address, err := parseListen(listen)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if ready == nil {
			w.Write([]byte("ok\n"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := ready(ctx); err != nil {
			http.Error(w, "unreachable: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		registry.WriteTo(w)
	})
	if manager != nil && token != "" {
		mux.HandleFunc("/clients", managedClients(manager, registry, token))
	}

	return &Server{
		network: network,
		address: address,
		http: &http.Server{
			Addr:              address,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}, nil
}

type managedClient struct {
	Name        string `json:"name"`
	Secret      string `json:"secret,omitempty"`
	Enabled     bool   `json:"enabled"`
	ExpiresUnix int64  `json:"expires_unix,omitempty"`
	QuotaBytes  int64  `json:"quota_bytes,omitempty"`
	BytesUp     int64  `json:"bytes_up,omitempty"`
	BytesDown   int64  `json:"bytes_down,omitempty"`
	Sessions    int64  `json:"sessions_active,omitempty"`
	Streams     int64  `json:"streams_active,omitempty"`
}

type clientsPayload struct {
	Domain  string          `json:"domain"`
	Clients []managedClient `json:"clients"`
}

func managedClients(manager ClientManager, registry *metrics.Registry, token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, token) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			var out []clientsPayload
			for _, domain := range manager.ClientSnapshot() {
				item := clientsPayload{Domain: domain.Domain}
				for _, entry := range domain.Entries {
					labels := []string{"domain", domain.Domain, "label", entry.Label}
					item.Clients = append(item.Clients, managedClient{
						Name: entry.Label, Secret: entry.Secret.Hex(), Enabled: !entry.Disabled,
						ExpiresUnix: entry.ExpiresUnix, QuotaBytes: entry.QuotaBytes,
						BytesUp:   registry.Sum("tgwp_bytes_up_total", labels...),
						BytesDown: registry.Sum("tgwp_bytes_down_total", labels...),
						Sessions:  registry.Sum("tgwp_sessions_active", labels...),
						Streams:   registry.Sum("tgwp_streams_active", labels...),
					})
				}
				out = append(out, item)
			}
			writeJSON(w, http.StatusOK, out)
		case http.MethodPut:
			var input clientsPayload
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&input); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			if input.Domain == "" || len(input.Clients) == 0 {
				http.Error(w, "domain and at least one client are required", http.StatusBadRequest)
				return
			}
			entries := make([]secret.Entry, 0, len(input.Clients))
			seen := map[string]struct{}{}
			for _, client := range input.Clients {
				name := strings.TrimSpace(client.Name)
				if name == "" {
					http.Error(w, "client name is required", http.StatusBadRequest)
					return
				}
				if _, exists := seen[name]; exists {
					http.Error(w, "duplicate client name", http.StatusBadRequest)
					return
				}
				seen[name] = struct{}{}
				sec, err := secret.Parse(client.Secret)
				if err != nil || client.ExpiresUnix < 0 || client.QuotaBytes < 0 {
					http.Error(w, "invalid client policy", http.StatusBadRequest)
					return
				}
				entries = append(entries, secret.Entry{
					Secret: sec, Label: name, Disabled: !client.Enabled,
					ExpiresUnix: client.ExpiresUnix, QuotaBytes: client.QuotaBytes,
				})
			}
			if err := manager.ReplaceClients(input.Domain, entries); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		default:
			w.Header().Set("Allow", "GET, PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func authorized(r *http.Request, token string) bool {
	const prefix = "Bearer "
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	got := strings.TrimPrefix(value, prefix)
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// parseListen decides between a Unix socket and a loopback TCP address.
func parseListen(listen string) (network, address string, err error) {
	if path, ok := strings.CutPrefix(listen, "unix:"); ok {
		return "unix", path, nil
	}
	if strings.ContainsAny(listen, "/") || filepath.IsAbs(listen) {
		return "unix", listen, nil
	}
	if err := checkLoopback(listen); err != nil {
		return "", "", err
	}
	return "tcp", listen, nil
}

func checkLoopback(listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("admin: the admin listener must be on the loopback, " +
			"since it exposes counters that identify the relay")
	}
	return nil
}

// Run serves until the context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if s.network == "unix" {
		// A socket left behind by a killed process would block the bind.
		_ = os.Remove(s.address)
	}
	listener, err := net.Listen(s.network, s.address)
	if err != nil {
		return err
	}
	if s.network == "unix" {
		// Readable by the owner only: the endpoint has no authentication of
		// its own, and the filesystem is what stands in for it.
		if err := os.Chmod(s.address, 0o600); err != nil {
			listener.Close()
			return err
		}
		defer os.Remove(s.address)
	}

	errs := make(chan error, 1)
	go func() {
		if err := s.http.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()
	select {
	case <-ctx.Done():
	case err := <-errs:
		s.shutdown()
		return err
	}
	s.shutdown()
	return nil
}

func (s *Server) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = s.http.Shutdown(ctx)
}

func (s *Server) Addr() string { return s.address }

// listen binds the configured address, so a caller (a test, mainly) can learn
// the port before serving.
func listen(s *Server) (net.Listener, error) {
	return net.Listen(s.network, s.address)
}
