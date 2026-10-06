// Package admin serves health and metrics on a private listener.
//
// It is deliberately a second listener rather than a path on 443. A relay
// whose public port answers /metrics is a relay anyone can fingerprint by
// asking, which would undo the capability gate it is built around.
package admin

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tgwebproxy/internal/metrics"
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
