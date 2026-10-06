package httpfront

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type ServerConfig struct {
	// Listen is the TLS address, normally ":443".
	Listen string
	// CertDir caches ACME certificates and account keys.
	CertDir string
	// PlainListen is the optional plain-HTTP address. A domain that answers
	// 443 but refuses 80 looks unusual, so serving it is part of the camouflage.
	PlainListen string
	// TLSConfig, when set, disables ACME; the local test bed relies on this.
	TLSConfig *tls.Config
	// Plaintext serves plain HTTP behind a reverse proxy that terminates TLS.
	// The real domain is still required: the capability is bound to it and the
	// bridge page opens wss:// against it.
	Plaintext bool
}

type Server struct {
	handler *Handler
	cfg     ServerConfig
	tls     *http.Server
	plain   *http.Server
}

// NewServer obtains and renews the certificate over ACME unless TLSConfig or
// Plaintext is set.
func NewServer(h *Handler, cfg ServerConfig) *Server {
	if cfg.Listen == "" {
		cfg.Listen = ":443"
	}

	tlsConfig := cfg.TLSConfig
	var manager *autocert.Manager
	if tlsConfig == nil && !cfg.Plaintext {
		manager = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(h.Domains()...),
			Cache:      autocert.DirCache(cfg.CertDir),
		}
		tlsConfig = manager.TLSConfig()
	}

	s := &Server{
		handler: h,
		cfg:     cfg,
		tls: &http.Server{
			Addr:              cfg.Listen,
			Handler:           h,
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: 15 * time.Second,
			// No write timeout: a relay session is a long-lived hijacked
			// connection, and a deadline would cut it off mid-transfer.
			IdleTimeout: 2 * time.Minute,
			ErrorLog:    nil,
		},
	}
	if cfg.Plaintext {
		// Behind a front end there is nothing to redirect and no challenge
		// to answer: the front end owns port 80.
		return s
	}
	if cfg.PlainListen != "" {
		plainHandler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Redirect to the name that was asked for when we serve it, so a
			// multi-domain relay does not bounce every visitor to one site.
			target := "https://" + redirectHost(h, r.Host) + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		}))
		if manager != nil {
			// Keeps the HTTP-01 challenge working when TLS-ALPN is blocked.
			plainHandler = manager.HTTPHandler(plainHandler)
		}
		s.plain = &http.Server{
			Addr:              cfg.PlainListen,
			Handler:           plainHandler,
			ReadHeaderTimeout: 15 * time.Second,
		}
	}
	return s
}

func (s *Server) Run(ctx context.Context) error {
	go s.handler.Run(ctx)

	errs := make(chan error, 2)
	if s.plain != nil {
		go func() {
			if err := s.plain.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errs <- err
			}
		}()
	}
	go func() {
		var err error
		if s.cfg.Plaintext {
			err = s.tls.ListenAndServe()
		} else {
			err = s.tls.ListenAndServeTLS("", "")
		}
		if err != nil && err != http.ErrServerClosed {
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

// redirectHost keeps a multi-domain relay from bouncing every visitor to one
// site, while an unknown name goes to the first domain we serve.
func redirectHost(h *Handler, host string) string {
	domain, _ := h.live.Load().lookup(host)
	return domain.name
}

func (s *Server) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.tls.Shutdown(ctx)
	if s.plain != nil {
		_ = s.plain.Shutdown(ctx)
	}
}
