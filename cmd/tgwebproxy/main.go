// Command tgwebproxy is a relay for the WEB proxy type in Telegram Desktop
// 7.1.1: an ordinary web site on 443 and, only to a client that knows the
// secret, a bridge page whose WebSocket carries multiplexed MTProto traffic.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tgwebproxy/internal/admin"
	"tgwebproxy/internal/config"
	"tgwebproxy/internal/dc"
	"tgwebproxy/internal/hostname"
	"tgwebproxy/internal/httpfront"
	"tgwebproxy/internal/metrics"
	"tgwebproxy/internal/relay"
	"tgwebproxy/internal/secret"
	"tgwebproxy/internal/share"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath  = flag.String("config", env("TGWP_CONFIG", ""), "TOML configuration file; enables several secrets and SIGHUP reload")
		domain      = flag.String("domain", env("TGWP_DOMAIN", ""), "domain this relay answers on (required without -config)")
		secretText  = flag.String("secret", env("TGWP_SECRET", ""), "MTProxy secret, hex or base64url; generated when empty")
		siteDir     = flag.String("site", env("TGWP_SITE", ""), "directory with the cover site; a built-in page is used when empty")
		certDir     = flag.String("cert-dir", env("TGWP_CERT_DIR", "certs"), "directory for ACME certificates")
		listen      = flag.String("listen", env("TGWP_LISTEN", ":443"), "TLS listen address")
		plainListen = flag.String("plain-listen", env("TGWP_PLAIN_LISTEN", ":80"), "plain HTTP listen address; empty disables it")
		maxStreams  = flag.Int("max-streams", 64, "concurrent MTProto streams per session")
		diagnose    = flag.Bool("diagnose", envBool("TGWP_DIAGNOSE"), "log one line per request; never logs the capability itself")
		behindProxy = flag.Bool("behind-proxy", envBool("TGWP_BEHIND_PROXY"), "serve plain HTTP for a reverse proxy that terminates TLS")
		logLevel    = flag.String("log-level", env("TGWP_LOG_LEVEL", "info"), "debug, info, warn or error")
	)
	flag.Parse()

	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	cfg, err := resolveConfig(*configPath, flagValues{
		explicit:    explicit,
		domain:      *domain,
		secretText:  *secretText,
		siteDir:     *siteDir,
		certDir:     *certDir,
		listen:      *listen,
		plainListen: *plainListen,
		maxStreams:  *maxStreams,
		diagnose:    *diagnose,
		behindProxy: *behindProxy,
		logLevel:    *logLevel,
	})
	if err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))

	domains, err := buildDomains(cfg)
	if err != nil {
		return err
	}
	registry := metrics.New()
	handler, err := httpfront.New(httpfront.Config{
		Domains:     domains,
		Logger:      log,
		Metrics:     registry,
		BehindProxy: cfg.BehindProxy,
		Diagnose:    cfg.Diagnose,
		Relay: relay.Options{
			MaxStreams:   cfg.MaxStreams,
			PingInterval: 30 * time.Second,
			IdleTimeout:  90 * time.Second,
			DialTimeout:  10 * time.Second,
		},
	})
	if err != nil {
		return err
	}

	printConnectionDetails(cfg)

	serverCfg := httpfront.ServerConfig{
		Listen:      cfg.Listen,
		CertDir:     cfg.CertDir,
		PlainListen: cfg.PlainListen,
	}
	if cfg.BehindProxy {
		serverCfg.Plaintext = true
		serverCfg.PlainListen = ""
	}
	server := httpfront.NewServer(handler, serverCfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.AdminListen != "" {
		adminServer, err := admin.New(cfg.AdminListen, registry, reachTelegram)
		if err != nil {
			return err
		}
		go func() {
			if err := adminServer.Run(ctx); err != nil {
				log.Error("admin listener failed", "error", err)
			}
		}()
		log.Info("admin listening", "address", cfg.AdminListen)
	}

	selfCheck(ctx, cfg, log)

	if *configPath != "" {
		go watchReloads(ctx, *configPath, cfg, handler, log)
	}

	log.Info("relay listening",
		"address", serverCfg.Listen,
		"domains", cfg.DomainNames(),
		"behind_proxy", cfg.BehindProxy)
	return server.Run(ctx)
}

func buildDomains(cfg *config.Config) ([]httpfront.Domain, error) {
	out := make([]httpfront.Domain, 0, len(cfg.Domains))
	for _, d := range cfg.Domains {
		keyring, err := secret.NewKeyring(d.Name, d.Entries)
		if err != nil {
			return nil, err
		}
		out = append(out, httpfront.Domain{Name: d.Name, Keyring: keyring, SiteDir: d.Site})
	}
	return out, nil
}

// reachTelegram opens and drops a TCP connection to a data centre. It answers
// the one question a health check cannot answer from inside the process: can
// this host talk to Telegram at all.
func reachTelegram(ctx context.Context) error {
	target, err := dc.Resolve(2)
	if err != nil {
		return err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", target.Address)
	if err != nil {
		return err
	}
	return conn.Close()
}

// selfCheck turns "deployed it and it silently does nothing" into a log line
// naming the broken part. Nothing here prevents start-up: a relay that refused
// to run because a data centre was briefly unreachable would be worse.
func selfCheck(ctx context.Context, cfg *config.Config, log *slog.Logger) {
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := reachTelegram(checkCtx); err != nil {
		log.Warn("cannot reach a Telegram data centre from this host", "error", err)
	}
	if cfg.BehindProxy && !loopbackListen(cfg.Listen) {
		log.Warn("behind_proxy is set but the relay listens beyond the loopback, "+
			"which exposes it without TLS", "listen", cfg.Listen)
	}
	if !cfg.BehindProxy {
		if err := os.MkdirAll(cfg.CertDir, 0o700); err != nil {
			log.Warn("the certificate cache is not writable; every restart will "+
				"ask Let's Encrypt for a fresh certificate", "dir", cfg.CertDir, "error", err)
		}
	}
	for _, domain := range cfg.Domains {
		if domain.Site == "" {
			log.Warn("serving the built-in cover page, which is a placeholder: "+
				"point site at something you would plausibly host", "domain", domain.Name)
		}
	}
}

func loopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type flagValues struct {
	explicit    map[string]bool
	domain      string
	secretText  string
	siteDir     string
	certDir     string
	listen      string
	plainListen string
	maxStreams  int
	diagnose    bool
	behindProxy bool
	logLevel    string
}

// explicitlySet lists the flags the operator passed that the file would
// override. Silently ignoring them is how someone spends an afternoon
// wondering why -listen had no effect.
func (f flagValues) explicitlySet() []string {
	var out []string
	for _, name := range []string{
		"site", "cert-dir", "listen", "plain-listen",
		"max-streams", "diagnose", "behind-proxy", "log-level",
	} {
		if f.explicit[name] {
			out = append(out, "-"+name)
		}
	}
	return out
}

// resolveConfig produces one snapshot from either the file or the flags. The
// two are never merged: a half-configured relay is worse than a refusal.
func resolveConfig(path string, flags flagValues) (*config.Config, error) {
	if path != "" {
		if flags.domain != "" || flags.secretText != "" {
			return nil, fmt.Errorf("-config cannot be combined with -domain or -secret")
		}
		if ignored := flags.explicitlySet(); len(ignored) > 0 {
			return nil, fmt.Errorf("-config takes precedence, so %s would be ignored; "+
				"move the setting into the file", strings.Join(ignored, ", "))
		}
		return config.Load(path)
	}

	if flags.domain == "" {
		return nil, fmt.Errorf("-domain is required (or pass -config)")
	}
	// The client hashes its normalised spelling of the domain, so the relay
	// must hash the same spelling or the capability never matches.
	normalized, err := hostname.Normalize(flags.domain)
	if err != nil {
		return nil, fmt.Errorf("domain %q: %w", flags.domain, err)
	}

	var sec secret.Secret
	if flags.secretText == "" {
		if sec, err = secret.Generate(); err != nil {
			return nil, err
		}
	} else if sec, err = secret.Parse(flags.secretText); err != nil {
		return nil, err
	}

	level := slog.LevelInfo
	if err := level.UnmarshalText([]byte(strings.ToLower(flags.logLevel))); err != nil {
		return nil, fmt.Errorf("bad log level %q", flags.logLevel)
	}

	listen := flags.listen
	if flags.behindProxy && listen == ":443" {
		// Behind a front end, listening on every interface would expose the
		// relay without TLS. Keep it on the loopback by default.
		listen = "127.0.0.1:4600"
	}

	return &config.Config{
		Domains: []config.Domain{{
			Name:    normalized,
			Site:    flags.siteDir,
			Entries: []secret.Entry{{Secret: sec, Label: "default"}},
		}},
		Listen:      listen,
		PlainListen: flags.plainListen,
		CertDir:     flags.certDir,
		BehindProxy: flags.behindProxy,
		Diagnose:    flags.diagnose,
		LogLevel:    level,
		MaxStreams:  flags.maxStreams,
	}, nil
}

// watchReloads applies SIGHUP. A rejected reload keeps the running
// configuration: reloading must never be a way to take the relay down.
func watchReloads(ctx context.Context, path string, current *config.Config, handler *httpfront.Handler, log *slog.Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			next, err := config.Load(path)
			if err != nil {
				log.Error("reload refused: the file did not parse", "error", err)
				continue
			}
			if err := current.CheckStaticMatch(next); err != nil {
				log.Error("reload refused", "error", err)
				continue
			}
			domains, err := buildDomains(next)
			if err != nil {
				log.Error("reload refused", "error", err)
				continue
			}
			if err := handler.Reload(httpfront.Live{
				Domains:    domains,
				MaxStreams: next.MaxStreams,
			}); err != nil {
				log.Error("reload refused", "error", err)
				continue
			}
			current = next
		}
	}
}

func printConnectionDetails(cfg *config.Config) {
	fmt.Println()
	fmt.Println("  Telegram Desktop -> Settings -> Advanced -> Connection type -> Add proxy -> WEB")
	for _, domain := range cfg.Domains {
		fmt.Println()
		fmt.Printf("    Web proxy hostname : %s\n", domain.Name)
		for _, entry := range domain.Entries {
			fmt.Printf("    Secret (%s) : %s\n", entry.Label, entry.Secret.Hex())
			fmt.Printf("      %s\n", share.Link(domain.Name, entry.Secret))
		}
	}
	fmt.Println()
	fmt.Println("  The link configures the client in one step. t.me does not route")
	fmt.Println("  this path yet, so it may need to be opened inside Telegram.")
	fmt.Println()
}

func envBool(name string) bool {
	switch strings.ToLower(os.Getenv(name)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func env(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok && value != "" {
		return value
	}
	return fallback
}
