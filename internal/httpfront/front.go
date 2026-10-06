// Package httpfront is the public face of the relay. A visitor without the
// capability must not be able to tell this domain from an ordinary site: every
// request goes through the same constant-time check, and a failed check yields
// the cover site with the same status, headers and bytes. Bridge and WebSocket
// both live on "/", so there is no second path to discover.
package httpfront

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"tgwebproxy/internal/longpoll"
	"tgwebproxy/internal/metrics"
	"tgwebproxy/internal/relay"
	"tgwebproxy/internal/secret"
	"tgwebproxy/internal/webassets"
)

type Config struct {
	// Domains lists every name this relay answers on. Capabilities are bound
	// to a name, so each domain carries its own keyring and cover site.
	Domains []Domain
	Logger  *slog.Logger
	Relay   relay.Options
	// BehindProxy marks that a trusted front end terminates TLS. Only then is
	// X-Forwarded-For trustworthy; exposed directly, any client could forge it.
	BehindProxy bool
	// Diagnose logs one line per request (never the capability itself). Off by
	// default: a relay that keeps request logs can betray its users.
	Diagnose bool
	// Metrics receives counts, labelled by domain and by the secret's label.
	// Nil means no accounting.
	Metrics *metrics.Registry
	// PollHold is how long a long-poll downlink request waits before it
	// answers empty. Zero uses the package default.
	PollHold time.Duration
}

// Domain is one served name.
type Domain struct {
	Name    string
	Keyring *secret.Keyring
	SiteDir string
}

// Handler serves the cover site, the bridge page, and the relay socket.
type Handler struct {
	log         *slog.Logger
	metrics     *metrics.Registry
	relay       relay.Options
	behindProxy bool
	diagnose    bool
	upgrader    websocket.Upgrader
	sessions    *sessionRegistry
	polls       *longpoll.Manager
	pollHold    time.Duration
	pollCtx     context.Context
	// live is swapped whole on reload, so a request either sees the old
	// snapshot or the new one and never a mixture.
	live atomic.Pointer[liveState]
}

// Live is the part of the configuration that may change while the relay runs.
// The set of names is not in it: it is fixed by the ACME host policy and by
// the capabilities already handed out.
type Live struct {
	Domains    []Domain
	MaxStreams int
}

type domainState struct {
	name    string
	keyring *secret.Keyring
	cover   http.Handler
}

type liveState struct {
	byHost map[string]*domainState
	// fallback answers a request for a name we do not serve. It is the first
	// configured domain's cover site: an unknown Host must still look like an
	// ordinary web server, not like something that knows it is being probed.
	fallback   *domainState
	maxStreams int
}

func New(cfg Config) (*Handler, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	state, err := buildState(cfg.Domains, cfg.Relay.MaxStreams)
	if err != nil {
		return nil, err
	}

	h := &Handler{
		log:         cfg.Logger,
		metrics:     cfg.Metrics,
		relay:       cfg.Relay,
		behindProxy: cfg.BehindProxy,
		diagnose:    cfg.Diagnose,
		sessions:    newSessionRegistry(),
		polls:       longpoll.NewManager(),
		pollHold:    cfg.PollHold,
		pollCtx:     context.Background(),
	}
	h.live.Store(state)
	h.upgrader = websocket.Upgrader{
		HandshakeTimeout: 15 * time.Second,
		ReadBufferSize:   32 * 1024,
		WriteBufferSize:  32 * 1024,
		CheckOrigin:      h.checkOrigin,
	}
	return h, nil
}

// Reload installs a new snapshot. Everything is validated before the running
// state is touched, so a bad configuration leaves the relay as it was.
func (h *Handler) Reload(next Live) error {
	current := h.live.Load()
	maxStreams := next.MaxStreams
	if maxStreams <= 0 {
		maxStreams = current.maxStreams
	}
	state, err := buildState(next.Domains, maxStreams)
	if err != nil {
		return err
	}
	if len(state.byHost) != len(current.byHost) {
		return errors.New("httpfront: reload cannot add or remove a domain")
	}
	for host := range state.byHost {
		if _, served := current.byHost[host]; !served {
			return fmt.Errorf("httpfront: reload cannot introduce the domain %q", host)
		}
	}

	h.live.Store(state)
	if dropped := h.sessions.revokeMissing(state); len(dropped) > 0 {
		h.log.Info("secrets revoked, sessions closed", "labels", dropped)
	}
	h.log.Info("configuration reloaded", "domains", len(state.byHost))
	return nil
}

// Domains lists the served names, in configuration order.
// Run drives the parts of the handler that outlive one request: the
// long-poll session reaper. It returns when the context is cancelled.
func (h *Handler) Run(ctx context.Context) {
	h.pollCtx = ctx
	h.polls.Run(ctx)
}

func (h *Handler) Domains() []string {
	state := h.live.Load()
	names := make([]string, 0, len(state.byHost))
	for _, d := range state.order() {
		names = append(names, d.name)
	}
	return names
}

func (s *liveState) order() []*domainState {
	out := make([]*domainState, 0, len(s.byHost))
	if s.fallback != nil {
		out = append(out, s.fallback)
	}
	for _, d := range s.byHost {
		if d != s.fallback {
			out = append(out, d)
		}
	}
	return out
}

func buildState(domains []Domain, maxStreams int) (*liveState, error) {
	if len(domains) == 0 {
		return nil, errors.New("httpfront: at least one domain is required")
	}
	state := &liveState{
		byHost:     make(map[string]*domainState, len(domains)),
		maxStreams: maxStreams,
	}
	for _, d := range domains {
		if d.Name == "" {
			return nil, errors.New("httpfront: a domain needs a name")
		}
		if d.Keyring == nil || d.Keyring.Len() == 0 {
			return nil, fmt.Errorf("httpfront: domain %q has no secrets", d.Name)
		}
		if d.Keyring.Host() != d.Name {
			return nil, fmt.Errorf("httpfront: the keyring for %q was built for %q",
				d.Name, d.Keyring.Host())
		}
		if _, clash := state.byHost[d.Name]; clash {
			return nil, fmt.Errorf("httpfront: domain %q appears twice", d.Name)
		}
		cover, err := coverHandler(d.SiteDir)
		if err != nil {
			return nil, fmt.Errorf("httpfront: domain %q: %w", d.Name, err)
		}
		entry := &domainState{name: d.Name, keyring: d.Keyring, cover: cover}
		state.byHost[d.Name] = entry
		if state.fallback == nil {
			state.fallback = entry
		}
	}
	return state, nil
}

func coverHandler(siteDir string) (http.Handler, error) {
	if siteDir == "" {
		return http.HandlerFunc(builtinCover), nil
	}
	info, err := os.Stat(siteDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("site path is not a directory")
	}
	if _, err := os.Stat(filepath.Join(siteDir, "index.html")); err != nil {
		return nil, errors.New("site directory has no index.html")
	}
	return http.FileServer(http.Dir(siteDir)), nil
}

func builtinCover(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(webassets.CoverPage())
}

// checkOrigin accepts every origin, deliberately. Telegram's own reference
// relay dropped its origin check for the same reason (tproxy-server commit
// "Remove origin checks"): a native WebView may omit the header entirely, so
// requiring it locks out the very client this exists for. Nothing is lost —
// a non-browser peer can forge any origin, and the capability in the query is
// what actually authenticates the upgrade.
func (h *Handler) checkOrigin(*http.Request) bool {
	return true
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	state := h.live.Load()
	domain, served := state.lookup(r.Host)
	entry, authorized := secret.Entry{}, false
	if served {
		entry, authorized = h.match(domain, r)
	}
	upgrade := websocket.IsWebSocketUpgrade(r)

	if h.diagnose {
		label := ""
		if authorized {
			label = entry.Label
		}
		h.log.Info("request",
			"peer", h.peerLabel(r),
			"domain", domain.name,
			"authorized", authorized,
			"label", label,
			"upgrade", upgrade,
			"method", r.Method,
			"path", r.URL.Path,
			"has_bridge_param", r.URL.Query().Has("bridge"),
			"agent", shortAgent(r.UserAgent()))
	}

	if served && h.servePoll(w, r, state, domain, entry) {
		return
	}

	if !authorized {
		h.count("tgwp_gate_rejections_total", 1, "domain", domain.name)
	}

	if upgrade {
		if !authorized {
			// Answer an unauthorised upgrade the way a site with no
			// WebSocket endpoint would: with the page itself.
			domain.cover.ServeHTTP(w, r)
			return
		}
		h.serveRelay(w, r, state, domain, entry)
		return
	}
	if authorized {
		h.serveBridge(w, r, state, domain, entry)
		return
	}
	domain.cover.ServeHTTP(w, r)
}

// lookup resolves the request's Host. An unserved name still gets a cover
// site — an error saying "wrong host" would answer the prober's question — but
// the second result is false and no capability is honoured for it.
//
// With a single domain there is nothing to route, so any Host resolves to it.
// That keeps the relay working behind a front end that rewrites the header,
// which is a common and otherwise silent misconfiguration; with several
// domains the header is the only thing telling them apart, so it must match.
func (s *liveState) lookup(host string) (*domainState, bool) {
	if len(s.byHost) == 1 {
		return s.fallback, true
	}
	name := host
	if colon := strings.LastIndex(name, ":"); colon > 0 && !strings.Contains(name[colon:], "]") {
		name = name[:colon]
	}
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if domain, ok := s.byHost[name]; ok {
		return domain, true
	}
	return s.fallback, false
}

// match runs the capability check for every request, authorised or not, so
// the work done before the response is identical either way.
func (h *Handler) match(domain *domainState, r *http.Request) (secret.Entry, bool) {
	if r.Method != http.MethodGet || r.URL.Path != "/" {
		return secret.Entry{}, false
	}
	entry, ok := domain.keyring.Match(r.URL.Query().Get("bridge"))
	if !ok || h.quotaExceeded(domain.name, entry) {
		return secret.Entry{}, false
	}
	return entry, true
}

func (h *Handler) quotaExceeded(domain string, entry secret.Entry) bool {
	if entry.QuotaBytes <= 0 || h.metrics == nil {
		return false
	}
	labels := []string{"domain", domain, "label", entry.Label}
	used := h.metrics.Value("tgwp_bytes_up_total", labels...) +
		h.metrics.Value("tgwp_bytes_down_total", labels...)
	return used >= entry.QuotaBytes
}

func (h *Handler) serveBridge(w http.ResponseWriter, r *http.Request, state *liveState, domain *domainState, entry secret.Entry) {
	// The page carries a session token for the long-poll carrier, which it
	// uses only if its WebSocket does not come up.
	token, err := h.startPollSession(state, domain, entry, h.peerLabel(r))
	if err != nil {
		h.log.Error("cannot start a fallback session", "error", err)
		domain.cover.ServeHTTP(w, r)
		return
	}
	page, nonce, err := webassets.Bridge(token)
	if err != nil {
		h.log.Error("cannot render the bridge page", "error", err)
		domain.cover.ServeHTTP(w, r)
		return
	}
	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Security-Policy", strings.Join([]string{
		"default-src 'none'",
		"script-src 'nonce-" + nonce + "'",
		"style-src 'unsafe-inline'",
		// wss for the socket, https for the long-poll fallback.
		"connect-src wss://" + domain.name + " https://" + domain.name,
		"base-uri 'none'",
		"form-action 'none'",
	}, "; "))
	w.Write(page)
}

func (h *Handler) serveRelay(w http.ResponseWriter, r *http.Request, state *liveState, domain *domainState, entry secret.Entry) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Debug("upgrade failed", "error", err)
		return
	}
	// One Data frame plus its header is the largest legitimate message.
	conn.SetReadLimit(2 * 1024 * 1024)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	// Closing the socket is not optional: the session's reader blocks in
	// ReadMessage, and cancelling the context alone would never wake it.
	stopSession := func() {
		cancel()
		_ = conn.Close()
	}
	id := h.sessions.add(domain.name, entry, stopSession)
	defer h.sessions.remove(id)

	h.count("tgwp_sessions_started_total", 1, "domain", domain.name, "label", entry.Label)
	h.count("tgwp_sessions_active", 1, "domain", domain.name, "label", entry.Label)
	defer h.count("tgwp_sessions_active", -1, "domain", domain.name, "label", entry.Label)

	opts := h.relay
	opts.Secret = entry.Secret
	opts.MaxStreams = state.maxStreams
	opts.Metrics = &reporter{
		registry: h.metrics, domain: domain.name, label: entry.Label,
		quotaBytes: entry.QuotaBytes, expiresUnix: entry.ExpiresUnix, stop: stopSession,
	}
	opts.Logger = h.log.With("peer", h.peerLabel(r), "domain", domain.name, "label", entry.Label)

	if err := relay.Serve(ctx, &wsConn{conn: conn}, opts); err != nil {
		if errors.Is(err, relay.ErrProtocol) {
			h.log.Warn("session dropped", "reason", err, "label", entry.Label)
		} else {
			h.log.Debug("session ended", "reason", err, "label", entry.Label)
		}
	}
}

// peerLabel identifies a session in logs without recording a full address.
// Behind a front end the socket address is always the front end, so the first
// X-Forwarded-For hop is used instead.
func (h *Handler) peerLabel(r *http.Request) string {
	if h.behindProxy {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			first := forwarded
			if idx := strings.Index(first, ","); idx >= 0 {
				first = first[:idx]
			}
			if first = strings.TrimSpace(first); first != "" {
				return first
			}
		}
	}
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	return host
}

// The user agent tells "no WebView at all" from "a WebView that failed later".
func shortAgent(agent string) string {
	const limit = 96
	if len(agent) > limit {
		return agent[:limit]
	}
	return agent
}

// wsConn adapts a gorilla WebSocket to relay.MessageConn. The relay reads from
// one goroutine and writes from one other, as gorilla requires.
type wsConn struct {
	conn *websocket.Conn
}

func (c *wsConn) ReadMessage() ([]byte, error) {
	kind, data, err := c.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	if kind != websocket.BinaryMessage {
		// A text message means the peer is not our bridge page.
		return nil, errors.New("httpfront: non-binary transport message")
	}
	return data, nil
}

func (c *wsConn) WriteMessage(data []byte) error {
	return c.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (c *wsConn) Close() error { return c.conn.Close() }

var _ relay.MessageConn = (*wsConn)(nil)

func (h *Handler) count(name string, delta int64, labels ...string) {
	if h.metrics != nil {
		h.metrics.Add(name, delta, labels...)
	}
}

// reporter binds the relay's counts to one session's domain and label.
type reporter struct {
	registry    *metrics.Registry
	domain      string
	label       string
	quotaBytes  int64
	expiresUnix int64
	stop        func()
	quotaOnce   sync.Once
}

func (r *reporter) add(name string, delta int64) {
	if r.registry != nil {
		r.registry.Add(name, delta, "domain", r.domain, "label", r.label)
	}
}

func (r *reporter) StreamOpened() {
	r.add("tgwp_streams_opened_total", 1)
	r.add("tgwp_streams_active", 1)
}
func (r *reporter) StreamClosed() { r.add("tgwp_streams_active", -1) }

// MessageWritten counts what batching would save: every message that was
// already waiting when another was written could have travelled with it.
func (r *reporter) MessageWritten(alsoQueued int) {
	r.add("tgwp_transport_messages_total", 1)
	if alsoQueued > 0 {
		r.add("tgwp_coalescable_messages_total", int64(alsoQueued))
	}
}
func (r *reporter) UpstreamDialFailed() { r.add("tgwp_upstream_dial_failures_total", 1) }
func (r *reporter) ProtocolError()      { r.add("tgwp_protocol_errors_total", 1) }
func (r *reporter) BytesUp(n int) {
	r.add("tgwp_bytes_up_total", int64(n))
	r.enforceQuota()
}
func (r *reporter) BytesDown(n int) {
	r.add("tgwp_bytes_down_total", int64(n))
	r.enforceQuota()
}

func (r *reporter) enforceQuota() {
	if r.stop == nil {
		return
	}
	if r.expiresUnix > 0 && time.Now().Unix() >= r.expiresUnix {
		r.quotaOnce.Do(r.stop)
		return
	}
	if r.registry == nil || r.quotaBytes <= 0 {
		return
	}
	labels := []string{"domain", r.domain, "label", r.label}
	used := r.registry.Value("tgwp_bytes_up_total", labels...) +
		r.registry.Value("tgwp_bytes_down_total", labels...)
	if used >= r.quotaBytes {
		r.quotaOnce.Do(r.stop)
	}
}
