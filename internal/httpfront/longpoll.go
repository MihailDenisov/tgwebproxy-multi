package httpfront

import (
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strconv"

	"tgwebproxy/internal/longpoll"
	"tgwebproxy/internal/relay"
	"tgwebproxy/internal/secret"
)

// The long-poll carrier rides on the same URL as everything else. A request
// is one of ours only if it carries a session token the relay itself issued,
// and every reply to a request without one is the cover site, so the extra
// verbs add no path to discover.
const (
	headerSession = "X-Tgwp-Session"
	headerSeq     = "X-Tgwp-Seq"
	headerCursor  = "X-Tgwp-Cursor"
)

// maxUplinkBody caps one uplink batch. Two MiB is one maximum frame plus its
// header, with room for the batch around it.
const maxUplinkBody = 2 * 1024 * 1024

// servePoll handles the long-poll carrier. It reports whether the request
// belonged to it; anything else falls through to the ordinary paths.
func (h *Handler) servePoll(w http.ResponseWriter, r *http.Request, state *liveState, domain *domainState, entry secret.Entry) bool {
	token := r.Header.Get(headerSession)
	if token == "" {
		return false
	}
	session, err := h.polls.Get(token)
	if err != nil {
		// An unknown token is answered like any other unauthorised request.
		domain.cover.ServeHTTP(w, r)
		return true
	}

	switch r.Method {
	case http.MethodPost:
		h.pollUplink(w, r, session)
	case http.MethodGet:
		h.pollDownlink(w, r, session)
	case http.MethodDelete:
		h.polls.Remove(token)
		w.WriteHeader(http.StatusNoContent)
	default:
		domain.cover.ServeHTTP(w, r)
	}
	return true
}

func (h *Handler) pollUplink(w http.ResponseWriter, r *http.Request, session *longpoll.Session) {
	seq, err := strconv.ParseUint(r.Header.Get(headerSeq), 10, 64)
	if err != nil {
		http.Error(w, "bad sequence", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxUplinkBody+1))
	if err != nil {
		http.Error(w, "unreadable", http.StatusBadRequest)
		return
	}
	if len(body) > maxUplinkBody {
		http.Error(w, "too large", http.StatusRequestEntityTooLarge)
		return
	}
	messages, err := splitBatch(body)
	if err != nil {
		http.Error(w, "malformed batch", http.StatusBadRequest)
		return
	}
	switch err := session.Deliver(seq, messages); {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, longpoll.ErrSequence):
		// The page has lost track. It must start a new session rather than
		// guess, because a gap here would corrupt an MTProto stream.
		http.Error(w, "out of sequence", http.StatusConflict)
	default:
		http.Error(w, "closed", http.StatusGone)
	}
}

func (h *Handler) pollDownlink(w http.ResponseWriter, r *http.Request, session *longpoll.Session) {
	cursor, err := strconv.ParseUint(r.Header.Get(headerCursor), 10, 64)
	if err != nil {
		http.Error(w, "bad cursor", http.StatusBadRequest)
		return
	}
	hold := h.pollHold
	if hold <= 0 {
		hold = longpoll.PollHold
	}
	batch, err := session.Collect(cursor, hold)
	switch {
	case errors.Is(err, longpoll.ErrSequence):
		http.Error(w, "out of sequence", http.StatusConflict)
		return
	case err != nil:
		http.Error(w, "closed", http.StatusGone)
		return
	}
	if len(batch) == 0 {
		// Nothing happened while the request was held. The cursor stays put
		// and the page asks again.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(joinBatch(batch))
}

// A batch is length-prefixed messages, so one HTTP body can carry several
// transport messages without the page having to understand frames.
func splitBatch(body []byte) ([][]byte, error) {
	var out [][]byte
	for len(body) > 0 {
		if len(body) < 4 {
			return nil, errors.New("httpfront: truncated batch header")
		}
		size := binary.BigEndian.Uint32(body)
		body = body[4:]
		if uint64(size) > uint64(len(body)) {
			return nil, errors.New("httpfront: truncated batch message")
		}
		message := make([]byte, size)
		copy(message, body[:size])
		out = append(out, message)
		body = body[size:]
	}
	return out, nil
}

func joinBatch(messages [][]byte) []byte {
	total := 0
	for _, m := range messages {
		total += 4 + len(m)
	}
	out := make([]byte, 0, total)
	for _, m := range messages {
		out = binary.BigEndian.AppendUint32(out, uint32(len(m)))
		out = append(out, m...)
	}
	return out
}

// startPollSession mints a session for a bridge page and runs the relay over
// it. The page picks the carrier up with the token embedded in the page.
func (h *Handler) startPollSession(state *liveState, domain *domainState, entry secret.Entry, peer string) (string, error) {
	session, err := h.polls.Create()
	if err != nil {
		return "", err
	}

	stopSession := func() {
		h.polls.Remove(session.Token())
	}
	opts := h.relay
	opts.Secret = entry.Secret
	opts.MaxStreams = state.maxStreams
	opts.Metrics = &reporter{
		registry: h.metrics, domain: domain.name, label: entry.Label,
		quotaBytes: entry.QuotaBytes, stop: stopSession,
	}
	opts.Logger = h.log.With("peer", peer, "domain", domain.name, "label", entry.Label, "carrier", "longpoll")

	h.count("tgwp_sessions_started_total", 1, "domain", domain.name, "label", entry.Label, "carrier", "longpoll")
	h.count("tgwp_sessions_active", 1, "domain", domain.name, "label", entry.Label, "carrier", "longpoll")

	id := h.sessions.add(domain.name, entry, stopSession)

	go func() {
		defer h.sessions.remove(id)
		defer h.count("tgwp_sessions_active", -1, "domain", domain.name, "label", entry.Label, "carrier", "longpoll")
		defer h.polls.Remove(session.Token())

		if err := relay.Serve(h.pollCtx, session, opts); err != nil {
			if errors.Is(err, relay.ErrProtocol) {
				opts.Logger.Warn("session dropped", "reason", err)
			} else {
				opts.Logger.Debug("session ended", "reason", err)
			}
		}
	}()
	return session.Token(), nil
}
