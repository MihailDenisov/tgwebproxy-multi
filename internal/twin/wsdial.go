package twin

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WSTransport serialises writes: the twin writes from two goroutines, its own
// traffic and the pump's Window and Pong replies, exactly as the client does.
type WSTransport struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
}

func (w *WSTransport) Send(data []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return w.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (w *WSTransport) Receive() ([]byte, error) {
	kind, data, err := w.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	if kind != websocket.BinaryMessage {
		return nil, fmt.Errorf("twin: relay sent message type %d, want binary", kind)
	}
	return data, nil
}

func (w *WSTransport) Close() error { return w.conn.Close() }

type DialOptions struct {
	// BaseURL is the relay's https origin, e.g. "https://p.example.com".
	BaseURL string
	// Domain is the name the capability is bound to and the Origin the bridge
	// page reports; it differs from BaseURL's host only when probing a relay
	// through an address that is not its domain.
	Domain     string
	Capability string
	TLSConfig  *tls.Config
	Timeout    time.Duration
}

func FetchPage(opts DialOptions, query string) (int, []byte, error) {
	client := &http.Client{
		Timeout:   opts.Timeout,
		Transport: &http.Transport{TLSClientConfig: opts.TLSConfig},
	}
	target := strings.TrimSuffix(opts.BaseURL, "/") + "/" + query
	resp, err := client.Get(target)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, body, err
}

// DialWS opens the relay socket as the bridge page does: same Origin, same query.
func DialWS(opts DialOptions) (*WSTransport, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	endpoint := strings.TrimSuffix(opts.BaseURL, "/") + "/?bridge=" + url.QueryEscape(opts.Capability)
	switch {
	case strings.HasPrefix(endpoint, "https://"):
		endpoint = "wss://" + strings.TrimPrefix(endpoint, "https://")
	case strings.HasPrefix(endpoint, "http://"):
		endpoint = "ws://" + strings.TrimPrefix(endpoint, "http://")
	}

	dialer := websocket.Dialer{
		TLSClientConfig:  opts.TLSConfig,
		HandshakeTimeout: opts.Timeout,
	}
	header := http.Header{"Origin": {"https://" + opts.Domain}}
	conn, resp, err := dialer.Dial(endpoint, header)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("dial %s: %w (server answered %s)", endpoint, err, resp.Status)
		}
		return nil, fmt.Errorf("dial %s: %w", endpoint, err)
	}
	return &WSTransport{conn: conn}, nil
}
