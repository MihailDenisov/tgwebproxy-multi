package twin

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PollTransport drives a relay over the long-poll carrier, the way the bridge
// page does when a WebSocket does not come up. It exists so the same twin —
// and therefore the same strictness — covers both carriers.
type PollTransport struct {
	client  *http.Client
	base    string
	token   string
	timeout time.Duration

	sendMu sync.Mutex
	seq    uint64

	recvMu  sync.Mutex
	cursor  uint64
	pending [][]byte

	closeOnce sync.Once
	closed    chan struct{}
}

const (
	headerSession = "X-Tgwp-Session"
	headerSeq     = "X-Tgwp-Seq"
	headerCursor  = "X-Tgwp-Cursor"
)

var sessionPattern = regexp.MustCompile(`sessionToken = "([A-Za-z0-9_-]+)"`)

// DialPoll fetches the bridge page, takes the session token out of it, and
// returns a transport that speaks the fallback carrier.
func DialPoll(opts DialOptions) (*PollTransport, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 40 * time.Second
	}
	client := &http.Client{
		Timeout:   opts.Timeout,
		Transport: &http.Transport{TLSClientConfig: opts.TLSConfig},
	}
	base := strings.TrimSuffix(opts.BaseURL, "/") + "/"

	resp, err := client.Get(base + "?bridge=" + opts.Capability)
	if err != nil {
		return nil, fmt.Errorf("fetch the bridge page: %w", err)
	}
	defer resp.Body.Close()
	page, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	found := sessionPattern.FindSubmatch(page)
	if found == nil {
		return nil, errors.New("twin: the bridge page carries no fallback session token")
	}
	return &PollTransport{
		client:  client,
		base:    base,
		token:   string(found[1]),
		timeout: opts.Timeout,
		closed:  make(chan struct{}),
	}, nil
}

func (p *PollTransport) Send(data []byte) error {
	select {
	case <-p.closed:
		return io.ErrClosedPipe
	default:
	}

	p.sendMu.Lock()
	defer p.sendMu.Unlock()

	body := binary.BigEndian.AppendUint32(nil, uint32(len(data)))
	body = append(body, data...)

	request, err := http.NewRequest(http.MethodPost, p.base, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set(headerSession, p.token)
	request.Header.Set(headerSeq, strconv.FormatUint(p.seq, 10))
	request.Header.Set("Content-Type", "application/octet-stream")

	resp, err := p.client.Do(request)
	if err != nil {
		return p.afterClose(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return p.afterClose(fmt.Errorf("twin: uplink answered %s", resp.Status))
	}
	p.seq++
	return nil
}

func (p *PollTransport) Receive() ([]byte, error) {
	p.recvMu.Lock()
	defer p.recvMu.Unlock()

	for {
		if len(p.pending) > 0 {
			next := p.pending[0]
			p.pending = p.pending[1:]
			return next, nil
		}
		select {
		case <-p.closed:
			return nil, io.EOF
		default:
		}

		request, err := http.NewRequest(http.MethodGet, p.base, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set(headerSession, p.token)
		request.Header.Set(headerCursor, strconv.FormatUint(p.cursor, 10))

		resp, err := p.client.Do(request)
		if err != nil {
			return nil, p.afterClose(err)
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, p.afterClose(readErr)
		}

		switch resp.StatusCode {
		case http.StatusNoContent:
			continue
		case http.StatusOK:
			p.cursor++
			messages, err := splitBatch(body)
			if err != nil {
				return nil, err
			}
			p.pending = append(p.pending, messages...)
		default:
			return nil, p.afterClose(fmt.Errorf("twin: downlink answered %s", resp.Status))
		}
	}
}

// afterClose reports a request that lost its race with Close as an ordinary
// end of transport. Closing removes the session, so whatever the relay says to
// a request already in flight is teardown noise, not a protocol complaint.
func (p *PollTransport) afterClose(err error) error {
	select {
	case <-p.closed:
		return io.EOF
	default:
		return err
	}
}

func (p *PollTransport) Close() error {
	p.closeOnce.Do(func() {
		close(p.closed)
		request, err := http.NewRequest(http.MethodDelete, p.base, nil)
		if err != nil {
			return
		}
		request.Header.Set(headerSession, p.token)
		if resp, err := p.client.Do(request); err == nil {
			resp.Body.Close()
		}
	})
	return nil
}

func splitBatch(body []byte) ([][]byte, error) {
	var out [][]byte
	for len(body) > 0 {
		if len(body) < 4 {
			return nil, errors.New("twin: truncated batch header")
		}
		size := binary.BigEndian.Uint32(body)
		body = body[4:]
		if uint64(size) > uint64(len(body)) {
			return nil, errors.New("twin: truncated batch message")
		}
		message := make([]byte, size)
		copy(message, body[:size])
		out = append(out, message)
		body = body[size:]
	}
	return out, nil
}
