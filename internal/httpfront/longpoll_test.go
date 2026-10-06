package httpfront

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"
	"time"

	"tgwebproxy/internal/frame"
)

var sessionPattern = regexp.MustCompile(`sessionToken = "([A-Za-z0-9_-]+)"`)

// pollClient drives the long-poll carrier the way the bridge page does.
type pollClient struct {
	t       *testing.T
	base    string
	token   string
	seq     uint64
	cursor  uint64
	timeout time.Duration
}

func newPollClient(t *testing.T, server *httptest.Server, host, capability string) *pollClient {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, server.URL+"/?bridge="+capability, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("fetch the bridge page: %v", err)
	}
	defer resp.Body.Close()
	page, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	found := sessionPattern.FindSubmatch(page)
	if found == nil {
		t.Fatal("the bridge page carries no session token for the fallback carrier")
	}
	return &pollClient{t: t, base: server.URL + "/", token: string(found[1]), timeout: 10 * time.Second}
}

func (c *pollClient) post(messages ...[]byte) *http.Response {
	c.t.Helper()
	var body []byte
	for _, m := range messages {
		body = binary.BigEndian.AppendUint32(body, uint32(len(m)))
		body = append(body, m...)
	}
	req, err := http.NewRequest(http.MethodPost, c.base, bytes.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set(headerSession, c.token)
	req.Header.Set(headerSeq, strconv.FormatUint(c.seq, 10))
	resp, err := (&http.Client{Timeout: c.timeout}).Do(req)
	if err != nil {
		c.t.Fatalf("uplink: %v", err)
	}
	return resp
}

func (c *pollClient) send(messages ...[]byte) {
	c.t.Helper()
	resp := c.post(messages...)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		c.t.Fatalf("uplink answered %d, want 204", resp.StatusCode)
	}
	c.seq++
}

// receive returns the next downlink batch, skipping empty holds.
func (c *pollClient) receive() [][]byte {
	c.t.Helper()
	deadline := time.Now().Add(c.timeout)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, c.base, nil)
		if err != nil {
			c.t.Fatal(err)
		}
		req.Header.Set(headerSession, c.token)
		req.Header.Set(headerCursor, strconv.FormatUint(c.cursor, 10))
		resp, err := (&http.Client{Timeout: c.timeout}).Do(req)
		if err != nil {
			c.t.Fatalf("downlink: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusNoContent:
			continue
		case http.StatusOK:
			c.cursor++
			messages, err := splitBatch(body)
			if err != nil {
				c.t.Fatalf("malformed downlink batch: %v", err)
			}
			return messages
		default:
			c.t.Fatalf("downlink answered %d", resp.StatusCode)
		}
	}
	c.t.Fatal("no downlink within the timeout")
	return nil
}

func pollBed(t *testing.T) (*httptest.Server, *pollClient) {
	t.Helper()
	h, sec := testHandler(t, func(c *Config) {
		c.Relay.Dial = refusingDialer
		c.PollHold = 200 * time.Millisecond
	})
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	return server, newPollClient(t, server, testDomain, sec.Capability(testDomain))
}

// The handshake must work over HTTP exactly as it does over a socket: the
// relay above the carrier cannot tell them apart.
func TestLongPollHandshake(t *testing.T) {
	_, client := pollBed(t)

	hello, err := frame.Marshal(frame.Hello, 0, []byte{frame.HelloVersion})
	if err != nil {
		t.Fatal(err)
	}
	client.send(hello)

	batch := client.receive()
	if len(batch) != 1 {
		t.Fatalf("welcome batch carried %d messages", len(batch))
	}
	frames, err := frame.Parse(batch[0])
	if err != nil {
		t.Fatalf("welcome: %v", err)
	}
	if len(frames) != 1 || frames[0].Type != frame.Welcome ||
		frames[0].StreamID != 0 || len(frames[0].Payload) != 0 {
		t.Fatalf("bad welcome: %+v", frames)
	}
}

// A retried POST must not deliver the same bytes twice: it would inject
// duplicate MTProto data and desynchronise the stream.
func TestLongPollUplinkReplayIsIdempotent(t *testing.T) {
	_, client := pollBed(t)
	hello, _ := frame.Marshal(frame.Hello, 0, []byte{frame.HelloVersion})

	resp := client.post(hello)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("first uplink answered %d", resp.StatusCode)
	}
	// Same sequence number again, as a retry would.
	resp = client.post(hello)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("replayed uplink answered %d, want 204", resp.StatusCode)
	}
	client.seq++

	if batch := client.receive(); len(batch) != 1 {
		t.Fatalf("expected exactly one welcome, got %d messages", len(batch))
	}
	// A second Hello would be a protocol error and close the session, so a
	// further poll must not produce another welcome.
	client.cursor = 0
	if batch := client.receive(); len(batch) != 1 {
		t.Fatalf("the replayed poll returned %d messages, want the same batch", len(batch))
	}
}

func TestLongPollRejectsBadSequence(t *testing.T) {
	_, client := pollBed(t)
	hello, _ := frame.Marshal(frame.Hello, 0, []byte{frame.HelloVersion})

	client.seq = 5
	resp := client.post(hello)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("a sequence gap answered %d, want 409", resp.StatusCode)
	}
}

// Without the session header the request is an ordinary one, and an unknown
// token must be answered like any other unauthorised request: with the site.
func TestLongPollTokenIsRequired(t *testing.T) {
	server, client := pollBed(t)

	req, _ := http.NewRequest(http.MethodPost, client.base, bytes.NewReader(nil))
	req.Header.Set(headerSession, "not-a-real-token")
	req.Header.Set(headerSeq, "0")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if bytes.Contains(body, []byte("TelegramWebProxy")) {
		t.Error("an unknown token was served the bridge")
	}
	if resp.StatusCode == http.StatusConflict || resp.StatusCode == http.StatusNoContent {
		t.Errorf("an unknown token got a carrier answer: %d", resp.StatusCode)
	}
}

func TestLongPollDeleteEndsTheSession(t *testing.T) {
	server, client := pollBed(t)
	hello, _ := frame.Marshal(frame.Hello, 0, []byte{frame.HelloVersion})
	client.send(hello)
	client.receive()

	req, _ := http.NewRequest(http.MethodDelete, client.base, nil)
	req.Header.Set(headerSession, client.token)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete answered %d", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodPost, client.base, bytes.NewReader(nil))
	req.Header.Set(headerSession, client.token)
	req.Header.Set(headerSeq, "1")
	resp, err = server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		t.Error("the session survived its own deletion")
	}
}
