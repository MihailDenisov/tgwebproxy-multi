package frame

import (
	"bytes"
	"errors"
	"testing"
)

func TestConstantsMatchClient(t *testing.T) {
	// These are the values tdesktop compiles in. If any of them drifts the
	// relay silently becomes incompatible, so pin them explicitly.
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"kFrameHeaderSize", HeaderSize, 8},
		{"kMaxFramePayload", MaxPayload, 1024 * 1024},
		{"kMaxBatchFrames", MaxBatch, 4096},
		{"kInitialStreamWindow", InitialWindow, 4 * 1024 * 1024},
		{"kDataFrameSize", DataChunk, 64 * 1024},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestAppendLayout(t *testing.T) {
	got, err := Marshal(Data, 0x123456, []byte("abc"))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := []byte{
		0x02,             // type
		0x12, 0x34, 0x56, // stream id, big-endian
		0x00, 0x00, 0x00, 0x03, // length, big-endian
		'a', 'b', 'c',
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got % x, want % x", got, want)
	}
}

func TestHelloAndWelcomeShape(t *testing.T) {
	// The client sends Hello with exactly one version byte and requires
	// Welcome to carry an empty payload.
	hello, err := Marshal(Hello, 0, []byte{HelloVersion})
	if err != nil {
		t.Fatalf("Marshal hello: %v", err)
	}
	frames, err := Parse(hello)
	if err != nil {
		t.Fatalf("Parse hello: %v", err)
	}
	if len(frames) != 1 || frames[0].Type != Hello || frames[0].StreamID != 0 {
		t.Fatalf("unexpected hello frames: %+v", frames)
	}
	if len(frames[0].Payload) != 1 || frames[0].Payload[0] != 0x01 {
		t.Fatalf("unexpected hello payload: % x", frames[0].Payload)
	}

	welcome, err := Marshal(Welcome, 0, nil)
	if err != nil {
		t.Fatalf("Marshal welcome: %v", err)
	}
	if len(welcome) != HeaderSize {
		t.Fatalf("welcome must be a bare header, got %d bytes", len(welcome))
	}
}

func TestParseMultiple(t *testing.T) {
	var buf []byte
	var err error
	if buf, err = Append(buf, Open, 1, nil); err != nil {
		t.Fatal(err)
	}
	if buf, err = Append(buf, Data, 1, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if buf, err = Append(buf, Close, 1, nil); err != nil {
		t.Fatal(err)
	}
	frames, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("got %d frames, want 3", len(frames))
	}
	if frames[1].Type != Data || string(frames[1].Payload) != "hello" {
		t.Fatalf("unexpected middle frame: %+v", frames[1])
	}
}

func TestParseRejects(t *testing.T) {
	full, err := Marshal(Data, 7, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"truncated header", full[:4], ErrShort},
		{"truncated payload", full[:len(full)-1], ErrShort},
		{"trailing garbage", append(append([]byte{}, full...), 0x02, 0x00), ErrShort},
		{"unknown type", []byte{0x77, 0, 0, 1, 0, 0, 0, 0}, ErrUnknownType},
		{"oversized payload", []byte{0x02, 0, 0, 1, 0x00, 0x20, 0x00, 0x01}, ErrPayloadTooBig},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse(c.in); !errors.Is(err, c.want) {
				t.Fatalf("Parse error = %v, want %v", err, c.want)
			}
		})
	}
}

func TestParseBatchBoundary(t *testing.T) {
	build := func(n int) []byte {
		var buf []byte
		for i := 0; i < n; i++ {
			var err error
			if buf, err = Append(buf, Ping, 0, nil); err != nil {
				t.Fatal(err)
			}
		}
		return buf
	}
	if frames, err := Parse(build(MaxBatch)); err != nil || len(frames) != MaxBatch {
		t.Fatalf("exactly MaxBatch must parse: n=%d err=%v", len(frames), err)
	}
	if _, err := Parse(build(MaxBatch + 1)); !errors.Is(err, ErrBatchTooBig) {
		t.Fatalf("MaxBatch+1 error = %v, want %v", err, ErrBatchTooBig)
	}
}

func TestPayloadBoundary(t *testing.T) {
	if _, err := Marshal(Data, 1, make([]byte, MaxPayload)); err != nil {
		t.Fatalf("exactly MaxPayload must encode: %v", err)
	}
	if _, err := Marshal(Data, 1, make([]byte, MaxPayload+1)); !errors.Is(err, ErrPayloadTooBig) {
		t.Fatalf("MaxPayload+1 error = %v, want %v", err, ErrPayloadTooBig)
	}
	if _, err := Marshal(Data, MaxStreamID+1, nil); !errors.Is(err, ErrStreamIDTooBig) {
		t.Fatalf("oversized stream id error = %v, want %v", err, ErrStreamIDTooBig)
	}
}

func TestWindowPayloadRoundTrip(t *testing.T) {
	amount, ok := ReadWindow(WindowPayload(65536))
	if !ok || amount != 65536 {
		t.Fatalf("ReadWindow = %d, %v", amount, ok)
	}
	if _, ok := ReadWindow(WindowPayload(0)); ok {
		t.Fatal("zero window must be rejected")
	}
	if _, ok := ReadWindow([]byte{0, 0, 1}); ok {
		t.Fatal("3-byte window must be rejected")
	}
}

func TestRelaySendableSet(t *testing.T) {
	// The client has no handler for these; sending one kills the transport.
	forbidden := []Type{Open, Hello, Pong, AuthChallenge, AuthResponse}
	for _, t2 := range forbidden {
		if t2.SendableByRelay() {
			t.Errorf("%v must not be sendable by the relay", t2)
		}
	}
	for _, t2 := range []Type{Welcome, Data, Window, Close, Ping, Bye} {
		if !t2.SendableByRelay() {
			t.Errorf("%v must be sendable by the relay", t2)
		}
	}
}
