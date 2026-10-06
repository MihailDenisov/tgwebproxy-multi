package longpoll

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

func TestUplinkOrderAndDuplicates(t *testing.T) {
	m := NewManager()
	defer m.Shutdown()
	s, err := m.Create()
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Deliver(0, [][]byte{[]byte("one")}); err != nil {
		t.Fatalf("first batch: %v", err)
	}
	// A retried POST must not inject the same MTProto bytes twice.
	if err := s.Deliver(0, [][]byte{[]byte("one")}); err != nil {
		t.Fatalf("replay of the previous batch must be accepted: %v", err)
	}
	if err := s.Deliver(1, [][]byte{[]byte("two")}); err != nil {
		t.Fatalf("second batch: %v", err)
	}
	// A gap means something was lost; guessing would corrupt the stream.
	if err := s.Deliver(5, [][]byte{[]byte("five")}); err != ErrSequence {
		t.Errorf("out-of-order batch: got %v, want ErrSequence", err)
	}

	for _, want := range []string{"one", "two"} {
		got, err := s.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage: %v", err)
		}
		if string(got) != want {
			t.Fatalf("read %q, want %q", got, want)
		}
	}
}

func TestDownlinkCursorAndReplay(t *testing.T) {
	m := NewManager()
	defer m.Shutdown()
	s, _ := m.Create()

	if err := s.WriteMessage([]byte("alpha")); err != nil {
		t.Fatal(err)
	}
	batch, err := s.Collect(0, time.Second)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(batch) != 1 || !bytes.Equal(batch[0], []byte("alpha")) {
		t.Fatalf("batch = %q", batch)
	}

	// A poll that was retried because its response was lost must get the same
	// bytes rather than nothing.
	again, err := s.Collect(0, time.Second)
	if err != nil {
		t.Fatalf("replayed poll: %v", err)
	}
	if len(again) != 1 || !bytes.Equal(again[0], []byte("alpha")) {
		t.Fatalf("replay returned %q, want the same batch", again)
	}

	if _, err := s.Collect(7, time.Second); err != ErrSequence {
		t.Errorf("a cursor from nowhere: got %v, want ErrSequence", err)
	}
}

// An empty poll must return without data and leave the cursor alone, so the
// page can simply ask again.
func TestPollHoldsThenReturnsEmpty(t *testing.T) {
	m := NewManager()
	defer m.Shutdown()
	s, _ := m.Create()

	start := time.Now()
	batch, err := s.Collect(0, 150*time.Millisecond)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(batch) != 0 {
		t.Fatalf("got %d messages from an idle session", len(batch))
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("poll returned after %s; it must hold the request", elapsed)
	}
	// The cursor did not move, so the next poll uses the same one.
	if err := s.WriteMessage([]byte("late")); err != nil {
		t.Fatal(err)
	}
	batch, err = s.Collect(0, time.Second)
	if err != nil || len(batch) != 1 {
		t.Fatalf("after an empty poll: %v, %q", err, batch)
	}
}

func TestPollWakesOnWrite(t *testing.T) {
	m := NewManager()
	defer m.Shutdown()
	s, _ := m.Create()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		s.WriteMessage([]byte("wake up"))
	}()

	start := time.Now()
	batch, err := s.Collect(0, 5*time.Second)
	wg.Wait()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(batch) != 1 {
		t.Fatalf("got %d messages", len(batch))
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("poll took %s; a write must wake it", elapsed)
	}
}

func TestClosedSessionUnblocksTheRelay(t *testing.T) {
	m := NewManager()
	defer m.Shutdown()
	s, _ := m.Create()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := s.ReadMessage(); err == nil {
			t.Error("ReadMessage must fail once the session is closed")
		}
	}()
	s.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("closing the session left the relay blocked in ReadMessage")
	}
}

// A page that stops collecting must lose its session rather than grow the
// queue without bound or have frames silently dropped.
func TestFullDownlinkClosesTheSession(t *testing.T) {
	m := NewManager()
	defer m.Shutdown()
	s, _ := m.Create()

	var err error
	for i := 0; i <= MaxPending; i++ {
		if err = s.WriteMessage([]byte("x")); err != nil {
			break
		}
	}
	if err != ErrClosed {
		t.Fatalf("writing past the limit returned %v, want ErrClosed", err)
	}
	if !s.Closed() {
		t.Error("the session must be closed once its queue overflows")
	}
}

func TestManagerReapsIdleSessions(t *testing.T) {
	m := NewManager()
	defer m.Shutdown()
	m.lifetime = 20 * time.Millisecond
	s, _ := m.Create()

	if _, err := m.Get(s.Token()); err != nil {
		t.Fatalf("a fresh session must be findable: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	m.reapOnce(time.Now())

	if _, err := m.Get(s.Token()); err != ErrUnknownSession {
		t.Errorf("idle session survived: %v", err)
	}
	if !s.Closed() {
		t.Error("a reaped session must be closed")
	}
}
