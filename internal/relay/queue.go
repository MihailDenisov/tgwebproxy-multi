package relay

import "sync"

// chunkQueue is the client-to-datacentre buffer for one stream.
//
// Pushing never blocks. That is deliberate: the push happens on the session's
// single reader goroutine, and blocking there would stall the control frames
// of every other stream — including the Window frames those streams are
// waiting on. The queue cannot grow without bound anyway, because the relay
// only returns window credit after a chunk has been written upstream, so the
// client's own flow control caps what can be sitting here.
type chunkQueue struct {
	mu     sync.Mutex
	wake   *sync.Cond
	items  [][]byte
	bytes  int
	closed bool
}

func newChunkQueue() *chunkQueue {
	q := &chunkQueue{}
	q.wake = sync.NewCond(&q.mu)
	return q
}

func (q *chunkQueue) push(chunk []byte) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.items = append(q.items, chunk)
	q.bytes += len(chunk)
	q.wake.Signal()
}

func (q *chunkQueue) pop() ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && !q.closed {
		q.wake.Wait()
	}
	if len(q.items) == 0 {
		return nil, false
	}
	chunk := q.items[0]
	q.items[0] = nil
	q.items = q.items[1:]
	q.bytes -= len(chunk)
	return chunk, true
}

// empty reports whether the queue has been drained. The writer uses it to
// decide when to flush accumulated window credit back to the client.
func (q *chunkQueue) empty() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items) == 0
}

func (q *chunkQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.items = nil
	q.bytes = 0
	q.wake.Broadcast()
}
