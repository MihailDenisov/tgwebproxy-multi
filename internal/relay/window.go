package relay

import "sync"

// credit is one stream's send allowance towards the client.
//
// The client starts every stream with frame.InitialWindow bytes of credit and
// tops it up with Window frames as it drains its socket. Overrunning that
// allowance is not a soft error: Transport::Private::processRelayFrame treats
// an oversized Data frame as a protocol error and tears down the entire
// transport, killing every other stream with it. So the pump takes credit
// before it reads from the data centre, which turns the client's window into
// real backpressure on the upstream socket instead of an unbounded queue in
// our memory.
type credit struct {
	mu     sync.Mutex
	wake   *sync.Cond
	avail  uint64
	closed bool
}

func newCredit(initial uint64) *credit {
	c := &credit{avail: initial}
	c.wake = sync.NewCond(&c.mu)
	return c
}

// add grants more credit, saturating at the 32-bit maximum the way the client
// does when it merges Window frames.
func (c *credit) add(amount uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	const max = uint64(^uint32(0))
	c.avail += uint64(amount)
	if c.avail > max {
		c.avail = max
	}
	c.wake.Broadcast()
}

func (c *credit) take(limit int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.avail == 0 && !c.closed {
		c.wake.Wait()
	}
	if c.closed {
		return 0
	}
	n := uint64(limit)
	if c.avail < n {
		n = c.avail
	}
	c.avail -= n
	return int(n)
}

// giveBack returns credit reserved for a read that came up short.
func (c *credit) giveBack(amount int) {
	if amount <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.avail += uint64(amount)
	c.wake.Broadcast()
}

func (c *credit) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.wake.Broadcast()
}
