package mtproto

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"tgwebproxy/internal/dc"
)

func listener(t *testing.T, network string) net.Listener {
	t.Helper()
	l, err := net.Listen(network, "localhost:0")
	if err != nil {
		t.Skipf("%s is not available here: %v", network, err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	return l
}

// A host with no IPv4 route must still reach a data centre over IPv6.
func TestDialFallsBackToIPv6(t *testing.T) {
	six := listener(t, "tcp6")
	target := dc.Target{
		ID: 2,
		// Reserved for documentation, so nothing answers and nothing is
		// disturbed by the attempt.
		Address:   "192.0.2.1:443",
		AddressV6: six.Addr().String(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	conn, err := dialAny(ctx, &net.Dialer{}, target)
	if err != nil {
		t.Fatalf("dialAny did not fall back to IPv6: %v", err)
	}
	conn.Close()
}

func TestDialPrefersIPv4WhenItAnswers(t *testing.T) {
	four := listener(t, "tcp4")
	target := dc.Target{ID: 2, Address: four.Addr().String(), AddressV6: "[2001:db8::1]:443"}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := dialAny(ctx, &net.Dialer{}, target)
	if err != nil {
		t.Fatalf("dialAny: %v", err)
	}
	defer conn.Close()
	if !strings.HasPrefix(conn.RemoteAddr().String(), "127.") {
		t.Errorf("connected to %s, want the IPv4 address", conn.RemoteAddr())
	}
}

// closedPort returns an address nothing listens on, so a dial is refused
// immediately and the test does not depend on what the network does with
// unroutable addresses.
func closedPort(t *testing.T, network string) string {
	t.Helper()
	l, err := net.Listen(network, "localhost:0")
	if err != nil {
		t.Skipf("%s is not available here: %v", network, err)
	}
	address := l.Addr().String()
	l.Close()
	return address
}

// With both families refused, the error must name the target rather than
// silently reporting only the last attempt.
func TestDialReportsFailure(t *testing.T) {
	target := dc.Target{
		ID:        2,
		Address:   closedPort(t, "tcp4"),
		AddressV6: closedPort(t, "tcp6"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := dialAny(ctx, &net.Dialer{}, target); err == nil {
		t.Fatal("dialAny must fail when nothing answers")
	} else if !strings.Contains(err.Error(), "DC2") {
		t.Errorf("error should name the target, got %v", err)
	}
}
