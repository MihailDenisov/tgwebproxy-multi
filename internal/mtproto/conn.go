package mtproto

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"tgwebproxy/internal/dc"
)

// Stream wraps a byte stream in an obfuscated2 keystream pair. Both directions
// are AES-256-CTR, a pure XOR: no framing, no buffering between calls.
type Stream struct {
	raw     io.ReadWriteCloser
	decrypt cipher.Stream
	encrypt cipher.Stream
	scratch []byte
}

func NewStream(raw io.ReadWriteCloser, decrypt, encrypt cipher.Stream) *Stream {
	return &Stream{raw: raw, decrypt: decrypt, encrypt: encrypt}
}

func (s *Stream) Read(p []byte) (int, error) {
	n, err := s.raw.Read(p)
	if n > 0 {
		s.decrypt.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

// Write encrypts through a scratch buffer, leaving the caller's slice intact.
func (s *Stream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if cap(s.scratch) < len(p) {
		s.scratch = make([]byte, len(p))
	}
	buf := s.scratch[:len(p)]
	s.encrypt.XORKeyStream(buf, p)
	return s.raw.Write(buf)
}

func (s *Stream) Close() error { return s.raw.Close() }

// DialDC talks to the DC as a proxy-less client would: the client's own
// transport tag so framing passes through untouched, no secret so the keys are
// the raw handshake material, and the DC id forwarded verbatim.
func DialDC(
	ctx context.Context,
	target dc.Target,
	protocol uint32,
	dcID int16,
	dialer *net.Dialer,
) (*Stream, error) {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 10 * time.Second}
	}
	conn, err := dialAny(ctx, dialer, target)
	if err != nil {
		return nil, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	stream, err := HandshakeOver(conn, protocol, dcID, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return stream, nil
}

// dialAny tries IPv4 and then IPv6, so the relay works on a host with either
// stack. Each attempt gets a share of the deadline: on a host with no IPv4
// route the first attempt fails at once, but one whose IPv4 path is blackholed
// would otherwise spend the whole budget before ever trying IPv6.
func dialAny(ctx context.Context, dialer *net.Dialer, target dc.Target) (net.Conn, error) {
	addresses := make([]string, 0, 2)
	if target.Address != "" {
		addresses = append(addresses, target.Address)
	}
	if target.AddressV6 != "" {
		addresses = append(addresses, target.AddressV6)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("dial %s: no address", target)
	}

	var errs []error
	for i, address := range addresses {
		attemptCtx, cancel := ctx, context.CancelFunc(nil)
		if deadline, ok := ctx.Deadline(); ok && i < len(addresses)-1 {
			left := time.Until(deadline)
			attemptCtx, cancel = context.WithTimeout(ctx, left/time.Duration(len(addresses)-i))
		}
		conn, err := dialer.DialContext(attemptCtx, "tcp", address)
		if cancel != nil {
			cancel()
		}
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("dial %s: %w", target, errors.Join(errs...))
}

func HandshakeOver(
	raw io.ReadWriteCloser,
	protocol uint32,
	dcID int16,
	secret []byte,
) (*Stream, error) {
	hello, err := NewHandshake(protocol, dcID, secret)
	if err != nil {
		return nil, err
	}
	if _, err := raw.Write(hello.Wire); err != nil {
		return nil, fmt.Errorf("write handshake: %w", err)
	}
	return NewStream(raw, hello.Decrypt, hello.Encrypt), nil
}
