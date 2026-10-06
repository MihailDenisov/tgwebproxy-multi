// Package frame implements the Telegram WEB-proxy wire format as parsed by
// tdesktop (Telegram/SourceFiles/mtproto/web_proxy/web_proxy_frame.{h,cpp}).
// The client treats any deviation as a protocol error that tears down the
// whole transport, not just one stream.
//
// Frame layout:
//
//	offset  size  field
//	0       1     type
//	1       3     stream id, big-endian, 24 bits
//	4       4     payload length, big-endian
//	8       N     payload
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Limits taken verbatim from web_proxy_frame.h and web_proxy_transport.cpp.
const (
	HeaderSize = 8           // kFrameHeaderSize
	MaxPayload = 1024 * 1024 // kMaxFramePayload
	MaxBatch   = 4096        // kMaxBatchFrames, per transport message
	// InitialWindow is kInitialStreamWindow: per-stream credit both sides
	// start with before any Window frame is exchanged.
	InitialWindow = 4 * 1024 * 1024
	// DataChunk is kDataFrameSize; matched so both directions behave alike.
	DataChunk   = 64 * 1024
	MaxStreamID = 0x00FFFFFF
	// MaxPingPayload is the largest Ping payload the client will echo back.
	MaxPingPayload = 64
	HelloVersion   = 0x01
)

type Type byte

const (
	Open          Type = 0x01
	Data          Type = 0x02
	Close         Type = 0x03
	Window        Type = 0x04
	Ping          Type = 0x05
	Pong          Type = 0x06
	Hello         Type = 0x10
	Welcome       Type = 0x11
	AuthChallenge Type = 0x12
	AuthResponse  Type = 0x13
	Bye           Type = 0x1F
)

// Known reports whether the byte is one of the types the client recognises.
// Anything else makes the client abandon the whole message.
func (t Type) Known() bool {
	switch t {
	case Open, Data, Close, Window, Ping, Pong,
		Hello, Welcome, AuthChallenge, AuthResponse, Bye:
		return true
	}
	return false
}

func (t Type) String() string {
	switch t {
	case Open:
		return "Open"
	case Data:
		return "Data"
	case Close:
		return "Close"
	case Window:
		return "Window"
	case Ping:
		return "Ping"
	case Pong:
		return "Pong"
	case Hello:
		return "Hello"
	case Welcome:
		return "Welcome"
	case AuthChallenge:
		return "AuthChallenge"
	case AuthResponse:
		return "AuthResponse"
	case Bye:
		return "Bye"
	}
	return fmt.Sprintf("Unknown(0x%02X)", byte(t))
}

// SendableByRelay reports the types Transport::Private::processRelayFrame
// (web_proxy_transport.cpp) has a handler for; sending anything else is an
// immediate protocol error on the client side.
func (t Type) SendableByRelay() bool {
	switch t {
	case Welcome, Ping, Bye, Data, Window, Close:
		return true
	}
	return false
}

// Frame is one parsed frame. Payload aliases the buffer it was parsed from.
type Frame struct {
	Type     Type
	StreamID uint32
	Payload  []byte
}

var (
	// ErrShort means the buffer ends in the middle of a frame. The client
	// requires every transport message to hold whole frames only, so for us
	// this is always an error rather than a "wait for more bytes" signal.
	ErrShort          = errors.New("frame: truncated frame in message")
	ErrUnknownType    = errors.New("frame: unknown frame type")
	ErrPayloadTooBig  = errors.New("frame: payload over 1 MiB")
	ErrBatchTooBig    = errors.New("frame: over 4096 frames in one message")
	ErrStreamIDTooBig = errors.New("frame: stream id over 24 bits")
)

// Append returns an error rather than panicking on oversized input: the
// payload usually comes from a network read and must never take the process
// down.
func Append(dst []byte, t Type, streamID uint32, payload []byte) ([]byte, error) {
	if streamID > MaxStreamID {
		return dst, ErrStreamIDTooBig
	}
	if len(payload) > MaxPayload {
		return dst, ErrPayloadTooBig
	}
	var header [HeaderSize]byte
	header[0] = byte(t)
	header[1] = byte(streamID >> 16)
	header[2] = byte(streamID >> 8)
	header[3] = byte(streamID)
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	dst = append(dst, header[:]...)
	dst = append(dst, payload...)
	return dst, nil
}

func Marshal(t Type, streamID uint32, payload []byte) ([]byte, error) {
	return Append(make([]byte, 0, HeaderSize+len(payload)), t, streamID, payload)
}

// Parse splits one complete transport message into frames.
//
// Unlike the client's ParseFrames, which keeps a partial tail in its buffer,
// this requires the message to contain whole frames and nothing else: the
// client itself enforces exactly that on the message it receives
// (processRelayPayload rejects a non-empty remainder), so a relay that
// tolerated ragged input would only be hiding its own framing bugs.
func Parse(buf []byte) ([]Frame, error) {
	var out []Frame
	for len(buf) > 0 {
		if len(buf) < HeaderSize {
			return nil, ErrShort
		}
		t := Type(buf[0])
		if !t.Known() {
			return nil, ErrUnknownType
		}
		streamID := uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
		size := binary.BigEndian.Uint32(buf[4:])
		if size > MaxPayload {
			return nil, ErrPayloadTooBig
		}
		total := HeaderSize + int(size)
		if len(buf) < total {
			return nil, ErrShort
		}
		if len(out) >= MaxBatch {
			return nil, ErrBatchTooBig
		}
		out = append(out, Frame{
			Type:     t,
			StreamID: streamID,
			Payload:  buf[HeaderSize:total],
		})
		buf = buf[total:]
	}
	return out, nil
}

func WindowPayload(amount uint32) []byte {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], amount)
	return out[:]
}

// ReadWindow mirrors the client: any length other than 4 or a zero amount is
// rejected.
func ReadWindow(payload []byte) (uint32, bool) {
	if len(payload) != 4 {
		return 0, false
	}
	amount := binary.BigEndian.Uint32(payload)
	if amount == 0 {
		return 0, false
	}
	return amount, true
}
