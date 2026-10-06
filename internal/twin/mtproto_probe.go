package twin

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

// req_pq_multi is the first message of the auth-key exchange: unencrypted, no
// key material, answered immediately by the DC. That makes it the cheapest
// end-to-end proof that bytes really reach Telegram through a relay.

const (
	reqPQMultiID uint32 = 0xbe7e8ef1
	resPQID      uint32 = 0x05162463
)

// ReqPQ runs one req_pq_multi exchange and returns the server nonce. Framing
// is abridged (what the client selects for a plain 16-byte secret): one length
// byte in 4-byte words, or 0x7F plus a 24-bit little-endian word count.
func (t *Twin) ReqPQ(st *Stream, timeout time.Duration) (serverNonce []byte, err error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	body := make([]byte, 0, 20)
	body = binary.LittleEndian.AppendUint32(body, reqPQMultiID)
	body = append(body, nonce...)

	message := make([]byte, 0, 20+len(body))
	message = binary.LittleEndian.AppendUint64(message, 0) // auth_key_id: unencrypted
	message = binary.LittleEndian.AppendUint64(message, messageID())
	message = binary.LittleEndian.AppendUint32(message, uint32(len(body)))
	message = append(message, body...)

	if err := t.Write(st, abridged(message)); err != nil {
		return nil, fmt.Errorf("send req_pq_multi: %w", err)
	}

	payload, err := t.readAbridged(st, timeout)
	if err != nil {
		return nil, err
	}
	if len(payload) < 24 {
		return nil, fmt.Errorf("reply is %d bytes, too short for an MTProto message", len(payload))
	}
	// auth_key_id (8) + message_id (8) + length (4), then the constructor.
	if id := binary.LittleEndian.Uint64(payload[0:8]); id != 0 {
		return nil, fmt.Errorf("reply carries auth_key_id %d, want an unencrypted message", id)
	}
	constructor := binary.LittleEndian.Uint32(payload[20:24])
	if constructor != resPQID {
		return nil, fmt.Errorf("reply constructor is %#08x, want resPQ %#08x", constructor, resPQID)
	}
	if len(payload) < 24+32 {
		return nil, fmt.Errorf("resPQ is truncated at %d bytes", len(payload))
	}
	if !bytes.Equal(payload[24:40], nonce) {
		return nil, fmt.Errorf("resPQ echoed a different nonce")
	}
	return payload[40:56], nil
}

// messageID: unix time in the high 32 bits, low word divisible by four as the
// protocol requires of client messages.
func messageID() uint64 {
	now := time.Now()
	return uint64(now.Unix())<<32 | uint64(now.Nanosecond()/1000)<<2&0xFFFFFFFC
}

func abridged(payload []byte) []byte {
	words := len(payload) / 4
	if words < 0x7F {
		return append([]byte{byte(words)}, payload...)
	}
	header := []byte{0x7F, byte(words), byte(words >> 8), byte(words >> 16)}
	return append(header, payload...)
}

func (t *Twin) readAbridged(st *Stream, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	var buf []byte
	for {
		if header := len(buf); header >= 1 {
			words := int(buf[0])
			offset := 1
			if words == 0x7F {
				if len(buf) < 4 {
					goto more
				}
				words = int(buf[1]) | int(buf[2])<<8 | int(buf[3])<<16
				offset = 4
			}
			size := words * 4
			if size > 0 && len(buf) >= offset+size {
				return buf[offset : offset+size], nil
			}
		}
	more:
		left := time.Until(deadline)
		if left <= 0 {
			return nil, fmt.Errorf("no reply from the data centre within %s", timeout)
		}
		chunk, err := t.Read(st, left)
		if err != nil {
			return nil, err
		}
		buf = append(buf, chunk...)
	}
}
