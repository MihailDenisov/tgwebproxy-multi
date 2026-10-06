package mtproto

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestStreamOverPipe(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	secret := testSecret()
	done := make(chan error, 1)
	var received []byte

	go func() {
		header := make([]byte, HandshakeSize)
		if _, err := io.ReadFull(serverRaw, header); err != nil {
			done <- err
			return
		}
		hello, err := AcceptClient(header, secret)
		if err != nil {
			done <- err
			return
		}
		stream := NewStream(serverRaw, hello.Decrypt, hello.Encrypt)
		buf := make([]byte, 5)
		if _, err := io.ReadFull(stream, buf); err != nil {
			done <- err
			return
		}
		received = append([]byte(nil), buf...)
		_, err = stream.Write([]byte("world"))
		done <- err
	}()

	client, err := HandshakeOver(clientRaw, Abridged, 2, secret)
	if err != nil {
		t.Fatalf("HandshakeOver: %v", err)
	}
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, 5)
	clientRaw.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server side: %v", err)
	}
	if string(received) != "hello" {
		t.Fatalf("server received %q, want hello", received)
	}
	if string(reply) != "world" {
		t.Fatalf("client received %q, want world", reply)
	}
}

func TestStreamWriteLeavesCallerBufferIntact(t *testing.T) {
	// The relay reuses the slice after Write, so in-place encryption would corrupt it.
	clientRaw, serverRaw := net.Pipe()
	defer serverRaw.Close()
	go io.Copy(io.Discard, serverRaw)

	client, err := HandshakeOver(clientRaw, Abridged, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("do not modify me")
	original := append([]byte(nil), payload...)
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, original) {
		t.Fatalf("Write mutated its argument: %q", payload)
	}
	clientRaw.Close()
}
