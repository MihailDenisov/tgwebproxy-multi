// Command tgwebproxy-load drives a relay hard enough to measure it.
//
// It repeats the cheapest real MTProto exchange, req_pq_multi, across many
// streams and sessions. That is deliberately the small-frame regime: it is
// where per-message overhead matters most, so what it measures is the upper
// bound on what batching could save.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"tgwebproxy/internal/hostname"
	"tgwebproxy/internal/mtproto"
	"tgwebproxy/internal/secret"
	"tgwebproxy/internal/twin"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		domain     = flag.String("domain", "", "relay domain (required)")
		secretText = flag.String("secret", "", "proxy secret (required)")
		sessions   = flag.Int("sessions", 4, "concurrent transport sessions")
		streams    = flag.Int("streams", 4, "streams per session")
		duration   = flag.Duration("duration", 20*time.Second, "how long to keep going")
		carrier    = flag.String("carrier", "websocket", "websocket or longpoll")
		dcID       = flag.Int("dc", 2, "data centre to reach")
	)
	flag.Parse()

	if *domain == "" || *secretText == "" {
		return fmt.Errorf("-domain and -secret are required")
	}
	name, err := hostname.Normalize(*domain)
	if err != nil {
		return err
	}
	sec, err := secret.Parse(*secretText)
	if err != nil {
		return err
	}
	opts := twin.DialOptions{
		BaseURL:    "https://" + name,
		Domain:     name,
		Capability: sec.Capability(name),
		Timeout:    40 * time.Second,
		TLSConfig:  &tls.Config{},
	}

	var exchanges, failures atomic.Int64
	deadline := time.Now().Add(*duration)
	start := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < *sessions; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			if err := driveSession(opts, sec, int16(*dcID), *carrier, *streams, deadline,
				&exchanges, &failures); err != nil {
				fmt.Fprintf(os.Stderr, "session %d: %v\n", index, err)
			}
		}(i)
	}
	wg.Wait()

	elapsed := time.Since(start)
	fmt.Printf("%d exchanges in %s (%.0f/s), %d failures\n",
		exchanges.Load(), elapsed.Round(time.Millisecond),
		float64(exchanges.Load())/elapsed.Seconds(), failures.Load())
	return nil
}

func driveSession(opts twin.DialOptions, sec secret.Secret, dcID int16, carrier string,
	streams int, deadline time.Time, exchanges, failures *atomic.Int64) error {

	var transport twin.Transport
	var err error
	if carrier == "longpoll" {
		transport, err = twin.DialPoll(opts)
	} else {
		transport, err = twin.DialWS(opts)
	}
	if err != nil {
		return err
	}
	defer transport.Close()

	tw := twin.NewTwin(transport, sec)
	if err := tw.Handshake(); err != nil {
		return err
	}
	go tw.Pump()

	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// One stream per worker, reused: opening a fresh one for every
			// exchange would hit the relay's per-session stream cap rather
			// than measure anything.
			stream, err := tw.Open(mtproto.Abridged, dcID)
			if err != nil {
				failures.Add(1)
				return
			}
			for time.Now().Before(deadline) {
				if _, err := tw.ReqPQ(stream, 20*time.Second); err != nil {
					failures.Add(1)
					// The data centre closes a connection that asks too
					// often; take a fresh stream and keep going.
					stream, err = tw.Open(mtproto.Abridged, dcID)
					if err != nil {
						return
					}
					continue
				}
				exchanges.Add(1)
			}
		}()
	}
	wg.Wait()
	return nil
}
