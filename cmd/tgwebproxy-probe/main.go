// Command tgwebproxy-probe checks a deployed relay the way Telegram Desktop
// would, then completes a real req_pq_multi exchange with a data centre
// through it.
package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
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
		secretText = flag.String("secret", "", "proxy secret, hex or base64url (required)")
		baseURL    = flag.String("url", "", "origin to probe; defaults to https://<domain>")
		dcID       = flag.Int("dc", 2, "data centre to reach through the relay")
		insecure   = flag.Bool("insecure", false, "skip certificate verification, for a local test bed")
		timeout    = flag.Duration("timeout", 20*time.Second, "per-step timeout")
		carrier    = flag.String("carrier", "both", "which carrier to exercise: websocket, longpoll or both")
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
	origin := *baseURL
	if origin == "" {
		origin = "https://" + name
	}

	opts := twin.DialOptions{
		BaseURL:    origin,
		Domain:     name,
		Capability: sec.Capability(name),
		Timeout:    *timeout,
	}
	if *insecure {
		opts.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}

	fmt.Printf("probing %s (domain %s)\n\n", origin, name)

	if err := checkGate(opts); err != nil {
		return err
	}

	var carriers []string
	switch *carrier {
	case "both":
		carriers = []string{"websocket", "longpoll"}
	case "websocket", "longpoll":
		carriers = []string{*carrier}
	default:
		return fmt.Errorf("-carrier must be websocket, longpoll or both")
	}
	for _, name := range carriers {
		fmt.Printf("\n  carrier: %s\n", name)
		if err := checkTunnel(name, opts, sec, int16(*dcID), *timeout); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	fmt.Println("\nOK: the relay carries real Telegram traffic end to end.")
	return nil
}

// checkGate verifies the camouflage: a wrong capability must be answered
// exactly like a bare request.
func checkGate(opts twin.DialOptions) error {
	coverStatus, cover, err := twin.FetchPage(opts, "")
	if err != nil {
		return fmt.Errorf("fetch the cover page: %w", err)
	}
	step("cover site answers", fmt.Sprintf("%d, %d bytes", coverStatus, len(cover)))

	wrongStatus, wrong, err := twin.FetchPage(opts, "?bridge=definitely-not-the-capability")
	if err != nil {
		return fmt.Errorf("fetch with a wrong capability: %w", err)
	}
	if wrongStatus != coverStatus || !bytes.Equal(wrong, cover) {
		return fmt.Errorf("a wrong capability is distinguishable from a plain request " +
			"(status or body differs), which defeats the camouflage")
	}
	step("wrong capability is indistinguishable", "identical status and body")

	bridgeStatus, bridge, err := twin.FetchPage(opts, "?bridge="+opts.Capability)
	if err != nil {
		return fmt.Errorf("fetch the bridge page: %w", err)
	}
	if bridgeStatus != 200 || !bytes.Contains(bridge, []byte("TelegramWebProxy")) {
		return fmt.Errorf("the valid capability did not produce the bridge page (status %d)", bridgeStatus)
	}
	step("valid capability serves the bridge", fmt.Sprintf("%d bytes", len(bridge)))
	return nil
}

func checkTunnel(carrier string, opts twin.DialOptions, sec secret.Secret, dcID int16, timeout time.Duration) error {
	var (
		transport twin.Transport
		err       error
	)
	if carrier == "longpoll" {
		// The same page the client would load, then its fallback carrier.
		transport, err = twin.DialPoll(opts)
		if err != nil {
			return fmt.Errorf("open the fallback carrier: %w", err)
		}
		step("fallback carrier open", "session token taken from the bridge page")
	} else {
		transport, err = twin.DialWS(opts)
		if err != nil {
			return fmt.Errorf("open the relay socket: %w", err)
		}
		step("websocket upgraded", "binary transport open")
	}
	defer transport.Close()

	tw := twin.NewTwin(transport, sec)
	if err := tw.Handshake(); err != nil {
		return fmt.Errorf("transport handshake: %w", err)
	}
	step("hello accepted", "welcome is a single empty frame, as the client requires")

	pumpErr := make(chan error, 1)
	go func() { pumpErr <- tw.Pump() }()

	stream, err := tw.Open(mtproto.Abridged, dcID)
	if err != nil {
		return fmt.Errorf("open a stream: %w", err)
	}
	step("stream opened", fmt.Sprintf("dc %d, abridged transport", dcID))

	done := make(chan error, 1)
	go func() {
		serverNonce, err := tw.ReqPQ(stream, timeout)
		if err != nil {
			done <- err
			return
		}
		step("telegram answered req_pq_multi", fmt.Sprintf("server nonce %x", serverNonce))
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("mtproto exchange: %w", err)
		}
	case err := <-pumpErr:
		return fmt.Errorf("the relay broke the client's rules: %w", err)
	}

	fmt.Println("\nOK: the relay carries real Telegram traffic end to end.")
	return nil
}

func step(name, detail string) {
	fmt.Printf("  ok  %-38s %s\n", name, detail)
}
