// Package webassets holds the bridge page that carries proxy traffic and the
// cover site everyone else sees.
package webassets

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"strings"
)

//go:embed bridge.html
var bridgeTemplate string

//go:embed site/index.html
var coverPage []byte

func CoverPage() []byte { return coverPage }

// Bridge renders the page with a per-response script nonce for the CSP header,
// so that no script injected by anything else can run alongside the bridge.
func Bridge(session string) (page []byte, nonce string, err error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", err
	}
	nonce = base64.RawStdEncoding.EncodeToString(raw)
	rendered := strings.ReplaceAll(bridgeTemplate, "__NONCE__", nonce)
	// The token is the credential for the long-poll carrier, so it is minted
	// per page and never reused.
	rendered = strings.ReplaceAll(rendered, "__SESSION__", session)
	return []byte(rendered), nonce, nil
}
