// Package share renders the credentials an operator hands to a user.
//
// The link format is the one Telegram Desktop parses for this proxy type. The
// public t.me frontend does not route it yet, so a user may have to open it
// inside the client rather than from a browser.
package share

import (
	"net/url"

	"tgwebproxy/internal/secret"
)

// Link renders the invitation for one secret on one domain.
func Link(domain string, sec secret.Secret) string {
	query := url.Values{"server": {domain}, "secret": {sec.Hex()}}
	return "https://t.me/webproxy?" + query.Encode()
}

// TelegramURI is the same invitation in the client's own scheme, which works
// when t.me is unreachable.
func TelegramURI(domain string, sec secret.Secret) string {
	query := url.Values{"server": {domain}, "secret": {sec.Hex()}}
	return "tg://webproxy?" + query.Encode()
}
