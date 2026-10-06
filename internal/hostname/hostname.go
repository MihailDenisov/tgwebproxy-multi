// Package hostname mirrors MTP::NormalizeWebProxyHost from tdesktop. The relay
// must agree with the client on the exact spelling of the domain, because that
// spelling is hashed into the bridge capability.
package hostname

import (
	"errors"
	"net"
	"strings"

	"golang.org/x/net/idna"
)

var ErrInvalid = errors.New("hostname: not a valid WEB proxy host")

// Normalize applies NormalizeWebProxyHost's rules and returns the canonical form.
func Normalize(value string) (string, error) {
	input := strings.TrimSpace(value)
	if input == "" ||
		strings.ContainsAny(input, ":/?#@") ||
		strings.HasSuffix(input, ".") {
		return "", ErrInvalid
	}

	ascii, err := idna.ToASCII(input)
	if err != nil {
		return "", ErrInvalid
	}
	result := strings.ToLower(ascii)
	if result == "" || len(result) > 253 || !strings.Contains(result, ".") {
		return "", ErrInvalid
	}

	labels := strings.Split(result, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalid
		}
		for _, ch := range label {
			switch {
			case ch >= 'a' && ch <= 'z':
			case ch >= '0' && ch <= '9':
			case ch == '-':
			default:
				return "", ErrInvalid
			}
		}
	}

	// A numeric last label keeps out shorthand IPs like "127.1"; the scheme
	// depends on a real domain.
	last := labels[len(labels)-1]
	numeric := true
	for _, ch := range last {
		if ch < '0' || ch > '9' {
			numeric = false
			break
		}
	}
	if numeric {
		return "", ErrInvalid
	}
	if net.ParseIP(result) != nil {
		return "", ErrInvalid
	}
	return result, nil
}
