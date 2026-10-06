// Package dc maps the data-centre id from an obfuscated2 handshake to a
// Telegram endpoint, using Telegram Desktop's built-in bootstrap list
// (kBuiltInDcs / kBuiltInDcsTest in mtproto_dc_options.cpp) so the relay has
// no start-up dependency on the network.
package dc

import (
	"fmt"
	"net"
	"strconv"
)

// TestShift is MTP::kDcShift, added to the id for the test servers; the media
// cluster negates the id (SessionPrivate::getProtocolDcId).
const TestShift = 10000

var production = map[int]string{
	1: "149.154.175.50",
	2: "149.154.167.51",
	3: "149.154.175.100",
	4: "149.154.167.91",
	5: "149.154.171.5",
}

var productionV6 = map[int]string{
	1: "2001:0b28:f23d:f001:0000:0000:0000:000a",
	2: "2001:067c:04e8:f002:0000:0000:0000:000a",
	3: "2001:0b28:f23d:f003:0000:0000:0000:000a",
	4: "2001:067c:04e8:f004:0000:0000:0000:000a",
	5: "2001:0b28:f23f:f005:0000:0000:0000:000a",
}

var test = map[int]string{
	1: "149.154.175.10",
	2: "149.154.167.40",
	3: "149.154.175.117",
}

var testV6 = map[int]string{
	1: "2001:0b28:f23d:f001:0000:0000:0000:000e",
	2: "2001:067c:04e8:f002:0000:0000:0000:000e",
	3: "2001:0b28:f23d:f003:0000:0000:0000:000e",
}

const port = 443

type Target struct {
	ID       int
	TestMode bool
	// MediaCluster is a download optimisation; the ordinary DC front door
	// serves those connections too, so the relay dials the same address.
	MediaCluster bool
	Address      string
	// AddressV6 is "" when the DC has none.
	AddressV6 string
}

// Resolve decodes the handshake int16 (SessionPrivate::getProtocolDcId): the
// magnitude is the DC id, negative means media, above TestShift means test.
func Resolve(protocolDCID int16) (Target, error) {
	value := int(protocolDCID)
	media := value < 0
	if media {
		value = -value
	}
	testMode := false
	if value > TestShift {
		testMode = true
		value -= TestShift
	}

	table, tableV6 := production, productionV6
	if testMode {
		table, tableV6 = test, testV6
	}
	ip, ok := table[value]
	if !ok {
		return Target{}, fmt.Errorf("dc: unknown data centre id %d (raw %d)", value, protocolDCID)
	}
	target := Target{
		ID:           value,
		TestMode:     testMode,
		MediaCluster: media,
		Address:      net.JoinHostPort(ip, strconv.Itoa(port)),
	}
	if ip6, ok := tableV6[value]; ok {
		target.AddressV6 = net.JoinHostPort(ip6, strconv.Itoa(port))
	}
	return target, nil
}

func (t Target) String() string {
	suffix := ""
	if t.TestMode {
		suffix += " test"
	}
	if t.MediaCluster {
		suffix += " media"
	}
	return fmt.Sprintf("DC%d%s (%s)", t.ID, suffix, t.Address)
}
