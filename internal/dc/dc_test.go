package dc

import "testing"

func TestResolveEncoding(t *testing.T) {
	cases := []struct {
		in      int16
		id      int
		test    bool
		media   bool
		address string
	}{
		{2, 2, false, false, "149.154.167.51:443"},
		{-2, 2, false, true, "149.154.167.51:443"},
		{5, 5, false, false, "149.154.171.5:443"},
		{10001, 1, true, false, "149.154.175.10:443"},
		{-10003, 3, true, true, "149.154.175.117:443"},
	}
	for _, c := range cases {
		got, err := Resolve(c.in)
		if err != nil {
			t.Errorf("Resolve(%d): %v", c.in, err)
			continue
		}
		if got.ID != c.id || got.TestMode != c.test || got.MediaCluster != c.media {
			t.Errorf("Resolve(%d) = %+v, want id=%d test=%v media=%v",
				c.in, got, c.id, c.test, c.media)
		}
		if got.Address != c.address {
			t.Errorf("Resolve(%d) address = %s, want %s", c.in, got.Address, c.address)
		}
	}
}

func TestResolveRejectsUnknown(t *testing.T) {
	for _, in := range []int16{0, 6, 99, 10004, -10005} {
		if got, err := Resolve(in); err == nil {
			t.Errorf("Resolve(%d) = %v, want error", in, got)
		}
	}
}

func TestProductionDCsHaveIPv6(t *testing.T) {
	for id := 1; id <= 5; id++ {
		target, err := Resolve(int16(id))
		if err != nil {
			t.Fatalf("Resolve(%d): %v", id, err)
		}
		if target.AddressV6 == "" {
			t.Errorf("DC%d has no IPv6 address", id)
		}
	}
}
