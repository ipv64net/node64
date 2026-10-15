package dnsserver

import (
	"net/netip"
	"testing"
)

func TestAttachedAllowed(t *testing.T) {
	yes := []string{"192.168.10.0/24", "10.0.0.0/8", "172.17.0.0/16", "100.64.0.0/10", "fd00:1::/64",
		"2001:db8:1:2::/64", "2001:db8:1:2::5/128", "::ffff:192.168.1.0/120"}
	no := []string{"203.0.113.0/24", "198.51.100.7/32", "2001:db8::/48", "0.0.0.0/0", "::/0", "192.168.0.0/15", "100.0.0.0/8"}
	for _, s := range yes {
		if !attachedAllowed(netip.MustParsePrefix(s).Masked()) {
			t.Errorf("%s must count", s)
		}
	}
	for _, s := range no {
		if attachedAllowed(netip.MustParsePrefix(s).Masked()) {
			t.Errorf("%s must not count", s)
		}
	}
}

func TestRefusedCounted(t *testing.T) {
	a := &clientACL{extra: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("2001:db8:5::/48")}}
	a.refresh()
	if !a.allowed(netip.MustParseAddr("192.168.1.5")) || !a.allowed(netip.MustParseAddr("2001:db8:5::1")) {
		t.Fatal("private or listed address refused")
	}
	for i := 0; i < 3; i++ {
		if a.allowed(netip.MustParseAddr("203.0.113.9")) { // 0.0.0.0/0 aus alten Einstellungen gilt nicht
			t.Fatal("foreign address allowed")
		}
	}
	if r := a.stats(); r.Count != 3 || r.LastIP.String() != "203.0.113.9" || r.LastAt.IsZero() {
		t.Fatalf("stats = %+v", r)
	}
}
