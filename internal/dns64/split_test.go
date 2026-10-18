package dns64

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestSplit(t *testing.T) {
	m := &Module{}
	if _, ok := m.split("app.test", dns.TypeA, netip.MustParseAddr("192.168.1.20")); ok {
		t.Fatal("no split names set")
	}
	m.SetSplit(func(n string) bool { return n == "app.test" })
	old := linkAddrs
	defer func() { linkAddrs = old }()
	linkAddrs = func(c netip.Addr) []netip.Addr {
		if c == netip.MustParseAddr("192.168.1.20") || c == netip.MustParseAddr("fd00::20") {
			return []netip.Addr{netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("fd00::5")}
		}
		return nil
	}
	rrs, ok := m.split("app.test", dns.TypeA, netip.MustParseAddr("192.168.1.20"))
	if !ok || len(rrs) != 1 || rrs[0].(*dns.A).A.String() != "192.168.1.5" {
		t.Fatalf("A: %v %v", ok, rrs)
	}
	rrs, ok = m.split("app.test", dns.TypeAAAA, netip.MustParseAddr("fd00::20"))
	if !ok || len(rrs) != 1 || rrs[0].(*dns.AAAA).AAAA.String() != "fd00::5" {
		t.Fatalf("AAAA: %v %v", ok, rrs)
	}
	if _, ok := m.split("other.test", dns.TypeA, netip.MustParseAddr("192.168.1.20")); ok {
		t.Fatal("other name")
	}
	if _, ok := m.split("app.test", dns.TypeMX, netip.MustParseAddr("192.168.1.20")); ok {
		t.Fatal("MX")
	}
	// Client aus einem fremden Netz: normale Antwort (ueber srv07/srv08)
	if _, ok := m.split("app.test", dns.TypeA, netip.MustParseAddr("10.9.9.9")); ok {
		t.Fatal("foreign network")
	}
	// echte Schnittstellen: Loopback kennt sich selbst
	linkAddrs = old
	rrs, ok = m.split("app.test", dns.TypeA, netip.MustParseAddr("127.0.0.1"))
	if !ok || len(rrs) == 0 {
		t.Fatalf("loopback: %v %v", ok, rrs)
	}
}
