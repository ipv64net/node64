package ra

import (
	"net"
	"net/netip"
	"testing"
)

// Code-Review 1.7: Eine RS darf von "::" kommen (Geraet noch ohne Adresse, RFC 4861 6.1.1) - dann ohne
// Link-Layer-Option; RAs und RS sonst nur von Link-Local.
func TestFromLink(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	ll, any, global := netip.MustParseAddr("fe80::1"), netip.IPv6Unspecified(), netip.MustParseAddr("2001:db8::1")
	rs, rsMAC := solicit(nil), solicit(mac)
	ad := Ad{MAC: mac}.Marshal()
	for _, c := range []struct {
		b    []byte
		ip   netip.Addr
		want bool
	}{{rs, any, true}, {rsMAC, any, false}, {rsMAC, ll, true}, {ad, ll, true}, {ad, any, false}, {rs, global, false}} {
		if got := fromLink(c.b, c.ip); got != c.want {
			t.Fatalf("type %d from %v (%d bytes): %v", c.b[0], c.ip, len(c.b), got)
		}
	}
}

// Router-Dienst auf demselben Host (radvd, odhcpd, dnsmasq) erkennt der Sender schon vor dem ersten eigenen RA an
// dessen Beitritt zur Gruppe aller Router (ff02::2) in /proc/net/igmp6 - abzueglich des eigenen Beitritts und dem des
// Kernels bei IPv6-Forwarding.
func TestRouterListeners(t *testing.T) {
	const igmp6 = `1    lo              ff020000000000000000000000000001     1 0000000C 0
2    eth0            ff020000000000000000000000000002     3 00000004 0
2    eth0            ff020000000000000000000000000001     1 0000000C 0
3    eth1            ff020000000000000000000000000002     1 00000004 0
`
	for _, c := range []struct {
		iface string
		want  int
	}{{"eth0", 3}, {"eth1", 1}, {"lo", 0}, {"eth9", 0}} {
		if got := routerListeners(igmp6, c.iface); got != c.want {
			t.Fatalf("%s: %d", c.iface, got)
		}
	}
	for _, c := range []struct {
		users           int
		joined, forward bool
		want            bool
	}{{3, true, true, true}, {2, true, true, false}, {1, true, false, false}, {2, true, false, true}, {1, false, false, true}, {0, false, false, false}} {
		if got := othersListen(c.users, c.joined, c.forward); got != c.want {
			t.Fatalf("%+v: %v", c, got)
		}
	}
}
