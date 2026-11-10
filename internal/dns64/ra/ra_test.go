package ra

import (
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestMarshalParse(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	dns := []netip.Addr{netip.MustParseAddr("fd00::2"), netip.MustParseAddr("2001:db8::2")}
	b := Ad{Other: true, DNS: dns, Domains: []string{"home.lan", "example.org."}, Lifetime: Lifetime, MAC: mac}.Marshal()
	if b[0] != typeRA || len(b)%8 != 0 {
		t.Fatalf("bad message % x", b)
	}
	if binary.BigEndian.Uint16(b[6:]) != 0 {
		t.Fatal("router lifetime must be 0 (no default router)")
	}
	r, ok := Parse(b)
	if !ok || r.Lifetime != 0 || r.Managed || !r.Other {
		t.Fatalf("parse %+v %v", r, ok)
	}
	if !slices.Equal(r.DNS, dns) || !slices.Equal(r.Domains, []string{"home.lan", "example.org"}) || len(r.Prefixes) != 0 {
		t.Fatalf("options %+v", r)
	}
	if r.Addresses() {
		t.Fatal("own RA announces no addresses")
	}
	// zuruecknehmen: Lifetime 0 -> keine DNS-Server mehr
	w := Ad{Withdraw: dns, Domains: []string{"home.lan"}}.Marshal()
	if r, ok := Parse(w); !ok || len(r.DNS) != 0 || len(r.Domains) != 0 {
		t.Fatalf("withdraw %+v", r)
	}
}

// RA eines Routers mit Praefix (SLAAC), DNS-Server und Default-Route.
func TestParseRouter(t *testing.T) {
	b := make([]byte, 16, 64)
	b[0], b[5] = typeRA, flagManaged
	binary.BigEndian.PutUint16(b[6:], 1800)
	pi := make([]byte, 32)
	pi[0], pi[1], pi[2], pi[3] = optPrefix, 4, 64, flagOnLink|flagAuto
	binary.BigEndian.PutUint32(pi[4:], 7200)
	p := netip.MustParseAddr("2001:db8:1:2::").As16()
	copy(pi[16:], p[:])
	b = append(b, pi...)
	b = appendRDNSS(b, []netip.Addr{netip.MustParseAddr("fe80::1")}, 600)
	r, ok := Parse(b)
	if !ok || r.Lifetime != 1800 || !r.Managed || r.Other || !r.Addresses() {
		t.Fatalf("router %+v %v", r, ok)
	}
	if len(r.Prefixes) != 1 || r.Prefixes[0].Prefix != netip.MustParsePrefix("2001:db8:1:2::/64") || !r.Prefixes[0].SLAAC || r.Prefixes[0].Valid != 7200 {
		t.Fatalf("prefix %+v", r.Prefixes)
	}
	if len(r.DNS) != 1 || r.DNS[0] != netip.MustParseAddr("fe80::1") {
		t.Fatalf("dns %v", r.DNS)
	}
	// kaputte Laenge, falscher Typ
	if _, ok := Parse(append(b[:16:16], optRDNSS, 0)); ok {
		t.Fatal("zero option length accepted")
	}
	if _, ok := Parse(solicit(nil)); ok {
		t.Fatal("RS parsed as RA")
	}
}

func TestStatusAndRouters(t *testing.T) {
	s := &Sender{Ifaces: []string{"eth0", "eth1"}}
	if st := s.Status(); len(st) != 2 || st[0].Iface != "eth0" || st[1].Iface != "eth1" {
		t.Fatalf("status %+v", st)
	}
	s.routers["eth0|fe80::1"] = Router{Iface: "eth0", Source: netip.MustParseAddr("fe80::1"), Lifetime: 1800, Other: true, LastSeen: time.Now()}
	s.routers["eth0|fe80::2"] = Router{Iface: "eth0", Source: netip.MustParseAddr("fe80::2"), Managed: true, LastSeen: time.Now()} // kein Default-Router
	s.routers["eth0|fe80::3"] = Router{Iface: "eth0", Source: netip.MustParseAddr("fe80::3"), Lifetime: 1800, LastSeen: time.Now().Add(-time.Hour)}
	if m, o := s.flags("eth0"); m || !o {
		t.Fatalf("flags from the default router: %v %v", m, o)
	}
	if r := s.Routers(); len(r) != 2 || r[0].Source != netip.MustParseAddr("fe80::1") {
		t.Fatalf("routers %+v", r)
	}
}
