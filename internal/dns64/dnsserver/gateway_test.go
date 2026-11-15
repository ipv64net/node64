package dnsserver

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/localnet"
)

// Docker-Bridge-Netz: Anfragen ueber die Gateway-Adresse haben eine unbekannte Herkunft (auch Internet) - abgewiesen
// und gezaehlt, ausser das Gateway steht ausdruecklich in den weiteren Client-Netzen; DoH/DoQ nehmen die Verbindung
// an (Pruefnamen), Answer weist ab (Review WE-3).
func TestGatewayOrigin(t *testing.T) {
	gw := netip.MustParseAddr("172.17.0.1")
	defer localnet.OriginForTest(true, gw)()
	s := &Server{}
	s.acl = newClientACL(nil)
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	if resp := s.Answer(q, gw, "udp"); resp.Rcode != dns.RcodeRefused {
		t.Fatalf("gateway answered: %s", dns.RcodeToString[resp.Rcode])
	}
	if s.Allowed(gw) || !s.Admit(gw) {
		t.Fatal("gateway allowed / not admitted for DoH")
	}
	if r := s.Refused(); r.Gateway != 2 || r.LastIP != gw {
		t.Fatalf("refused: %+v", r)
	}
	if !s.Allowed(netip.MustParseAddr("172.17.0.5")) || !s.Allowed(netip.MustParseAddr("192.168.1.20")) {
		t.Fatal("other private clients refused")
	}
	// ausdruecklich eingetragen: erlaubt
	s.acl = newClientACL([]netip.Prefix{netip.MustParsePrefix("172.17.0.1/32")})
	if !s.Allowed(gw) || s.Refused().Gateway != 0 {
		t.Fatal("listed gateway refused")
	}
	// ohne Bridge-Netz ist dieselbe Adresse ein normaler privater Client
	defer localnet.OriginForTest(false, netip.Addr{})()
	s.acl = newClientACL(nil)
	if !s.Allowed(gw) {
		t.Fatal("private address refused outside the bridge network")
	}
}
