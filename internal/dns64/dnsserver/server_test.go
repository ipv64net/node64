package dnsserver

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestIsLocalName(t *testing.T) {
	local := []string{"nas", "drucker.fritz.box", "fritz.box", "pi.lan", "tv.home.arpa",
		"5.1.168.192.in-addr.arpa", "1.0.20.172.in-addr.arpa", "4.3.2.10.in-addr.arpa"}
	public := []string{"example.com", "fritz.box.example.com", "1.0.15.172.in-addr.arpa",
		"8.8.8.8.in-addr.arpa", "lan.example.org"}
	for _, n := range local {
		if !isLocalName(n) {
			t.Errorf("isLocalName(%q) = false, want true", n)
		}
	}
	for _, n := range public {
		if isLocalName(n) {
			t.Errorf("isLocalName(%q) = true, want false", n)
		}
	}
}

func TestACL(t *testing.T) {
	a := &clientACL{}
	a.refresh()
	for _, s := range []string{"192.168.1.10", "10.0.0.1", "172.20.0.5", "127.0.0.1", "fd00::1", "fe80::1", "100.100.1.1"} {
		if !a.allowed(netip.MustParseAddr(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
	if a.allowed(netip.MustParseAddr("8.8.8.8")) {
		t.Error("8.8.8.8 should be refused")
	}
}

func TestBlockedMsg(t *testing.T) {
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS} {
		req := new(dns.Msg)
		req.SetQuestion("ads.example.com.", qt)
		resp := blockedMsg(req)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("rcode %d", resp.Rcode)
		}
		wantAnswers := 1
		if qt == dns.TypeHTTPS {
			wantAnswers = 0
		}
		if len(resp.Answer) != wantAnswers {
			t.Fatalf("type %d: %d answers, want %d", qt, len(resp.Answer), wantAnswers)
		}
		if _, err := resp.Pack(); err != nil {
			t.Fatal(err)
		}
	}
}
