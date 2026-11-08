package certs

import (
	"net"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

// fakeSOA beantwortet SOA-Fragen nach festen Zonen (Name -> zustaendige Zone; "" = nicht vorhanden).
func fakeSOA(t *testing.T, zones []string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		name := strings.ToLower(q.Question[0].Name)
		zone := ""
		for _, z := range zones { // laengste passende Zone
			if (name == z || strings.HasSuffix(name, "."+z)) && len(z) > len(zone) {
				zone = z
			}
		}
		soa := &dns.SOA{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns." + zone, Mbox: "h." + zone, Serial: 1, Refresh: 60, Retry: 60, Expire: 60, Minttl: 60}
		switch {
		case zone == "":
			r.Rcode = dns.RcodeNameError
		case name == zone && q.Question[0].Qtype == dns.TypeSOA:
			r.Answer = []dns.RR{soa}
		case strings.HasPrefix(name, "_acme-challenge."):
			r.Rcode, r.Ns = dns.RcodeNameError, []dns.RR{soa}
		default:
			r.Ns = []dns.RR{soa} // Name vorhanden, kein SOA: NODATA
		}
		_ = w.WriteMsg(r)
	})
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// node64#45: Der lokale Resolver hat eine eigene Zone sub.domain.test (Split-DNS), oeffentlich gibt es nur
// domain.test. lego darf die Zone nicht beim lokalen Resolver bestimmen.
func TestLegoDNSZoneNotFromSplitDNS(t *testing.T) {
	local := fakeSOA(t, []string{"sub.domain.test.", "domain.test."})
	public := fakeSOA(t, []string{"domain.test."})
	fqdn := "_acme-challenge.sub.domain.test."

	// so war es: lego fragt den System-Resolver und nimmt dessen Teil-Zone
	if z, err := dns01.FindZoneByFqdnCustom(fqdn, []string{local}); err != nil || z != "sub.domain.test." {
		t.Fatalf("Ausgangslage: zone %q err %v", z, err)
	}

	f, addr, err := startLegoDNS(func() []checkPath { return []checkPath{{Name: "fake", plain: public}} }, []string{local})
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()
	if z, err := dns01.FindZoneByFqdnCustom("_acme-challenge.x.sub.domain.test.", []string{addr}); err != nil || z != "domain.test." {
		t.Fatalf("ueber den Weiterleiter: zone %q err %v", z, err)
	}

	// kein oeffentlicher Resolver erreichbar: wie bisher der System-Resolver
	dead, _ := net.ListenPacket("udp", "127.0.0.1:0")
	deadAddr := dead.LocalAddr().String()
	_ = dead.Close()
	f2, addr2, err := startLegoDNS(func() []checkPath { return []checkPath{{Name: "dead", plain: deadAddr}} }, []string{local})
	if err != nil {
		t.Fatal(err)
	}
	defer f2.close()
	if z, err := dns01.FindZoneByFqdnCustom("_acme-challenge.y.domain.test.", []string{addr2}); err != nil || z != "domain.test." {
		t.Fatalf("Rueckfall System: zone %q err %v", z, err)
	}

	// TCP auf demselben Port (lego fragt bei abgeschnittener Antwort per TCP)
	c := &dns.Client{Net: "tcp"}
	q := new(dns.Msg)
	q.SetQuestion("domain.test.", dns.TypeSOA)
	if r, _, err := c.Exchange(q, addr); err != nil || len(r.Answer) != 1 {
		t.Fatalf("tcp: %v %v", r, err)
	}
}

func TestSetLegoNameservers(t *testing.T) {
	if err := setLegoNameservers(); err == nil {
		t.Fatal("leer muss scheitern")
	}
	if err := setLegoNameservers("127.0.0.1"); err == nil {
		t.Fatal("ohne Port muss scheitern")
	}
}
