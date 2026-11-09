package certs

import (
	"context"
	"errors"
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

// fakeWild: Zonen example.test, dyn.test, other.test mit Wildcard-CNAMEs (*.<parent> -> Ziel) und expliziten CNAMEs.
// Wie bei Cloudflare liefert der Wildcard den CNAME fuer jeden Namen unter parent, der nicht selbst eingetragen ist.
func fakeWild(t *testing.T, wild, explicit map[string]string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	zones := []string{"example.test.", "dyn.test.", "other.test."}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		name := strings.ToLower(q.Question[0].Name)
		cname := func(target string) {
			r.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: target}}
		}
		if tg := explicit[name]; tg != "" {
			cname(tg)
			_ = w.WriteMsg(r)
			return
		}
		for parent, tg := range wild {
			if strings.HasSuffix(name, "."+parent) {
				cname(tg)
				_ = w.WriteMsg(r)
				return
			}
		}
		zone := ""
		for _, z := range zones {
			if name == z || strings.HasSuffix(name, "."+z) {
				zone = z
			}
		}
		soa := &dns.SOA{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns." + zone, Mbox: "h." + zone, Serial: 1, Refresh: 60, Retry: 60, Expire: 60, Minttl: 60}
		_, isParent := wild[name]
		switch {
		case zone == "":
			r.Rcode = dns.RcodeNameError
		case name == zone && q.Question[0].Qtype == dns.TypeSOA:
			r.Answer = []dns.RR{soa}
		case name == zone || isParent || name == "home.dyn.test.":
			r.Ns = []dns.RR{soa} // NODATA
		default:
			r.Rcode, r.Ns = dns.RcodeNameError, []dns.RR{soa}
		}
		_ = w.WriteMsg(r)
	})
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// legoFQDN: wo lego den TXT-Record fuer domain setzt (folgt CNAMEs ueber seine rekursiven Nameserver) und die Zone,
// die es dafuer beim Anbieter sucht.
func legoFQDN(t *testing.T, ns, domain string) (fqdn, zone string) {
	t.Helper()
	if err := setLegoNameservers(ns); err != nil {
		t.Fatal(err)
	}
	fqdn = dns01.GetChallengeInfo(domain, "ka").EffectiveFQDN
	zone, err := dns01.FindZoneByFqdnCustom(fqdn, []string{ns})
	if err != nil {
		t.Fatalf("%s: zone: %v", fqdn, err)
	}
	return fqdn, zone
}

func restoreLegoNameservers(t *testing.T) {
	t.Cleanup(func() {
		if sys := systemNameservers(); len(sys) > 0 {
			_ = setLegoNameservers(sys...)
		}
	})
}

// Forum 5036: *.lab.example.test zeigt per CNAME nach Hause (DynDNS home.dyn.test). lego folgte dem Wildcard auch fuer
// _acme-challenge.lab.example.test und suchte die Zone dyn.test beim Anbieter ("failed to find zone home64.de").
func TestLegoDNSWildcardCNAME(t *testing.T) {
	restoreLegoNameservers(t)
	srv := fakeWild(t, map[string]string{"lab.example.test.": "home.dyn.test."}, nil)

	// so war es: lego landet in der Zone des Ziels
	if fqdn, zone := legoFQDN(t, srv, "lab.example.test"); fqdn != "home.dyn.test." || zone != "dyn.test." {
		t.Fatalf("Ausgangslage: %s in %s", fqdn, zone)
	}

	f, addr, err := startLegoDNS(func() []checkPath { return []checkPath{{Name: "fake", plain: srv}} }, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()
	if fqdn, zone := legoFQDN(t, addr, "lab.example.test"); fqdn != "_acme-challenge.lab.example.test." || zone != "example.test." {
		t.Fatalf("ueber den Weiterleiter: %s in %s", fqdn, zone)
	}
	// andere Namen unter dem Wildcard behalten ihren CNAME
	c := new(dns.Client)
	q := new(dns.Msg)
	q.SetQuestion("www.lab.example.test.", dns.TypeCNAME)
	if r, _, err := c.Exchange(q, addr); err != nil || len(r.Answer) != 1 {
		t.Fatalf("www: %v %v", r, err)
	}
}

// Explizite CNAMEs von _acme-challenge (Delegation auf eine andere Zone, auch neben einem Wildcard mit anderem Ziel)
// verfolgt lego ueber den Weiterleiter weiter.
func TestLegoDNSExplicitCNAME(t *testing.T) {
	restoreLegoNameservers(t)
	srv := fakeWild(t, map[string]string{"ex2.example.test.": "home.dyn.test."}, map[string]string{
		"_acme-challenge.ex1.example.test.": "ex1.acme.other.test.",
		"_acme-challenge.ex2.example.test.": "ex2.acme.other.test.",
		"_acme-challenge.ex3.example.test.": "_acme-challenge.ex3.other.test.",
	})
	f, addr, err := startLegoDNS(func() []checkPath { return []checkPath{{Name: "fake", plain: srv}} }, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()
	for _, n := range []string{"ex1", "ex2", "ex3"} {
		want := n + ".acme.other.test."
		if n == "ex3" {
			want = "_acme-challenge.ex3.other.test."
		}
		if fqdn, zone := legoFQDN(t, addr, n+".example.test"); fqdn != want || zone != "other.test." {
			t.Fatalf("%s: %s in %s", n, fqdn, zone)
		}
	}
}

// Die eigene Pruefung fragt denselben Namen wie lego: Wildcard-CNAME nicht verfolgt, explizite schon, Fehler der
// Gegenprobe = verfolgen.
func TestChallengeFQDNWildcard(t *testing.T) {
	probeErr := false
	m := &Manager{cnameOf: func(_ context.Context, name string) (string, error) {
		switch {
		case probeErr && strings.HasPrefix(name, "_n64-"):
			return "", errors.New("timeout")
		case name == "_acme-challenge.ex.fqdn.test":
			return "ex.acme.other.fqdn.", nil
		case strings.HasSuffix(name, ".lab.fqdn.test"), strings.HasSuffix(name, ".ex.fqdn.test"):
			return "home.dyn.test.", nil
		}
		return "", nil
	}}
	ctx := context.Background()
	if got := m.challengeFQDN(ctx, "lab.fqdn.test"); got != "_acme-challenge.lab.fqdn.test" {
		t.Fatalf("wildcard: %s", got)
	}
	if got := m.challengeFQDN(ctx, "ex.fqdn.test"); got != "ex.acme.other.fqdn" {
		t.Fatalf("explizit neben Wildcard: %s", got)
	}
	probeErr = true
	if got := m.challengeFQDN(ctx, "sub.lab.fqdn.test"); got != "home.dyn.test" {
		t.Fatalf("Gegenprobe gescheitert: %s", got)
	}
	probeErr = false
	if got := m.challengeFQDN(ctx, "sub.lab.fqdn.test"); got != "_acme-challenge.sub.lab.fqdn.test" {
		t.Fatalf("Fehler nicht gemerkt, jetzt wildcard: %s", got)
	}
}
