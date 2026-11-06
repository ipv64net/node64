package localnet

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

// fakeMDNS: Geraete, die einmalige Anfragen wie mDNS-Responder beantworten (Cache-Flush-Bit, lange TTL, Name in
// anderer Schreibweise, fremde Eintraege). Antworten kommen vom Port des Ziels; "otherport.local" beantwortet ein
// Socket mit anderem Port, "badid.local" eine falsche Kennung - beides muss verworfen werden.
func fakeMDNS(t *testing.T) *atomic.Int64 {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close(); other.Close() })
	old := mdnsDst
	mdnsDst = pc.LocalAddr().(*net.UDPAddr)
	t.Cleanup(func() { mdnsDst = old })
	var n atomic.Int64
	rr := func(s string) dns.RR {
		r, err := dns.NewRR(s)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	go func() {
		buf := make([]byte, 2000)
		for {
			k, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			n.Add(1)
			var q dns.Msg
			if q.Unpack(buf[:k]) != nil || len(q.Question) != 1 {
				continue
			}
			name, qt := q.Question[0].Name, q.Question[0].Qtype
			reply := func(conn *net.UDPConn, id uint16, rrs ...dns.RR) {
				m := new(dns.Msg)
				m.SetReply(&q)
				m.Id = id
				m.Answer = rrs
				b, _ := m.Pack()
				_, _ = conn.WriteToUDP(b, from)
			}
			switch {
			case name == "drucker.local." && qt == dns.TypeA:
				a := rr("DRUCKER.local. 120 IN A 192.168.178.40")
				a.Header().Class |= 1 << 15
				reply(pc, q.Id, a, rr("other.local. 120 IN A 192.168.178.41"))
			case name == "nsec.local." && qt == dns.TypeAAAA:
				reply(pc, q.Id, rr("nsec.local. 120 IN NSEC nsec.local. A"))
			case name == "slow.local.":
				time.Sleep(100 * time.Millisecond)
				reply(pc, q.Id, rr("slow.local. 120 IN A 192.168.178.42"))
			case name == "badid.local.":
				reply(pc, q.Id+1, rr("badid.local. 120 IN A 6.6.6.6"))
			case name == "otherport.local.":
				reply(other, q.Id, rr("otherport.local. 120 IN A 6.6.6.6"))
			case name == "50.0.0.127.in-addr.arpa." && qt == dns.TypePTR:
				reply(pc, q.Id, rr("50.0.0.127.in-addr.arpa. 120 IN PTR macbook.local."))
			case name == "_ipp._tcp.local." && qt == dns.TypePTR: // zwei Drucker, je eine Antwort
				reply(pc, q.Id, rr("_ipp._tcp.local. 120 IN PTR eins._ipp._tcp.local."))
				reply(pc, q.Id, rr("_ipp._tcp.local. 120 IN PTR zwei._ipp._tcp.local."))
			case name == mdnsServices:
				reply(pc, q.Id, rr(mdnsServices+" 120 IN PTR _ipp._tcp.local."))
			default: // mDNS: wer nichts weiss, schweigt
			}
		}
	}()
	return &n
}

func newTestResolver() *Resolver { return New("", slog.New(slog.NewTextHandler(io.Discard, nil))) }

func ask(r *Resolver, ctx context.Context, name string, t uint16) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(name, t)
	return r.ExchangeMDNS(ctx, req)
}

func TestMDNSBridge(t *testing.T) {
	sent := fakeMDNS(t)
	r := newTestResolver()
	ctx := context.Background()
	if ask(r, ctx, "drucker.local.", dns.TypeA) != nil {
		t.Fatal("off: no mDNS")
	}
	r.SetMDNS(true)
	resp := ask(r, ctx, "drucker.local.", dns.TypeA)
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("answer: %v", resp)
	}
	a := resp.Answer[0].(*dns.A)
	if a.A.String() != "192.168.178.40" || a.Hdr.Class != dns.ClassINET || a.Hdr.Ttl > 10 || a.Hdr.Name != "drucker.local." {
		t.Fatalf("record: %v", a)
	}
	n := sent.Load()
	if ask(r, ctx, "drucker.local.", dns.TypeA) == nil || sent.Load() != n {
		t.Fatal("second answer must come from the cache")
	}
	// den Namen gibt es (A), AAAA nicht: NODATA statt NXDOMAIN
	if m := ask(r, ctx, "drucker.local.", dns.TypeAAAA); m == nil || m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 {
		t.Fatalf("known name without AAAA must be NODATA: %v", m)
	}
	if m := ask(r, ctx, "nsec.local.", dns.TypeAAAA); m == nil || m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 {
		t.Fatalf("NSEC must be NODATA: %v", m)
	}
	// unbekannt: nil, und das Fehlen wird gemerkt
	if ask(r, ctx, "gibtsnicht.local.", dns.TypeA) != nil {
		t.Fatal("miss")
	}
	n = sent.Load()
	if ask(r, ctx, "gibtsnicht.local.", dns.TypeA) != nil || sent.Load() != n {
		t.Fatal("miss must be cached")
	}
	// gefaelschte Antworten: falsche Kennung, falscher Port
	if ask(r, ctx, "badid.local.", dns.TypeA) != nil || ask(r, ctx, "otherport.local.", dns.TypeA) != nil {
		t.Fatal("answers with wrong id or port must be dropped")
	}
	// Absender ausserhalb des eigenen Netzes
	res, _ := mdnsQuery(ctx, dns.Question{Name: "drucker.local.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, true, func(netip.Addr) bool { return false })
	if len(res.rrs) != 0 {
		t.Fatal("answers from outside the own network must be dropped")
	}
	// abgelaufener Kontext des Aufrufers: eigene Wartezeit, kein leerer Treffer
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if m := ask(r, cctx, "slow.local.", dns.TypeA); m == nil || len(m.Answer) != 1 {
		t.Fatalf("own budget: %v", m)
	}
	// Rueckwaertssuche nur fuer Adressen im eigenen Netz
	if p := r.mdnsPTR(ctx, "50.0.0.127.in-addr.arpa."); p != "macbook.local" {
		t.Fatalf("ptr: %q", p)
	}
	n = sent.Load()
	if ask(r, ctx, "5.113.0.203.in-addr.arpa.", dns.TypePTR) != nil || sent.Load() != n {
		t.Fatal("reverse lookups outside the own networks must not be sent")
	}
	// gemeinsame Eintraege: alle Geraete
	if m := ask(r, ctx, "_ipp._tcp.local.", dns.TypePTR); m == nil || len(m.Answer) != 2 {
		t.Fatalf("shared records: %v", m)
	}
	res, _ = mdnsQuery(ctx, dns.Question{Name: mdnsServices, Qtype: dns.TypePTR, Qclass: dns.ClassINET}, false, r.onLink)
	if res.from != 1 {
		t.Fatalf("probe: %d", res.from)
	}
	if !MDNSName("drucker.local") || MDNSName("nas.fritz.box") {
		t.Fatal("MDNSName")
	}
}

// gleiche Anfragen gleichzeitig: eine Anfrage ins Netz; Bremse: darueber nichts senden und nichts merken
func TestMDNSFlightAndRate(t *testing.T) {
	sent := fakeMDNS(t)
	r := newTestResolver()
	r.SetMDNS(true)
	ctx := context.Background()
	n := sent.Load()
	var wg sync.WaitGroup
	var ok atomic.Int64
	for range 5 {
		wg.Go(func() {
			if m := ask(r, ctx, "slow.local.", dns.TypeA); m != nil && len(m.Answer) == 1 {
				ok.Add(1)
			}
		})
	}
	wg.Wait()
	if sent.Load()-n != 1 || ok.Load() != 5 {
		t.Fatalf("flight: sent %d, ok %d", sent.Load()-n, ok.Load())
	}
	r.md.lim = rate.NewLimiter(0, 1)
	n = sent.Load()
	_ = ask(r, ctx, "eins.local.", dns.TypeA)
	if ask(r, ctx, "zwei.local.", dns.TypeA) != nil || sent.Load()-n != 1 {
		t.Fatalf("rate: sent %d", sent.Load()-n)
	}
	r.md.lim = rate.NewLimiter(rate.Inf, 1)
	if _ = ask(r, ctx, "zwei.local.", dns.TypeA); sent.Load()-n != 2 {
		t.Fatal("a throttled miss must not be cached")
	}
}

func TestLearnDomain(t *testing.T) {
	r := newTestResolver()
	r.IsBuiltin = func(s string) bool { return s == "lan" }
	priv, pub := netip.MustParseAddr("192.168.1.20"), netip.MustParseAddr("8.8.8.8")
	r.learnDomain(priv, "nas.zuhause.")
	if r.LearnedLocal("nas.zuhause") {
		t.Fatal("only with the mDNS bridge on")
	}
	r.SetMDNS(true)
	var saved atomic.Int64
	r.SetOnDomains(func(map[string]time.Time) { saved.Add(1) })
	r.learnDomain(priv, "nas.zuhause.")
	r.learnDomain(priv, "pc.home.example.com")    // oeffentliche Domain
	r.learnDomain(priv, "nas.myhost.duckdns.org") // privater Teil der Public Suffix List
	r.learnDomain(priv, "tv.fritz.box")           // .box gibt es im Internet
	r.learnDomain(priv, "nas.lan")                // kennt DNS64 schon
	r.learnDomain(pub, "x.intern")                // oeffentliche Adresse
	r.learnDomain(priv, "android")                // ohne Endung
	if !r.LearnedLocal("nas.zuhause") || !r.LearnedLocal("zuhause") || r.LearnedLocal("x.intern") || r.LearnedLocal("myhost.duckdns.org") {
		t.Fatalf("learned: %v", r.Domains())
	}
	if d := r.Domains(); len(d) != 1 || d[0] != "zuhause" || saved.Load() != 1 {
		t.Fatalf("domains: %v, saved %d", d, saved.Load())
	}
	// voll: die am laengsten nicht gesehene weicht
	r.md.mu.Lock()
	r.md.domains["zuhause"] = time.Now().Add(-time.Hour)
	r.md.mu.Unlock()
	for _, s := range []string{"a", "b", "c", "d"} {
		r.learnDomain(priv, "x."+s+"-heim")
	}
	if d := r.Domains(); len(d) != maxDomains || r.LearnedLocal("zuhause") {
		t.Fatalf("eviction: %v", d)
	}
	// abgelaufen beim Laden
	r.LoadDomains(map[string]time.Time{"alt": time.Now().Add(-domainTTL - time.Hour), "neu": time.Now()})
	if d := r.Domains(); len(d) != 1 || d[0] != "neu" {
		t.Fatalf("load: %v", d)
	}
	// aus der Antwort des Routers auf eine Rueckwaertssuche
	r.LearnPTR("20.1.168.192.in-addr.arpa.", "drucker.heimnetz.")
	if !r.LearnedLocal("drucker.heimnetz") {
		t.Fatalf("LearnPTR: %v", r.Domains())
	}
	r.SetMDNS(false)
	if r.LearnedLocal("drucker.heimnetz") || len(r.Domains()) != 0 {
		t.Fatal("off: nothing learned applies")
	}
}

func TestArpaAddr(t *testing.T) {
	for in, want := range map[string]string{
		"20.1.168.192.in-addr.arpa.": "192.168.1.20",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.": "fe80::1",
	} {
		if a, ok := arpaAddr(in); !ok || a.String() != want {
			t.Fatalf("%s: %v %v", in, a, ok)
		}
	}
	if _, ok := arpaAddr("example.com."); ok {
		t.Fatal("no arpa")
	}
}
