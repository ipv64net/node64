package localnet

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeMDNS: ein Geraet, das einmalige Anfragen wie ein mDNS-Responder beantwortet (Cache-Flush-Bit, lange TTL, Name in
// anderer Schreibweise, dazu ein fremder Eintrag).
func fakeMDNS(t *testing.T) *atomic.Int64 {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	old := mdnsDst
	mdnsDst = pc.LocalAddr().(*net.UDPAddr)
	t.Cleanup(func() { mdnsDst = old })
	var n atomic.Int64
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
			m := new(dns.Msg)
			m.SetReply(&q)
			name := q.Question[0].Name
			switch {
			case name == "drucker.local." && q.Question[0].Qtype == dns.TypeA:
				a, _ := dns.NewRR("DRUCKER.local. 120 IN A 192.168.178.40")
				a.Header().Class |= 1 << 15
				other, _ := dns.NewRR("other.local. 120 IN A 192.168.178.41")
				m.Answer = []dns.RR{a, other}
			case name == "50.178.168.192.in-addr.arpa." && q.Question[0].Qtype == dns.TypePTR:
				p, _ := dns.NewRR("50.178.168.192.in-addr.arpa. 120 IN PTR macbook.local.")
				m.Answer = []dns.RR{p}
			case name == mdnsServices:
				p, _ := dns.NewRR(mdnsServices + " 120 IN PTR _ipp._tcp.local.")
				m.Answer = []dns.RR{p}
			default:
				continue // mDNS: wer nichts weiss, schweigt
			}
			b, _ := m.Pack()
			_, _ = pc.WriteToUDP(b, from)
		}
	}()
	return &n
}

func TestMDNSBridge(t *testing.T) {
	sent := fakeMDNS(t)
	r := New("", slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()
	req := new(dns.Msg)
	req.SetQuestion("drucker.local.", dns.TypeA)
	if r.ExchangeMDNS(ctx, req) != nil {
		t.Fatal("off: no mDNS")
	}
	r.SetMDNS(true)
	resp := r.ExchangeMDNS(ctx, req)
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("answer: %v", resp)
	}
	a := resp.Answer[0].(*dns.A)
	if a.A.String() != "192.168.178.40" || a.Hdr.Class != dns.ClassINET || a.Hdr.Ttl > 10 || a.Hdr.Name != "drucker.local." || resp.Id != req.Id {
		t.Fatalf("record: %v", a)
	}
	n := sent.Load()
	if r.ExchangeMDNS(ctx, req) == nil || sent.Load() != n {
		t.Fatal("second answer must come from the cache")
	}
	// unbekannt: nil, schnell, und das Fehlen wird gemerkt
	miss := new(dns.Msg)
	miss.SetQuestion("gibtsnicht.local.", dns.TypeA)
	start := time.Now()
	if r.ExchangeMDNS(ctx, miss) != nil || time.Since(start) > time.Second {
		t.Fatal("miss")
	}
	n = sent.Load()
	if r.ExchangeMDNS(ctx, miss) != nil || sent.Load() != n {
		t.Fatal("miss must be cached")
	}
	if st := r.MDNS(); !st.On || st.Queries != 2 || st.Answered != 1 {
		t.Fatalf("status: %+v", st)
	}
	// Geraetename ohne Router: Rueckwaertssuche per mDNS
	if names := r.Hostnames(ctx, []string{"192.168.178.50"}); names["192.168.178.50"] != "macbook.local" {
		t.Fatalf("hostnames: %v", names)
	}
	// Pruefung: wie viele Geraete antworten
	_, from, err := mdnsQuery(ctx, dns.Question{Name: mdnsServices, Qtype: dns.TypePTR, Qclass: dns.ClassINET}, false)
	if err != nil || from != 1 {
		t.Fatalf("probe: %d %v", from, err)
	}
	if !MDNSName("drucker.local") || MDNSName("nas.fritz.box") {
		t.Fatal("MDNSName")
	}
}

func TestLearnDomain(t *testing.T) {
	r := New("", slog.New(slog.NewTextHandler(io.Discard, nil)))
	priv, pub := netip.MustParseAddr("192.168.1.20"), netip.MustParseAddr("8.8.8.8")
	r.learnDomain(priv, "nas.zuhause.")
	r.learnDomain(priv, "pc.home.example.com") // oeffentliche Domain: nie lernen
	r.learnDomain(pub, "x.intern")             // oeffentliche Adresse: nicht
	r.learnDomain(priv, "android")             // ohne Endung
	r.learnDomain(priv, "drucker.local")
	if !r.LearnedLocal("nas.zuhause") || !r.LearnedLocal("zuhause") || r.LearnedLocal("x.intern") || r.LearnedLocal("www.example.com") {
		t.Fatalf("learned: %v", r.Domains())
	}
	if d := r.Domains(); len(d) != 1 || d[0] != "zuhause" {
		t.Fatalf("domains: %v", d)
	}
	for _, s := range []string{"a", "b", "c", "d", "e"} {
		r.learnDomain(priv, "x."+s+"-heim")
	}
	if len(r.Domains()) != maxDomains {
		t.Fatalf("limit: %v", r.Domains())
	}
}
