package dns64

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/upstream"
)

func TestNormalizeServerAndReverseZone(t *testing.T) {
	for in, want := range map[string]string{
		"192.168.1.1":               "dns://192.168.1.1:53",
		"10.0.0.53:5353":            "dns://10.0.0.53:5353",
		"fd00::1":                   "dns://[fd00::1]:53",
		"[fd00::1]:5353":            "dns://[fd00::1]:5353",
		"dns://10.0.0.1":            "dns://10.0.0.1:53",
		"TLS://Dns.Firma.de":        "tls://dns.firma.de",
		"https://dns.firma.de":      "https://dns.firma.de/dns-query",
		"quic://dns.firma.de:8853/": "quic://dns.firma.de:8853",
	} {
		if got, err := normalizeServer(in); err != nil || got != want {
			t.Errorf("normalizeServer(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "firma", "ftp://x", "dns://x:99999", "https://user:pw@x/"} {
		if _, err := normalizeServer(bad); err == nil {
			t.Errorf("normalizeServer(%q) accepted", bad)
		}
	}
	// klassisches DNS als eigener Upstream (Wunsch: einfach 8.8.8.8 eintragen): nur mit IP, Port 53 als Standard
	for in, want := range map[string]string{"8.8.8.8": "dns://8.8.8.8:53", " dns://1.1.1.1 ": "dns://1.1.1.1:53", "192.168.1.1:5353": "dns://192.168.1.1:5353",
		"2001:4860:4860::8888": "dns://[2001:4860:4860::8888]:53", "[fd00::1]:5353": "dns://[fd00::1]:5353"} {
		s := upstream.Server{URL: in}
		if err := checkUpstream(&s); err != nil || s.URL != want || s.Name == "" || upstream.Proto(s.URL) != "dns" {
			t.Errorf("checkUpstream(%q) = %q %q %v; want %q", in, s.URL, s.Name, err, want)
		}
	}
	for _, bad := range []string{"dns://dns.google", "dns.google", "8.8.8.8:0", "https://", "[fe80::1%eth0]:0"} {
		if err := checkUpstream(&upstream.Server{URL: bad}); err == nil {
			t.Errorf("checkUpstream(%q) accepted", bad)
		}
	}
	if serverLabel("dns://192.168.1.1:53") != "192.168.1.1" || serverLabel("dns://[fd00::1]:5353") != "[fd00::1]:5353" {
		t.Error("serverLabel")
	}
	// Link-Local mit Zone: %25 in der URL, der Leser holt die Zone wieder heraus
	const zoned = "dns://[fe80::1%25eth0]:53"
	for _, in := range []string{"fe80::1%eth0", "[fe80::1%eth0]:53", zoned} {
		if got, err := normalizeServer(in); err != nil || got != zoned {
			t.Errorf("normalizeServer(%q) = %q, %v; want %q", in, got, err, zoned)
		}
		s := upstream.Server{URL: in}
		if err := checkUpstream(&s); err != nil || s.URL != zoned || s.Name != "[fe80::1%eth0]:53" {
			t.Errorf("checkUpstream(%q) = %q %q %v", in, s.URL, s.Name, err)
		}
	}
	if u, err := url.Parse(zoned); err != nil || u.Hostname() != "fe80::1%eth0" || u.Port() != "53" || upstream.Proto(zoned) != "dns" || serverLabel(zoned) != "fe80::1%eth0" {
		t.Errorf("zone lesen: %v %v", u, err)
	}
	for in, want := range map[string]string{"192.168.0.0/16": "168.192.in-addr.arpa", "10.0.0.0/8": "10.in-addr.arpa", "fd00::/8": "d.f.ip6.arpa", "2001:db8::/32": "8.b.d.0.1.0.0.2.ip6.arpa"} {
		if got, ok := reverseZone(in); !ok || got != want {
			t.Errorf("reverseZone(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
	if _, ok := reverseZone("192.168.0.0/20"); ok {
		t.Error("reverseZone accepted /20")
	}
}

// fakeDNS beantwortet jede A-Anfrage mit ip und zaehlt die Anfragen.
func fakeDNS(t *testing.T, ip string, n *atomic.Int32) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		n.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)}}
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func answerA(t *testing.T, addr, name string) (string, int) {
	t.Helper()
	r, err := query(addr, name)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			if a.Hdr.Name != dns.Fqdn(name) {
				t.Fatalf("%s: answer under %s", name, a.Hdr.Name)
			}
			return a.A.String(), r.Rcode
		}
	}
	return "", r.Rcode
}

// Weiterleitung lokaler und oeffentlicher Domains, Vorrang vor dem Router, SERVFAIL bei Ausfall, Umschreiben.
func TestForwardAndRewrite(t *testing.T) {
	m, port := testModule(t)
	ctx := context.Background()
	var hits atomic.Int32
	fwdAddr := fakeDNS(t, "10.9.9.9", &hits)
	f, err := m.AddForward(ctx, Forward{Domain: "Firma.Local.", Servers: []string{fwdAddr}})
	if err != nil || f.Domain != "firma.local" {
		t.Fatalf("add forward: %+v %v", f, err)
	}
	if _, err := m.AddForward(ctx, Forward{Domain: "intern.example.test", Servers: []string{fwdAddr}}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddForward(ctx, Forward{Domain: "firma.local", Servers: []string{"1.2.3.4"}}); err == nil {
		t.Fatal("duplicate domain accepted")
	}
	dead := freePort(t)
	if _, err := m.AddForward(ctx, Forward{Domain: "tot.test", Servers: []string{"127.0.0.1:" + strconv.Itoa(dead)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddRecord(ctx, Record{Name: "nas.home.lan", Type: "A", Value: "192.168.1.10"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddRewrite(ctx, Rewrite{Name: "nas.example.com", Target: "nas.home.lan"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddRewrite(ctx, Rewrite{Name: "*.alias.test", Target: "nas.example.com"}); err != nil {
		t.Fatal(err)
	}
	_, _ = m.AddRewrite(ctx, Rewrite{Name: "a.loop.test", Target: "b.loop.test"})
	_, _ = m.AddRewrite(ctx, Rewrite{Name: "b.loop.test", Target: "a.loop.test"})
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	if ip, _ := answerA(t, addr, "pc1.firma.local"); ip != "10.9.9.9" {
		t.Fatalf("local forward = %q", ip)
	}
	if ip, _ := answerA(t, addr, "db.intern.example.test"); ip != "10.9.9.9" {
		t.Fatalf("public forward = %q", ip)
	}
	if hits.Load() != 2 {
		t.Fatalf("forward server hits = %d", hits.Load())
	}
	if _, rc := answerA(t, addr, "x.tot.test"); rc != dns.RcodeServerFailure {
		t.Fatalf("dead forward rcode = %s", dns.RcodeToString[rc])
	}
	if ip, _ := answerA(t, addr, "nas.example.com"); ip != "192.168.1.10" {
		t.Fatalf("rewrite = %q", ip)
	}
	if ip, _ := answerA(t, addr, "tv.alias.test"); ip != "192.168.1.10" {
		t.Fatalf("wildcard rewrite chain = %q", ip)
	}
	if _, rc := answerA(t, addr, "a.loop.test"); rc != dns.RcodeServerFailure {
		t.Fatalf("rewrite loop rcode = %s", dns.RcodeToString[rc])
	}

	// ausgeschaltet: lokale Namen wieder an den Router (Test-Router kennt pc1.firma.local nicht)
	if err := m.SetForwardEnabled(ctx, f.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, rc := answerA(t, addr, "pc1.firma.local"); rc != dns.RcodeNameError {
		t.Fatalf("after disable rcode = %s", dns.RcodeToString[rc])
	}
	if res, err := m.TestForward(ctx, f.ID); err != nil || !res.OK {
		t.Fatalf("test forward: %+v %v", res, err)
	}
	views := m.forwardViews([]Forward{f})
	if len(views) != 1 || len(views[0].State) != 1 || views[0].State[0].Label != fwdAddr {
		t.Fatalf("views = %+v", views)
	}
}
