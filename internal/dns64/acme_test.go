package dns64

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// waitTXT wartet, bis der Nameserver den TXT-Record ausliefert (ipv64 schreibt ihn erst nach einigen Sekunden).
func TestWaitTXT(t *testing.T) {
	var asked atomic.Int32
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if asked.Add(1) >= 2 && r.Question[0].Name == "_acme-challenge.dns.home.ipv64.net." { // erst beim zweiten Mal da
			m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"tok"}}}
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()
	old := lookupNS
	lookupNS = func(context.Context, string) ([]string, error) { return []string{pc.LocalAddr().String()}, nil }
	defer func() { lookupNS = old }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	if err := waitTXT(ctx, "_acme-challenge.dns.home.ipv64.net", "tok", "home.ipv64.net"); err != nil {
		t.Fatal(err)
	}
	if asked.Load() < 2 || time.Since(start) < 2*time.Second {
		t.Fatalf("must poll until the record is there (asked %d)", asked.Load())
	}
	// falscher Wert: Abbruch ueber den Kontext
	ctx2, cancel2 := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel2()
	if err := waitTXT(ctx2, "_acme-challenge.dns.home.ipv64.net", "other", "home.ipv64.net"); err == nil {
		t.Fatal("wrong value accepted")
	}
}

func TestACMEName(t *testing.T) {
	if acmeName(config{ACMEDomain: "home.ipv64.net", ACMEPrefix: "dns"}) != "dns.home.ipv64.net" || acmeName(config{ACMEDomain: "home.ipv64.net"}) != "home.ipv64.net" || acmeName(config{}) != "" {
		t.Fatal("acmeName")
	}
	m, _ := testModule(t)
	ctx := context.Background()
	c := m.loadConfig(ctx)
	c.CertMode, c.ACMEDomain = certACME, ""
	if err := m.saveConfig(ctx, c); err == nil {
		t.Fatal("acme without domain accepted")
	}
	c.ACMEDomain, c.ACMEPrefix = "home.ipv64.net", "_acme-challenge"
	if err := m.saveConfig(ctx, c); err == nil {
		t.Fatal("prefix with underscore accepted")
	}
	c.ACMEPrefix = "dns"
	if err := m.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	// ohne Zertifikat: Dienste laufen mit der eigenen CA, der Name steht mit im Zertifikat
	crt, names, err := m.serverCert(m.loadConfig(ctx))
	if err != nil || crt.Certificate == nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range names {
		found = found || n == "dns.home.ipv64.net"
	}
	if !found {
		t.Fatalf("fallback certificate names = %v", names)
	}
	// ohne Nutzungsbedingungen startet kein Abruf
	if err := m.obtain(ctx); err == nil {
		t.Fatal("obtain without accepted terms")
	}
}
