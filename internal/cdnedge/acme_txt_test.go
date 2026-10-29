package cdnedge

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// txtServer startet einen Nameserver auf 127.0.0.1, dessen Antworten val liefert (leer = kein TXT).
func txtServer(t *testing.T, val func() string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if v := val(); v != "" {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10}, Txt: []string{v}})
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// Nameserver, die kurz nach dem Anlegen abwechselnd leer und den Wert liefern (ns1/ns2.ipv64.net, Test 2026-10-29),
// gelten erst nach txtStableRounds Runden hintereinander als sichtbar; eine Adresse ohne Wert haelt den Nameserver auf.
func TestWaitTXTFlapping(t *testing.T) {
	oldR, oldE := txtStableRounds, txtEvery
	txtEvery = 10 * time.Millisecond
	t.Cleanup(func() { txtStableRounds, txtEvery = oldR, oldE })
	var mu sync.Mutex
	n := 0
	flap := txtServer(t, func() string { // die ersten 6 Antworten wechseln, danach immer der Wert
		mu.Lock()
		defer mu.Unlock()
		n++
		if n <= 6 && n%2 == 0 {
			return ""
		}
		return "token"
	})
	ctx := context.Background()
	if err := waitTXTOn(ctx, [][]string{{flap}}, "_acme-challenge.example.org", []string{"token"}, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if n < 6+txtStableRounds {
		t.Fatalf("returned after %d answers while the record was still flapping", n)
	}
	mu.Unlock()

	// zweite Adresse desselben Nameservers ohne Wert (z. B. IPv6-Instanz noch alt): nicht sichtbar
	good := txtServer(t, func() string { return "token" })
	stale := txtServer(t, func() string { return "" })
	if err := waitTXTOn(ctx, [][]string{{good, stale}}, "_acme-challenge.example.org", []string{"token"}, 300*time.Millisecond); err == nil {
		t.Fatal("an address answering without the value must hold the nameserver back")
	}
	// nicht erreichbare Adresse zaehlt nicht
	if err := waitTXTOn(ctx, [][]string{{good, "127.0.0.1:1"}}, "_acme-challenge.example.org", []string{"token"}, 30*time.Second); err != nil {
		t.Fatalf("unreachable address must not count: %v", err)
	}
}
