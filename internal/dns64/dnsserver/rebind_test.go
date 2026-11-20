package dnsserver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/cache"
	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/querylog"
	"github.com/ipv64net/node64/internal/dns64/upstream"
)

// Rebinding-Schutz: Adressen aus dem eigenen Netz fallen aus Antworten des Internets, oeffentliche bleiben; Namen mit
// Ausnahme und eigene Freigaben behalten sie (Review DN-3).
func TestRebind(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rr := func(s string) dns.RR { r, _ := dns.NewRR(s); return r }
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		n := r.Question[0].Name
		switch r.Question[0].Qtype {
		case dns.TypeA:
			m.Answer = []dns.RR{rr(n + " 60 IN A 192.168.1.1"), rr(n + " 60 IN A 203.0.113.5"), rr(n + " 60 IN A 0.0.0.0")}
		case dns.TypeAAAA:
			m.Answer = []dns.RR{rr(n + " 60 IN AAAA fd00::1"), rr(n + " 60 IN AAAA fe80::1"), rr(n + " 60 IN AAAA ::ffff:127.0.0.1")}
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, _ := filter.LoadAllowlist(filepath.Join(dir, "allow.txt"))
	if _, err := a.Add("released.example"); err != nil {
		t.Fatal(err)
	}
	fm, err := filter.NewManager(filepath.Join(dir, "lists"), nil, 0, a, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	st, err := querylog.Open(filepath.Join(dir, "q.db"), time.Hour, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go st.Run(ctx)
	defer st.CloseNow()
	up := upstream.New([]upstream.Server{{Name: "test", URL: "dns://" + pc.LocalAddr().String()}}, "")
	s := &Server{Logger: log, Log: st, Filter: fm, Cache: cache.New(100), Upstream: up,
		Rebind: func(name string) bool { return name != "ok.example" }}
	s.acl = newClientACL(nil)

	client := netip.MustParseAddr("127.0.0.1")
	answer := func(n string, qt uint16) []string {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(n), qt)
		var out []string
		for _, r := range s.Answer(q, client, "udp").Answer {
			switch v := r.(type) {
			case *dns.A:
				out = append(out, v.A.String())
			case *dns.AAAA:
				out = append(out, v.AAAA.String())
			}
		}
		return out
	}
	if got := answer("evil.example", dns.TypeA); !slices.Equal(got, []string{"203.0.113.5", "0.0.0.0"}) {
		t.Fatalf("A: %v", got)
	}
	if got := answer("evil.example", dns.TypeA); !slices.Equal(got, []string{"203.0.113.5", "0.0.0.0"}) { // aus dem Cache
		t.Fatalf("cached A: %v", got)
	}
	if got := answer("evil.example", dns.TypeAAAA); len(got) != 0 {
		t.Fatalf("AAAA: %v", got)
	}
	if got := answer("ok.example", dns.TypeA); len(got) != 3 {
		t.Fatalf("exempt name: %v", got)
	}
	if got := answer("released.example", dns.TypeAAAA); len(got) != 3 {
		t.Fatalf("released name: %v", got)
	}
	// Freigabe nur fuer eine Geraetegruppe: der Cache ist gemeinsam, gefiltert wird je Anfrager - in beiden
	// Reihenfolgen (erst das freigegebene Geraet, dann eins ohne Freigabe und umgekehrt)
	kid := netip.MustParseAddr("127.0.0.2")
	s.Policy = func(ip netip.Addr) *Policy {
		if ip == kid {
			return &Policy{Group: "lab", Mask: fm.Global(), Allow: filter.NewDomainSet([]string{"lab.example", "lab2.example"})}
		}
		return nil
	}
	ask := func(ip netip.Addr, n string) int {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(n), dns.TypeA)
		return len(s.Answer(q, ip, "udp").Answer)
	}
	if ask(kid, "lab.example") != 3 || ask(client, "lab.example") != 2 || ask(kid, "lab.example") != 3 {
		t.Fatal("group release: private address must reach only the released group (released first)")
	}
	if ask(client, "lab2.example") != 2 || ask(kid, "lab2.example") != 3 {
		t.Fatal("group release: filtered answer of another group must not be cached for the released group")
	}
	s.Policy = nil
	s.Rebind = nil
	if got := answer("off.example", dns.TypeA); len(got) != 3 {
		t.Fatalf("switched off: %v", got)
	}
}
