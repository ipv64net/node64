package localnet

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestIPv6Gateways(t *testing.T) {
	route := `fd000000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 ens18
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000021122fffe334455 00000400 00000001 00000000 00000003 ens18
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000021122fffe334455 00000400 00000001 00000000 00000003 ens18
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fd000000000000000000000000000001 00000400 00000001 00000000 00000003 eth1
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo
`
	got := ipv6Gateways(strings.NewReader(route))
	if want := []string{"fe80::211:22ff:fe33:4455%ens18", "fd00::1"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// Router-Suche: landet der Pruefname beim eigenen DNS-Dienst (Docker-Bridge mit veroeffentlichtem Port 53), ist der
// Kandidat diese Node selbst; ein fremder DNS-Server ist es nicht.
func TestSelfProbe(t *testing.T) {
	r := New("", slog.New(slog.NewTextHandler(io.Discard, nil)))
	serve := func(self bool) string {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			if self {
				r.SelfProbe(q.Question[0].Name) // wie der eigene DNS-Dienst
			}
			m := new(dns.Msg)
			m.SetRcode(q, dns.RcodeNameError)
			_ = w.WriteMsg(m)
		})}
		go func() { _ = srv.ActivateAndServe() }()
		t.Cleanup(func() { _ = srv.Shutdown() })
		return pc.LocalAddr().String()
	}
	ctx := context.Background()
	if !r.isSelf(ctx, serve(true)) {
		t.Fatal("eigener Dienst nicht erkannt")
	}
	if r.isSelf(ctx, serve(false)) {
		t.Fatal("fremder Router als eigener erkannt")
	}
	if r.SelfProbe("example.org.") {
		t.Fatal("normaler Name als Pruefname")
	}
}

// Anfragen vom Router selbst gehen nicht an ihn zurueck (Schleife); ein Loopback-Router zaehlt nicht.
func TestIsRouter(t *testing.T) {
	r := New("172.17.0.1:53", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !r.IsRouter(netip.MustParseAddr("172.17.0.1")) || !r.IsRouter(netip.MustParseAddr("::ffff:172.17.0.1")) || r.IsRouter(netip.MustParseAddr("172.17.0.2")) {
		t.Fatal("router ip")
	}
	if New("127.0.0.1:5353", r.log).IsRouter(netip.MustParseAddr("127.0.0.1")) || New("", r.log).IsRouter(netip.MustParseAddr("172.17.0.1")) {
		t.Fatal("loopback/ohne router")
	}
}
