package certs

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// Ist ein Nameserver nur ueber eine Familie erreichbar (z. B. IPv6-only-Anschluss), gilt der TXT-Record trotzdem
// als sichtbar: die nicht erreichbare IPv4-Adresse haelt die Pruefung nicht auf.
func TestWaitTXTEitherFamily(t *testing.T) {
	pc, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"token"}})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	dead, _ := net.ListenPacket("udp", "127.0.0.1:0") // IPv4-Adresse ohne DNS-Dienst
	deadAddr := dead.LocalAddr().String()
	dead.Close()
	old := lookupNS
	defer func() { lookupNS = old }()
	lookupNS = func(context.Context, string) ([][]string, error) {
		return [][]string{{deadAddr, pc.LocalAddr().String()}}, nil
	}
	if err := waitTXT(context.Background(), "example.org", "_acme-challenge.example.org", "token"); err != nil {
		t.Fatal(err)
	}
}
