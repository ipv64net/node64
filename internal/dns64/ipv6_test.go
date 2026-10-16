package dns64

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Ohne feste Adresse lauscht DNS64 auf IPv4 und IPv6: UDP, TCP und DoT antworten ueber 127.0.0.1 und ::1, auch
// fuer AAAA; das Zertifikat der Heimnetz-CA enthaelt die IPv6-Adresse.
func TestDualStack(t *testing.T) {
	if l, err := net.ListenPacket("udp", "[::1]:0"); err != nil {
		t.Skip("no IPv6 loopback: ", err)
	} else {
		l.Close()
	}
	m, port := testModule(t)
	ctx := context.Background()
	c := m.loadConfig(ctx)
	c.Bind, c.DoT, c.DoTPort = "", true, freePort(t)
	if err := m.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Record{{Name: "nas.home.lan", Type: "A", Value: "192.168.1.10"}, {Name: "nas.home.lan", Type: "AAAA", Value: "fd00::10"}} {
		if _, err := m.AddRecord(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Start(ctx); err != nil || m.running() == nil {
		t.Fatalf("start: %v %s", err, m.startError())
	}
	pemCA, err := os.ReadFile(m.caFile())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemCA)
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, q := range []struct {
			net  string
			typ  uint16
			want string
		}{{"udp", dns.TypeA, "192.168.1.10"}, {"tcp", dns.TypeAAAA, "fd00::10"}, {"tcp-tls", dns.TypeAAAA, "fd00::10"}} {
			cl := &dns.Client{Net: q.net, Timeout: 3 * time.Second}
			addr := net.JoinHostPort(host, strconv.Itoa(port))
			if q.net == "tcp-tls" {
				cl.TLSConfig = &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12}
				addr = net.JoinHostPort(host, strconv.Itoa(c.DoTPort))
			}
			msg := new(dns.Msg)
			msg.SetQuestion("nas.home.lan.", q.typ)
			r, _, err := cl.Exchange(msg, addr)
			if err != nil {
				t.Fatalf("%s %s: %v", q.net, host, err)
			}
			var got string
			for _, rr := range r.Answer {
				switch v := rr.(type) {
				case *dns.A:
					got = v.A.String()
				case *dns.AAAA:
					got = v.AAAA.String()
				}
			}
			if got != q.want {
				t.Fatalf("%s %s: answer %q, want %q", q.net, host, got, q.want)
			}
		}
	}
	// Router mit IPv6 (auch Link-local mit Schnittstelle) laesst sich eintragen
	for _, r := range []string{"fd00::1", "[fd00::1]:5353", "fe80::1%eth0", "192.168.1.1"} {
		c := m.loadConfig(ctx)
		c.Router = r
		if err := c.validate(); err != nil {
			t.Fatalf("router %q: %v", r, err)
		}
	}
}
