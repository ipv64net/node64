package dns64

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"html/template"
	"net"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
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

// IPv6-Feinheiten: Host-Kopf ohne Port, Zone der Client-Adresse, AAAA mit Zone oder ::ffff:, ::ffff:-Netze.
func TestIPv6Edges(t *testing.T) {
	m, _ := testModule(t)
	c := m.loadConfig(context.Background())
	c.Names, c.CertMode = nil, certSelf
	r := httptest.NewRequest("GET", "/dns64/encrypted", nil)
	r.Host = "[fd00::5]"
	if v := m.encView(r, c); v.Host != "fd00::5" || strings.Contains(v.DoHURL, "[[") || v.DoQURL != "quic://[fd00::5]:"+strconv.Itoa(c.DoTPort) {
		t.Errorf("encView: %q %q %q", v.Host, v.DoHURL, v.DoQURL)
	}
	if a := clientAddr(&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 853, Zone: "eth0"}); a.String() != "fe80::1" {
		t.Errorf("clientAddr: %s", a)
	}
	for v, ok := range map[string]bool{"FD00::0010": true, "fe80::1%eth0": false, "::ffff:192.168.1.1": false} {
		rec := Record{Name: "nas.home.lan", Type: "AAAA", Value: v}
		if err := normalizeRecord(&rec); (err == nil) != ok || (ok && rec.Value != "fd00::10") {
			t.Errorf("AAAA %s: %v %q", v, err, rec.Value)
		}
	}
	for in, want := range map[string]string{"::ffff:10.8.0.0/112": "10.8.0.0/16", "::ffff:10.8.0.1": "10.8.0.1/32", "fd00::/8": "fd00::/8"} {
		if p, err := parsePrefix(in); err != nil || p.String() != want {
			t.Errorf("parsePrefix(%s) = %s %v", in, p, err)
		}
	}
	if _, err := parsePrefix("::ffff:0:0/90"); err != nil {
		t.Errorf("/90 ist kein ::ffff:-Netz mehr (maskiert): %v", err)
	}
	if p, err := parsePrefix("::ffff:0.0.0.0/96"); err != nil || p.Bits() != 0 { // 0.0.0.0/0, beim Speichern abgelehnt
		t.Errorf("parsePrefix /96 = %s %v", p, err)
	}
	if _, err := template.New("s").Funcs(template.FuncMap{"join": strings.Join}).ParseFS(templateFS, "templates/pages/settings.html"); err != nil {
		t.Fatal(err) // Warnung bei fester Bind-Adresse
	}
}
