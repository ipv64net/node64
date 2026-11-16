package dnsserver

import (
	"io"
	"log/slog"
	"testing"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/querylog"
)

// Umschreiben auf eine Adresse (#174): IPv4 beantwortet A, IPv6 AAAA, andere Typen NOERROR ohne Antwort - nie
// NXDOMAIN; auch am Ende einer Kette von Umschreibungen.
func TestRewriteToIP(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rw := map[string]string{"nas.example.de": "192.168.1.10", "v6.example.de": "fd00::10", "kette.example.de": "nas.example.de"}
	s := &Server{Logger: log, Rewrite: func(n string) (string, bool) { t, ok := rw[n]; return t, ok }}
	ask := func(name string, qt uint16) (*dns.Msg, querylog.Entry) {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(name), qt)
		var e querylog.Entry
		return s.resolve(q, name, &e, nil, false, 0), e
	}
	for _, c := range []struct {
		name string
		qt   uint16
		want string // "" = NOERROR ohne Antwort
	}{
		{"nas.example.de", dns.TypeA, "192.168.1.10"},
		{"nas.example.de", dns.TypeAAAA, ""},
		{"nas.example.de", dns.TypeMX, ""},
		{"v6.example.de", dns.TypeAAAA, "fd00::10"},
		{"v6.example.de", dns.TypeA, ""},
		{"kette.example.de", dns.TypeA, "192.168.1.10"},
	} {
		resp, e := ask(c.name, c.qt)
		if resp.Rcode != dns.RcodeSuccess || e.Status != querylog.StatusCustom {
			t.Fatalf("%s %s: rcode %s, status %s", c.name, dns.TypeToString[c.qt], dns.RcodeToString[resp.Rcode], e.Status)
		}
		got := ""
		if len(resp.Answer) == 1 {
			rr := resp.Answer[0]
			if rr.Header().Name != dns.Fqdn(c.name) || rr.Header().Ttl != rewriteTTL {
				t.Fatalf("%s: header %v", c.name, rr.Header())
			}
			switch v := rr.(type) {
			case *dns.A:
				got = v.A.String()
			case *dns.AAAA:
				got = v.AAAA.String()
			}
		} else if len(resp.Answer) > 1 {
			t.Fatalf("%s: %v", c.name, resp.Answer)
		}
		if got != c.want {
			t.Fatalf("%s %s: %q, want %q", c.name, dns.TypeToString[c.qt], got, c.want)
		}
	}
	if _, e := ask("nas.example.de", dns.TypeA); e.Reason != ReasonRewrite+"192.168.1.10" {
		t.Fatalf("reason %q", e.Reason)
	}
}
