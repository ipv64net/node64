package dnsserver

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/localnet"
	"github.com/ipv64net/node64/internal/dns64/querylog"
)

type cnameRecords map[string]string

func (c cnameRecords) Lookup(name string, _ uint16) ([]dns.RR, bool) {
	target, ok := c[name]
	if !ok {
		return nil, false
	}
	return []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: dns.Fqdn(target)}}, true
}

// Fragt der Router selbst, geht ein lokales Ziel auch ueber Umschreiben und eigenen CNAME nicht an ihn zurueck
// (sonst kreist die Anfrage). Der "Router" ist hier nicht erreichbar: ginge die Anfrage hin, wartete sie Sekunden.
func TestFromRouterNotBackViaRewriteOrCNAME(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &Server{Local: localnet.New("10.255.255.1:53", log), Logger: log, Records: cnameRecords{"alias.example": "nas.lan"},
		Rewrite: func(n string) (string, bool) { return "nas.lan", n == "rw.example" }}
	for _, name := range []string{"rw.example", "alias.example"} {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(name), dns.TypeA)
		start := time.Now()
		resp := s.resolve(q, name, &querylog.Entry{}, nil, true)
		if d := time.Since(start); d > time.Second {
			t.Fatalf("%s: local target went to the router (%s)", name, d)
		}
		if resp.Rcode != dns.RcodeNameError && len(resp.Answer) > 1 {
			t.Fatalf("%s: unexpected answer %v", name, resp)
		}
	}
}
