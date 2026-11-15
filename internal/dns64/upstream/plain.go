package upstream

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// plain spricht klassisches DNS (UDP, bei abgeschnittener Antwort TCP), z. B. mit dem DNS eines VPN oder Routers
// (Weiterleitungen) oder einem selbst eingetragenen Upstream wie 8.8.8.8 (dns://ip:port, unverschluesselt).
type plain struct {
	addr string // ip:port
}

// plainTimeout: Server im eigenen Netz antworten schnell; ein toter Server soll den Client nicht warten lassen.
const plainTimeout = 1500 * time.Millisecond

func newPlain(host, port string) *plain {
	if port == "" {
		port = "53"
	}
	return &plain{addr: net.JoinHostPort(host, port)}
}

func (p *plain) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	// eigene Zufalls-ID: die des Clients ist bei DoH/DoQ 0 und damit unverschluesselt leicht zu faelschen
	q := req.Copy()
	q.Id = dns.Id()
	c := &dns.Client{Net: "udp", Timeout: plainTimeout, UDPSize: dns.DefaultMsgSize}
	resp, _, err := c.ExchangeContext(ctx, q, p.addr)
	if err == nil && resp.Truncated {
		c = &dns.Client{Net: "tcp", Timeout: plainTimeout, Dialer: &net.Dialer{Timeout: 2 * time.Second}}
		resp, _, err = c.ExchangeContext(ctx, q, p.addr)
	}
	if err == nil && !sameQuestion(q, resp) {
		// unverschluesselt: nur die passende Antwort (Name, Typ, Klasse) - sonst landete eine untergeschobene Antwort
		// fuer einen anderen Namen im Cache
		return nil, errQuestion
	}
	if err == nil {
		resp.Id = req.Id
	}
	return resp, err
}

var errQuestion = errors.New("plain: answer for another question")

// sameQuestion: die Antwort nennt genau die Frage der Anfrage (Gross/Klein egal, wie 0x20).
func sameQuestion(q, resp *dns.Msg) bool {
	if len(q.Question) != len(resp.Question) {
		return false
	}
	for i, a := range q.Question {
		b := resp.Question[i]
		if a.Qtype != b.Qtype || a.Qclass != b.Qclass || !strings.EqualFold(a.Name, b.Name) {
			return false
		}
	}
	return true
}

func (p *plain) close() {}
