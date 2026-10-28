package upstream

import (
	"context"
	"net"
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
	if err == nil {
		resp.Id = req.Id
	}
	return resp, err
}

func (p *plain) close() {}
