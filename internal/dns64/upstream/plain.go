package upstream

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

// plain spricht klassisches DNS (UDP, bei abgeschnittener Antwort TCP) mit einem Server im eigenen Netz, z. B.
// dem DNS eines VPN oder Routers. Nur fuer Weiterleitungen einzelner Domains (dns://ip:port); die oeffentlichen
// Upstreams bleiben verschluesselt.
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
	c := &dns.Client{Net: "udp", Timeout: plainTimeout, UDPSize: dns.DefaultMsgSize}
	resp, _, err := c.ExchangeContext(ctx, req, p.addr)
	if err == nil && resp.Truncated {
		c = &dns.Client{Net: "tcp", Timeout: plainTimeout, Dialer: &net.Dialer{Timeout: 2 * time.Second}}
		resp, _, err = c.ExchangeContext(ctx, req, p.addr)
	}
	return resp, err
}

func (p *plain) close() {}
