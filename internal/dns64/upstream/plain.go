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
	c := &dns.Client{Net: "udp", Timeout: plainTimeout, UDPSize: dns.DefaultMsgSize}
	resp, _, err := c.ExchangeContext(ctx, req, p.addr)
	if err == nil && resp.Truncated {
		c = &dns.Client{Net: "tcp", Timeout: plainTimeout, Dialer: &net.Dialer{Timeout: 2 * time.Second}}
		resp, _, err = c.ExchangeContext(ctx, req, p.addr)
	}
	return resp, err
}

func (p *plain) close() {}
