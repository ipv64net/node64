package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// exchanger is a transport other than DoH (DoT, DoQ).
type exchanger interface {
	exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
	close()
}

const maxIdleConns = 4

// dot speaks DNS-over-TLS (RFC 7858) and keeps a few connections open for reuse.
type dot struct {
	host  string   // name for the certificate check
	addrs []string // ip:port to dial (bootstrap IPs, else the host)
	tls   *tls.Config

	mu     sync.Mutex
	idle   []*dns.Conn
	closed bool
}

func newDoT(host, port string, ips []string) *dot {
	return &dot{host: host, addrs: dialAddrs(host, port, ips), tls: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: testRoots}}
}

// dialAddrs lists the addresses to try: the bootstrap IPs, or the host itself if it is an IP.
func dialAddrs(host, port string, ips []string) []string {
	if len(ips) == 0 {
		return []string{net.JoinHostPort(host, port)}
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, net.JoinHostPort(ip, port))
	}
	return out
}

func (d *dot) dial(ctx context.Context) (*dns.Conn, error) {
	var lastErr error
	for _, addr := range d.addrs {
		dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: d.tls}
		c, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			return &dns.Conn{Conn: c}, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (d *dot) get() *dns.Conn {
	d.mu.Lock()
	defer d.mu.Unlock()
	if n := len(d.idle); n > 0 {
		c := d.idle[n-1]
		d.idle = d.idle[:n-1]
		return c
	}
	return nil
}

func (d *dot) put(c *dns.Conn) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || len(d.idle) >= maxIdleConns {
		c.Close()
		return
	}
	d.idle = append(d.idle, c)
}

func (d *dot) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	// a reused connection may have been closed by the server in the meantime: then once more with a new one
	if c := d.get(); c != nil {
		if resp, err := d.roundTrip(ctx, c, req); err == nil {
			return resp, nil
		}
	}
	c, err := d.dial(ctx)
	if err != nil {
		return nil, err
	}
	return d.roundTrip(ctx, c, req)
}

func (d *dot) roundTrip(ctx context.Context, c *dns.Conn, req *dns.Msg) (*dns.Msg, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(attemptTimeout)
	}
	_ = c.SetDeadline(deadline)
	if err := c.WriteMsg(req); err != nil {
		c.Close()
		return nil, err
	}
	resp, err := c.ReadMsg()
	if err != nil {
		c.Close()
		return nil, err
	}
	if resp.Id != req.Id {
		c.Close()
		return nil, errors.New("dot: answer for another query")
	}
	_ = c.SetDeadline(time.Time{})
	d.put(c)
	return resp, nil
}

func (d *dot) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	for _, c := range d.idle {
		c.Close()
	}
	d.idle = nil
}
