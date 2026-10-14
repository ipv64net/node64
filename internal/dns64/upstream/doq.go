package upstream

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// doq speaks DNS-over-QUIC (RFC 9250): one QUIC connection per upstream, one stream per query.
type doq struct {
	addrs []string
	tls   *tls.Config
	conf  *quic.Config

	mu     sync.Mutex
	conn   *quic.Conn
	closed bool
}

func newDoQ(host, port string, ips []string) *doq {
	return &doq{
		addrs: dialAddrs(host, port, ips),
		tls:   &tls.Config{ServerName: host, MinVersion: tls.VersionTLS13, NextProtos: []string{"doq"}, RootCAs: testRoots},
		conf:  &quic.Config{HandshakeIdleTimeout: 2 * time.Second, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 15 * time.Second},
	}
}

// connection returns the open QUIC connection or dials a new one.
func (d *doq) connection(ctx context.Context) (*quic.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, errors.New("doq: closed")
	}
	if d.conn != nil && d.conn.Context().Err() == nil {
		return d.conn, nil
	}
	var lastErr error
	for _, addr := range d.addrs {
		c, err := quic.DialAddr(ctx, addr, d.tls, d.conf)
		if err == nil {
			d.conn = c
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// drop forgets a broken connection so the next query dials anew.
func (d *doq) drop(c *quic.Conn) {
	d.mu.Lock()
	if d.conn == c {
		d.conn = nil
	}
	d.mu.Unlock()
	_ = c.CloseWithError(0, "")
}

func (d *doq) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	resp, err := d.try(ctx, req)
	if err != nil && ctx.Err() == nil { // the server may have closed an idle connection: once more
		resp, err = d.try(ctx, req)
	}
	return resp, err
}

func (d *doq) try(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	c, err := d.connection(ctx)
	if err != nil {
		return nil, err
	}
	q := req.Copy()
	q.Id = 0 // RFC 9250 §4.2.1: the message ID must be 0
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	s, err := c.OpenStreamSync(ctx)
	if err != nil {
		d.drop(c)
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = s.SetDeadline(dl)
	}
	buf := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(buf, uint16(len(wire)))
	copy(buf[2:], wire)
	if _, err := s.Write(buf); err != nil {
		s.CancelRead(0)
		d.drop(c)
		return nil, err
	}
	_ = s.Close() // end of the query (FIN), the answer comes on the same stream
	var n [2]byte
	if _, err := io.ReadFull(s, n[:]); err != nil {
		s.CancelRead(0)
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(n[:]))
	if _, err := io.ReadFull(s, body); err != nil {
		s.CancelRead(0)
		return nil, err
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(body); err != nil {
		return nil, err
	}
	resp.Id = req.Id
	return resp, nil
}

func (d *doq) close() {
	d.mu.Lock()
	c := d.conn
	d.conn, d.closed = nil, true
	d.mu.Unlock()
	if c != nil {
		_ = c.CloseWithError(0, "")
	}
}
