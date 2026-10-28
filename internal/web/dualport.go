package web

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

// HTTP und HTTPS auf demselben Port: Am ersten Byte der Verbindung ist zu erkennen, ob der Browser TLS spricht
// (Handshake beginnt mit 0x16). Dann bekommt der HTTP-Server eine TLS-Verbindung mit dem Zertifikat der
// Oberflaeche, sonst die unveraenderte Verbindung. Die Erkennung laeuft je Verbindung nebenher, damit ein Client,
// der nichts sendet, keine anderen aufhaelt.

const peekTimeout = 10 * time.Second

type dualListener struct {
	net.Listener
	tls    *tls.Config
	conns  chan net.Conn
	errc   chan error
	done   chan struct{}
	closed sync.Once
}

func newDualListener(ln net.Listener, cfg *tls.Config) *dualListener {
	d := &dualListener{Listener: ln, tls: cfg, conns: make(chan net.Conn), errc: make(chan error, 1), done: make(chan struct{})}
	go d.loop()
	return d
}

func (d *dualListener) loop() {
	var delay time.Duration
	for {
		c, err := d.Listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				// voruebergehend (z. B. zu viele offene Dateien): kurz warten und weiter annehmen, wie net/http
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				select {
				case <-time.After(delay):
					continue
				case <-d.done:
					return
				}
			}
			select {
			case d.errc <- err:
			case <-d.done:
			}
			return
		}
		delay = 0
		go d.classify(c)
	}
}

func (d *dualListener) classify(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(peekTimeout))
	br := bufio.NewReader(c)
	b, err := br.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		_ = c.Close()
		return
	}
	var out net.Conn = &peekedConn{Conn: c, r: br}
	if b[0] == 0x16 { // TLS-Handshake (ClientHello)
		out = tls.Server(out, d.tls)
	}
	select {
	case d.conns <- out:
	case <-d.done:
		_ = c.Close()
	}
}

func (d *dualListener) Accept() (net.Conn, error) {
	select {
	case c := <-d.conns:
		return c, nil
	case err := <-d.errc:
		return nil, err
	case <-d.done:
		return nil, net.ErrClosed
	}
}

func (d *dualListener) Close() error {
	d.closed.Do(func() { close(d.done) })
	return d.Listener.Close()
}

// peekedConn liest zuerst die schon gepufferten Bytes.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekedConn) Read(b []byte) (int, error) { return p.r.Read(b) }
