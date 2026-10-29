package edge

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// TLS durchreichen: Edge liest auf Port 443 nur die erste Nachricht des Browsers (ClientHello) und den Namen
// darin. Gehoert der Name einer Route mit Passthrough, geht die Verbindung roh an das Ziel, ohne dass Edge sie
// entschluesselt (das Ziel hat sein eigenes Zertifikat). Alles andere bekommt der TLS-Server von Edge, mit den
// schon gelesenen Bytes vorneweg.

var errPeeked = errors.New("client hello read")

const helloTimeout = 10 * time.Second

// peekHello liest das ClientHello und liefert den Namen (SNI) und alle dabei gelesenen Bytes.
func peekHello(conn net.Conn) (sni string, data []byte, ok bool) {
	sni, _, data, ok = PeekHello(conn)
	return sni, data, ok
}

// PeekHello wie PeekSNI, dazu die angebotenen Protokolle (ALPN), z. B. um den Tunnel einer Node von einem Browser zu
// unterscheiden.
func PeekHello(conn net.Conn) (sni string, alpn []string, data []byte, ok bool) {
	var buf bytes.Buffer
	var hello *tls.ClientHelloInfo
	_ = tls.Server(readOnlyConn{r: io.TeeReader(conn, &buf), c: conn}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = h
			return nil, errPeeked
		},
	}).Handshake()
	if hello == nil {
		return "", nil, buf.Bytes(), false
	}
	return hello.ServerName, hello.SupportedProtos, buf.Bytes(), true
}

// PeekSNI liest das TLS-ClientHello einer Verbindung, ohne zu antworten: Name (SNI) und die gelesenen Bytes, die
// beim Weiterreichen zuerst gesendet werden muessen (auch fuer die CDN64-Server).
func PeekSNI(conn net.Conn) (sni string, data []byte, ok bool) { return peekHello(conn) }

// readOnlyConn liest aus r und verwirft alles Geschriebene (die Antwort des Handshakes geht nie raus).
type readOnlyConn struct {
	r io.Reader
	c net.Conn
}

func (c readOnlyConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c readOnlyConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (c readOnlyConn) Close() error                     { return nil }
func (c readOnlyConn) LocalAddr() net.Addr              { return c.c.LocalAddr() }
func (c readOnlyConn) RemoteAddr() net.Addr             { return c.c.RemoteAddr() }
func (c readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (c readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (c readOnlyConn) SetWriteDeadline(time.Time) error { return nil }

// prefixConn liefert zuerst die schon gelesenen Bytes, danach die Verbindung.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// chanListener reicht Verbindungen an den TLS-Server von Edge weiter.
type chanListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{addr: addr, ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }

func (l *chanListener) push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		_ = c.Close()
	}
}

// acceptSNI nimmt Verbindungen auf Port 443 an und verteilt sie (je Verbindung eine Goroutine, damit ein
// langsamer Client die anderen nicht aufhaelt).
func (e *Edge) acceptSNI(ln net.Listener, tlsLn *chanListener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond) // z. B. zu viele offene Dateien
			continue
		}
		if conn = e.admit(conn); conn == nil { // Sperrliste und Limits: vor TLS und vor der Verteilung
			continue
		}
		go e.dispatch(conn, tlsLn)
	}
}

func (e *Edge) dispatch(conn net.Conn, tlsLn *chanListener) {
	_ = conn.SetReadDeadline(time.Now().Add(helloTimeout))
	sni, data, ok := peekHello(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if !ok {
		_ = conn.Close() // kein TLS
		return
	}
	if nonce, found := strings.CutSuffix(strings.ToLower(sni), probeSuffix); found && e.probeHit(nonce) {
		_ = conn.Close() // Pruefanfrage (published.go)
		return
	}
	if want := routedHost(conn); want != "" { // aus dem Tunnel: nur der Name, fuer den der CDN64-Server durchreicht
		if name, _ := NormalizeName(sni); name != want {
			_ = conn.Close()
			return
		}
	}
	if name, err := NormalizeName(sni); err == nil {
		if _, routes := e.table.Load().lookup(name); len(routes) > 0 {
			for _, rt := range routes {
				if rt.Passthrough != "" {
					e.passthrough(conn, data, rt)
					return
				}
			}
		}
	}
	tlsLn.push(&prefixConn{Conn: conn, r: io.MultiReader(bytes.NewReader(data), conn)})
}

// passthrough verbindet roh mit dem Ziel und kopiert in beide Richtungen.
func (e *Edge) passthrough(conn net.Conn, data []byte, rt *Route) {
	if rt.Allow != nil {
		if ip := addrIP(conn.RemoteAddr()); !rt.Allow(ip) {
			_ = conn.Close()
			return
		}
	}
	up, err := net.DialTimeout("tcp", rt.Passthrough, 10*time.Second)
	if err != nil {
		e.log.Debug("passthrough target not reachable", "target", rt.Passthrough, "err", err)
		_ = conn.Close()
		return
	}
	if !e.track(conn, up) {
		_ = conn.Close()
		_ = up.Close()
		return
	}
	defer e.untrack(conn, up)
	if _, err := up.Write(data); err != nil {
		_ = conn.Close()
		_ = up.Close()
		return
	}
	if rt.Count != nil {
		rt.Count()
	}
	if rt.Wrap != nil {
		conn = rt.Wrap(conn)
	}
	Pipe(conn, up)
}

// Pipe kopiert in beide Richtungen, bis eine Seite schliesst, und schliesst dann beide.
func Pipe(a, b net.Conn) (ab, ba int64) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ba, _ = io.Copy(a, b)
		closeWrite(a)
	}()
	ab, _ = io.Copy(b, a)
	closeWrite(b)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
	return ab, ba
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// track merkt durchgereichte Verbindungen, damit Close sie beenden kann.
func (e *Edge) track(cs ...net.Conn) bool {
	e.passMu.Lock()
	defer e.passMu.Unlock()
	if e.passClosed {
		return false
	}
	for _, c := range cs {
		e.pass[c] = struct{}{}
	}
	return true
}

func (e *Edge) untrack(cs ...net.Conn) {
	e.passMu.Lock()
	defer e.passMu.Unlock()
	for _, c := range cs {
		delete(e.pass, c)
	}
}

// closePassthrough beendet alle durchgereichten Verbindungen (beim Schliessen von Port 443).
func (e *Edge) closePassthrough(final bool) {
	e.passMu.Lock()
	defer e.passMu.Unlock()
	if final {
		e.passClosed = true
	}
	for c := range e.pass {
		_ = c.Close()
	}
}
