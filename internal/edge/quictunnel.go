package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/ipv64net/node64/internal/tunnel"
)

// HTTP/3 ueber den Tunnel (CDN64 online Modus 1): Der CDN64-Server reicht die QUIC-Datagramme eines Besuchers roh
// durch (ein Tunnel-Stream je Besucher-Adresse, Datagramme mit Laengenpraefix). Hier landen sie in einer virtuellen
// PacketConn mit der echten Besucher-Adresse als Absender, davor ein eigener HTTP/3-Server mit denselben Routen,
// Zertifikaten und Pruefungen wie auf UDP 443 - TLS endet wie bei TCP erst hier.

// Absender von QUIC-Datagrammen sind nicht bestaetigt (UDP laesst sich faelschen). Die Verbindungs-Limits (SetGate)
// zaehlen einen Besucher deshalb erst nach dem Handshake; bis dahin gelten diese Grenzen fuer offene Streams.
const (
	quicPendingMax   = 1024             // Streams ohne fertigen Handshake insgesamt
	quicPendingPerIP = 16               // je Besucher-Adresse
	quicPendingTime  = 20 * time.Second // so lange darf der Handshake dauern
)

// ServeQUICStream nimmt einen QUIC-Stream aus dem Tunnel an (client = echte Besucher-Adresse). Kehrt sofort zurueck.
func (e *Edge) ServeQUICStream(c net.Conn, client netip.AddrPort) {
	e.ServeQUICStreamFor(c, client, "")
}

// ServeQUICStreamFor wie ServeQUICStream fuer den Namen, fuer den der CDN64-Server durchreicht ("" = beliebig): ein
// Handshake mit anderem SNI wird abgewiesen.
func (e *Edge) ServeQUICStreamFor(c net.Conn, client netip.AddrPort, host string) {
	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed || !client.IsValid() || e.blocked(net.UDPAddrFromAddrPort(client)) {
		_ = c.Close()
		return
	}
	vq := e.virtualQUIC()
	if vq == nil || !vq.pc.reserve(client.Addr()) {
		_ = c.Close()
		return
	}
	if host != "" {
		host = routedName(host)
	}
	go vq.serve(c, client, host)
}

// SetTunnelHTTP3 setzt die Abfrage, ob HTTP/3 ueber den Tunnel geht (alle verbundenen CDN64-Server koennen es).
// Dann bekommen Antworten auf Modus-1-Anfragen aus dem Tunnel den Hinweis Alt-Svc h3=":443".
func (e *Edge) SetTunnelHTTP3(f func() bool) {
	if f == nil {
		e.tunH3.Store(nil)
		return
	}
	e.tunH3.Store(&f)
}

func (e *Edge) tunnelHTTP3() bool {
	f := e.tunH3.Load()
	return f != nil && (*f)()
}

type virtQUIC struct {
	pc  *virtPacketConn
	srv *http3.Server
}

func (e *Edge) virtualQUIC() *virtQUIC {
	e.qonce.Do(func() {
		e.mu.Lock()
		closed := e.closed
		e.mu.Unlock()
		if closed {
			return
		}
		pc := newVirtPacketConn()
		srv := &http3.Server{Handler: http.HandlerFunc(e.serveHTTPS), IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
				if !pc.sniOK(h) {
					return nil, errMisrouted
				}
				return e.quicConfig(h)
			}},
			ConnContext: func(ctx context.Context, qc *quic.Conn) context.Context {
				if f := pc.flow(qc.RemoteAddr()); f != nil {
					go e.admitQUIC(qc, f)
				}
				return ctx
			}}
		go func() { _ = srv.Serve(pc) }()
		e.vq = &virtQUIC{pc: pc, srv: srv}
	})
	return e.vq
}

func (e *Edge) closeVirtualQUIC(ctx context.Context) {
	e.qonce.Do(func() {}) // danach legt niemand mehr einen an
	if e.vq == nil {
		return
	}
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second) // offene HTTP/3-Verbindungen nicht bis zum Leerlauf abwarten
	defer cancel()
	_ = e.vq.srv.Shutdown(sctx)
	_ = e.vq.srv.Close()
	_ = e.vq.pc.Close()
}

var errMisrouted = errors.New("server name differs from the routed name")

// admitQUIC: nach dem Handshake (Absender bestaetigt) die Verbindungs-Limits; abgewiesen wird die Verbindung samt
// Stream geschlossen.
func (e *Edge) admitQUIC(qc *quic.Conn, f *vflow) {
	select {
	case <-qc.HandshakeComplete():
	case <-qc.Context().Done():
		return
	}
	var g ConnGate
	if p := e.gate.Load(); p != nil {
		g = *p
	}
	if f.admit(g, addrIP(qc.RemoteAddr())) {
		return
	}
	_ = qc.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad), "")
	_ = f.c.Close()
}

// serve: Datagramme aus dem Stream an den HTTP/3-Server, bis der Stream endet.
func (v *virtQUIC) serve(c net.Conn, client netip.AddrPort, host string) {
	key := client.String()
	f := &vflow{c: c, host: host, ip: client.Addr(), pc: v.pc, pending: true}
	v.pc.mu.Lock()
	old := v.pc.flows[key]
	v.pc.flows[key] = f
	v.pc.mu.Unlock()
	if old != nil {
		_ = old.c.Close()
	}
	t := time.AfterFunc(quicPendingTime, func() { // Handshake nicht rechtzeitig fertig (z. B. gefaelschter Absender)
		if f.isPending() {
			_ = c.Close()
		}
	})
	defer func() {
		t.Stop()
		v.pc.mu.Lock()
		if v.pc.flows[key] == f {
			delete(v.pc.flows, key)
		}
		v.pc.mu.Unlock()
		_ = c.Close()
		f.end()
	}()
	addr := net.UDPAddrFromAddrPort(client)
	buf := make([]byte, tunnel.MaxDatagram)
	for {
		n, err := tunnel.ReadDatagram(c, buf)
		if err != nil {
			return
		}
		select { // voll: verwerfen wie UDP (QUIC wiederholt), damit ein Besucher die anderen nicht aufhaelt
		case v.pc.in <- vpkt{data: append([]byte(nil), buf[:n]...), addr: addr}:
		case <-v.pc.done:
			return
		default:
		}
	}
}

// ---------------------------------------------------------------- virtuelle PacketConn

type vpkt struct {
	data []byte
	addr net.Addr
}

type vflow struct {
	mu   sync.Mutex // Schreiben in c
	c    net.Conn
	host string     // Name, fuer den der CDN64-Server durchreicht ("" = beliebig)
	ip   netip.Addr // Besucher
	pc   *virtPacketConn

	st       sync.Mutex
	pending  bool   // Handshake noch nicht fertig (zaehlt bei quicPending*)
	admitted bool   // Limits nach dem Handshake geprueft
	ended    bool   // Stream zu
	release  func() // Platz beim Limit (SetGate)
}

func (f *vflow) isPending() bool {
	f.st.Lock()
	defer f.st.Unlock()
	return f.pending
}

// admit: Verbindungs-Limits nach dem Handshake (einmal je Stream); false = abgewiesen bzw. Stream schon zu.
func (f *vflow) admit(g ConnGate, ip netip.Addr) bool {
	f.st.Lock()
	defer f.st.Unlock()
	if f.ended {
		return false
	}
	if f.admitted {
		return true
	}
	if g != nil {
		release, ok := g(ip)
		if !ok {
			return false
		}
		f.release = release
	}
	f.admitted = true
	if f.pending {
		f.pending = false
		f.pc.unreserve(f.ip)
	}
	return true
}

// end: Stream zu - Platz beim Limit bzw. bei den offenen Handshakes freigeben.
func (f *vflow) end() {
	f.st.Lock()
	release, pending := f.release, f.pending
	f.ended, f.release, f.pending = true, nil, false
	f.st.Unlock()
	if pending {
		f.pc.unreserve(f.ip)
	}
	if release != nil {
		release()
	}
}

type virtPacketConn struct {
	in    chan vpkt
	done  chan struct{}
	once  sync.Once
	mu    sync.Mutex
	flows map[string]*vflow
	dl    time.Time     // Lesefrist (quic-go weckt damit beim Beenden)
	wake  chan struct{} // geaenderte Frist

	pending   map[netip.Addr]int // Streams ohne fertigen Handshake je Besucher (unter mu)
	pendingN  int
	pendingMx int // Grenze insgesamt (Tests kleiner)
}

func newVirtPacketConn() *virtPacketConn {
	return &virtPacketConn{in: make(chan vpkt, 1024), done: make(chan struct{}), flows: map[string]*vflow{}, wake: make(chan struct{}, 1),
		pending: map[netip.Addr]int{}, pendingMx: quicPendingMax}
}

// reserve: Platz fuer einen Stream ohne fertigen Handshake (false = Grenze erreicht).
func (p *virtPacketConn) reserve(ip netip.Addr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pendingN >= p.pendingMx || p.pending[ip] >= quicPendingPerIP {
		return false
	}
	p.pending[ip]++
	p.pendingN++
	return true
}

func (p *virtPacketConn) unreserve(ip netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending[ip] <= 1 {
		delete(p.pending, ip)
	} else {
		p.pending[ip]--
	}
	p.pendingN--
}

func (p *virtPacketConn) flow(a net.Addr) *vflow {
	if a == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.flows[a.String()]
}

// sniOK: SNI des Handshakes passt zum Namen, fuer den der CDN64-Server den Besucher durchreicht.
func (p *virtPacketConn) sniOK(h *tls.ClientHelloInfo) bool {
	if h.Conn == nil {
		return false
	}
	f := p.flow(h.Conn.RemoteAddr())
	if f == nil {
		return false
	}
	if f.host == "" {
		return true
	}
	name, _ := NormalizeName(h.ServerName)
	return name == f.host
}

func (p *virtPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		dl := p.dl
		p.mu.Unlock()
		var t *time.Timer
		var timer <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			t = time.NewTimer(d)
			timer = t.C
		}
		select {
		case pk := <-p.in:
			stopTimer(t)
			return copy(b, pk.data), pk.addr, nil
		case <-p.done:
			stopTimer(t)
			return 0, nil, net.ErrClosed
		case <-timer:
			return 0, nil, os.ErrDeadlineExceeded
		case <-p.wake:
			stopTimer(t)
		}
	}
}

// WriteTo schickt ein Datagramm zurueck in den Stream des Besuchers (unbekannt: verwerfen wie UDP).
func (p *virtPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case <-p.done:
		return 0, net.ErrClosed
	default:
	}
	p.mu.Lock()
	f := p.flows[addr.String()]
	p.mu.Unlock()
	if f == nil {
		return len(b), nil
	}
	f.mu.Lock()
	err := tunnel.WriteDatagram(f.c, b)
	f.mu.Unlock()
	if err != nil {
		return len(b), nil // Stream zu: wie ein verlorenes Paket
	}
	return len(b), nil
}

func (p *virtPacketConn) Close() error {
	p.once.Do(func() {
		close(p.done)
		p.mu.Lock()
		for _, f := range p.flows {
			_ = f.c.Close()
		}
		p.mu.Unlock()
	})
	return nil
}

func (p *virtPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv6unspecified, Port: 443}
}

func (p *virtPacketConn) SetDeadline(t time.Time) error { return p.SetReadDeadline(t) }

func (p *virtPacketConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.dl = t
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
	return nil
}

func (p *virtPacketConn) SetWriteDeadline(time.Time) error { return nil }

func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}
