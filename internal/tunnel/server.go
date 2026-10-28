package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// Peer ist eine angemeldete Node auf der Server-Seite.
type Peer struct {
	Tunnel  string
	Node    string
	Version string
	Caps    []string // Faehigkeiten der Node (Hello)
	Slot    int      // Nummer der Verbindung (parallele Sessions eines Tunnels)
	Since   time.Time
	Session Session
	Streams atomic.Int64 // offene Daten-Streams (Auswahl der am wenigsten belasteten Verbindung)
	ctrl    Stream
	wmu     sync.Mutex
}

// GoAway kuendigt der Node einen Neustart an (sie verbindet sich danach neu, laufende Streams duerfen enden).
func (p *Peer) GoAway() {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	_ = p.ctrl.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_ = writeMsg(p.ctrl, Control{Type: "goaway"})
}

// Server nimmt Tunnel-Verbindungen an (QUIC und TCP+TLS) und meldet angemeldete Nodes.
type Server struct {
	Name string              // eigener Name im Welcome (z. B. srv07)
	Caps []string            // Faehigkeiten im Welcome (z. B. CapQUIC)
	TLS  *tls.Config         // Zertifikat des Servers
	Auth func(h Hello) error // nil = angenommen; Fehlertext geht an die Node
	// Sessions: erlaubte parallele Verbindungen je Tunnel (nil bzw. < 1 = eine); hoehere Slots lehnt der Server ab
	Sessions func(tunnel string) int
	Up       func(p *Peer) // Node angemeldet
	Down     func(p *Peer) // Node getrennt
	Log      *slog.Logger  // nil = still

	mu    sync.Mutex
	wg    sync.WaitGroup
	slots map[string]*Peer // je Tunnel und Slot die angemeldete Verbindung (eine neue ersetzt die alte)
	ql    []*quic.Listener
	tl    []net.Listener
	conf  func() *quic.Config // Tests: eigene Einstellungen
	auth  time.Duration       // Zeit fuer die Anmeldung (Standard 5 s, G7)
}

func (s *Server) log() *slog.Logger {
	if s.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Log
}

func (s *Server) authTimeout() time.Duration {
	if s.auth > 0 {
		return s.auth
	}
	return 5 * time.Second
}

// ServeQUIC oeffnet einen UDP-Port fuer QUIC (blockiert nicht).
func (s *Server) ServeQUIC(addr string) (net.Addr, error) {
	conf := QUICConfig()
	if s.conf != nil {
		conf = s.conf()
	}
	ln, err := quic.ListenAddr(addr, tlsConfigFor(s.TLS), conf)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.ql = append(s.ql, ln)
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go s.handshake(&quicSession{c})
		}
	}()
	return ln.Addr(), nil
}

// ServeTCP oeffnet einen TCP-Port fuer den Ausweichweg (TLS + yamux, blockiert nicht).
func (s *Server) ServeTCP(addr string) (net.Addr, error) {
	ln, err := tls.Listen("tcp", addr, tlsConfigFor(s.TLS))
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.tl = append(s.tl, ln)
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
			go s.serveTLS(c.(*tls.Conn))
		}
	}()
	return ln.Addr(), nil
}

// ServeTCPConn nimmt eine schon angenommene TCP-Verbindung als Tunnel an (G1: Port 443, nach dem SNI-Namen des
// Servers vom Besucher-Eingang getrennt). Blockiert bis zum Ende der Sitzung.
func (s *Server) ServeTCPConn(c net.Conn) { s.serveTLS(tls.Server(c, tlsConfigFor(s.TLS))) }

// ServeQUICConn nimmt eine QUIC-Verbindung mit der ALPN des Tunnels an, die ein gemeinsamer Listener angenommen hat
// (G1: UDP 443 neben HTTP/3). Kehrt sofort zurueck.
func (s *Server) ServeQUICConn(c *quic.Conn) { go s.handshake(&quicSession{c}) }

func (s *Server) serveTLS(tc *tls.Conn) {
	_ = tc.SetDeadline(time.Now().Add(s.authTimeout()))
	if err := tc.Handshake(); err != nil || tc.ConnectionState().NegotiatedProtocol != ALPN {
		_ = tc.Close()
		return
	}
	_ = tc.SetDeadline(time.Time{})
	ys, err := newYamux(tc, true)
	if err != nil {
		_ = tc.Close()
		return
	}
	s.handshake(ys)
}

// handshake: Steuer-Stream der Node annehmen, Hello pruefen, Welcome senden, dann bis zum Ende Steuer-Stream lesen.
func (s *Server) handshake(sess Session) {
	ctx, cancel := context.WithTimeout(context.Background(), s.authTimeout())
	ctrl, err := sess.AcceptStream(ctx)
	cancel()
	if err != nil {
		_ = sess.Close("no hello")
		return
	}
	_ = ctrl.SetDeadline(time.Now().Add(s.authTimeout()))
	br := bufio.NewReaderSize(ctrl, 64<<10)
	var h Hello
	if err := readMsg(br, &h); err != nil || h.Tunnel == "" {
		_ = sess.Close("bad hello")
		return
	}
	if h.Version < Version-1 || h.Version > Version { // N und N-1
		_ = writeMsg(ctrl, Welcome{Version: Version, Edge: s.Name, Error: "unsupported version"})
		_ = sess.Close("version")
		return
	}
	if s.Auth != nil {
		if err := s.Auth(h); err != nil {
			_ = writeMsg(ctrl, Welcome{Version: Version, Edge: s.Name, Error: err.Error()})
			time.Sleep(100 * time.Millisecond) // Antwort zustellen, dann trennen
			_ = sess.Close("auth")
			s.log().Info("tunnel rejected", "tunnel", h.Tunnel, "from", sess.RemoteAddr().String(), "err", err)
			return
		}
	}
	limit := 1
	if s.Sessions != nil {
		limit = max(1, s.Sessions(h.Tunnel))
	}
	if h.Slot < 0 || h.Slot >= limit {
		_ = writeMsg(ctrl, Welcome{Version: Version, Edge: s.Name, Error: "session limit (" + strconv.Itoa(limit) + ")", Sessions: limit})
		time.Sleep(100 * time.Millisecond)
		_ = sess.Close("session limit")
		return
	}
	if err := writeMsg(ctrl, Welcome{Version: Version, Edge: s.Name, Caps: s.Caps, Sessions: limit}); err != nil {
		_ = sess.Close("write")
		return
	}
	_ = ctrl.SetDeadline(time.Time{})
	p := &Peer{Tunnel: h.Tunnel, Node: h.Node, Version: h.NodeVersion, Caps: h.Caps, Slot: h.Slot, Since: time.Now(), Session: sess, ctrl: ctrl}
	// Je Tunnel und Slot hoechstens eine Verbindung: eine neue (Neuverbindung, alte noch nicht als tot erkannt)
	// ersetzt die alte - so bleiben es nie mehr Verbindungen als die Grenze der Klasse.
	k := h.Tunnel + "/" + strconv.Itoa(h.Slot)
	s.mu.Lock()
	if s.slots == nil {
		s.slots = map[string]*Peer{}
	}
	old := s.slots[k]
	s.slots[k] = p
	s.mu.Unlock()
	if old != nil {
		// anderer Name oder andere Adresse: vermutlich zwei Nodes mit demselben Token (z. B. aus Backup geklont)
		oh, _, _ := net.SplitHostPort(old.Session.RemoteAddr().String())
		nh, _, _ := net.SplitHostPort(sess.RemoteAddr().String())
		if old.Node != p.Node || oh != nh {
			s.log().Warn("tunnel slot taken over, maybe two nodes with one token", "tunnel", h.Tunnel, "slot", h.Slot,
				"old_node", old.Node, "old_from", oh, "node", p.Node, "from", nh)
		}
		_ = old.Session.Close("replaced")
	}
	s.log().Info("tunnel up", "tunnel", h.Tunnel, "node", h.Node, "slot", h.Slot, "transport", sess.Transport(), "from", sess.RemoteAddr().String())
	if s.Up != nil {
		s.Up(p)
	}
	go func() { // die Node oeffnet nur den Steuer-Stream: jeder weitere ist ein Fehler, die Verbindung endet (Speicher)
		if st, err := sess.AcceptStream(context.Background()); err == nil {
			_ = st.Close()
			_ = sess.Close("unexpected stream")
			s.log().Warn("tunnel closed: node opened a stream", "tunnel", h.Tunnel, "slot", h.Slot)
		}
	}()
	// Steuer-Stream lesen, bis die Verbindung endet (die Node schickt derzeit nichts mehr)
	go func() {
		var m Control
		for readMsg(br, &m) == nil {
		}
		_ = sess.Close("control closed")
	}()
	<-sess.Done()
	s.mu.Lock()
	if s.slots[k] == p {
		delete(s.slots, k)
	}
	s.mu.Unlock()
	s.log().Info("tunnel down", "tunnel", h.Tunnel, "transport", sess.Transport())
	if s.Down != nil {
		s.Down(p)
	}
}

// Close schliesst die Listener (angemeldete Sessions bleiben, bis der Aufrufer sie trennt).
func (s *Server) Close() {
	s.mu.Lock()
	for _, l := range s.ql {
		_ = l.Close()
	}
	for _, l := range s.tl {
		_ = l.Close()
	}
	s.ql, s.tl = nil, nil
	s.mu.Unlock()
	s.wg.Wait()
}

// OpenStream oeffnet auf der Session einer Node einen Daten-Stream und schreibt den Kopf.
func OpenStream(ctx context.Context, p *Peer, h Header) (Stream, error) {
	st, err := p.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	_ = st.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := WriteHeader(st, h); err != nil {
		_ = st.Close()
		return nil, err
	}
	_ = st.SetWriteDeadline(time.Time{})
	p.Streams.Add(1)
	return &countedStream{Stream: st, n: &p.Streams}, nil
}
