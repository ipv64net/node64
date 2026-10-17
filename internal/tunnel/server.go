package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Peer ist eine angemeldete Node auf der Server-Seite.
type Peer struct {
	Tunnel  string
	Node    string
	Version string
	Since   time.Time
	Session Session
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
	TLS  *tls.Config         // Zertifikat des Servers
	Auth func(h Hello) error // nil = angenommen; Fehlertext geht an die Node
	Up   func(p *Peer)       // Node angemeldet
	Down func(p *Peer)       // Node getrennt
	Log  *slog.Logger        // nil = still

	mu   sync.Mutex
	wg   sync.WaitGroup
	ql   []*quic.Listener
	tl   []net.Listener
	conf func() *quic.Config // Tests: eigene Einstellungen
	auth time.Duration       // Zeit fuer die Anmeldung (Standard 5 s, G7)
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
			go func() {
				tc := c.(*tls.Conn)
				_ = tc.SetDeadline(time.Now().Add(s.authTimeout()))
				if err := tc.Handshake(); err != nil || tc.ConnectionState().NegotiatedProtocol != ALPN {
					_ = c.Close()
					return
				}
				_ = tc.SetDeadline(time.Time{})
				ys, err := newYamux(c, true)
				if err != nil {
					_ = c.Close()
					return
				}
				s.handshake(ys)
			}()
		}
	}()
	return ln.Addr(), nil
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
	if err := writeMsg(ctrl, Welcome{Version: Version, Edge: s.Name}); err != nil {
		_ = sess.Close("write")
		return
	}
	_ = ctrl.SetDeadline(time.Time{})
	p := &Peer{Tunnel: h.Tunnel, Node: h.Node, Version: h.NodeVersion, Since: time.Now(), Session: sess, ctrl: ctrl}
	s.log().Info("tunnel up", "tunnel", h.Tunnel, "node", h.Node, "transport", sess.Transport(), "from", sess.RemoteAddr().String())
	if s.Up != nil {
		s.Up(p)
	}
	// Steuer-Stream lesen, bis die Verbindung endet (die Node schickt derzeit nichts mehr)
	go func() {
		var m Control
		for readMsg(br, &m) == nil {
		}
		_ = sess.Close("control closed")
	}()
	<-sess.Done()
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
	return st, nil
}
