package tunnel

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/quic-go/quic-go"
)

// Stream ist ein Kanal im Tunnel (eine Besucher-Verbindung bzw. der Steuer-Stream).
type Stream interface {
	net.Conn
	CloseWrite() error // halb schliessen: nichts mehr senden, weiter lesen
}

// Session ist eine angemeldete oder sich anmeldende Tunnel-Verbindung (QUIC oder TCP+yamux).
type Session interface {
	OpenStream(ctx context.Context) (Stream, error)
	AcceptStream(ctx context.Context) (Stream, error)
	Close(reason string) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Transport() string // "quic" | "tcp"
	RTT() time.Duration
	Done() <-chan struct{}
}

// QUICConfig: Wachhalten alle 10 s (Router-Zeitlimits fuer UDP oft 30 s), nach 30 s ohne Antwort tot - so merkt
// der Server einen weggefallenen Tunnel schnell und nimmt den Nachbarn; kleine Startpakete mit Path-MTU-Discovery
// (DS-Lite, PPPoE, IPv6-Tunnel; G4); Fenster fuer hohen Durchsatz.
func QUICConfig() *quic.Config {
	return &quic.Config{KeepAlivePeriod: 10 * time.Second, MaxIdleTimeout: 30 * time.Second, HandshakeIdleTimeout: 10 * time.Second,
		MaxIncomingStreams: 10000, InitialStreamReceiveWindow: 512 << 10, MaxStreamReceiveWindow: 6 << 20, MaxConnectionReceiveWindow: 15 << 20}
}

func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.AcceptBacklog = 1024
	c.KeepAliveInterval = 10 * time.Second
	c.ConnectionWriteTimeout = 15 * time.Second
	c.MaxStreamWindowSize = 6 << 20
	c.StreamOpenTimeout = 30 * time.Second
	c.StreamCloseTimeout = 5 * time.Minute
	c.LogOutput = io.Discard
	return c
}

// ---------------------------------------------------------------- QUIC

type quicSession struct{ c *quic.Conn }

func (s *quicSession) OpenStream(ctx context.Context) (Stream, error) {
	st, err := s.c.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &quicStream{Stream: st, s: s.c}, nil
}

func (s *quicSession) AcceptStream(ctx context.Context) (Stream, error) {
	st, err := s.c.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &quicStream{Stream: st, s: s.c}, nil
}

func (s *quicSession) Close(reason string) error { return s.c.CloseWithError(0, reason) }
func (s *quicSession) LocalAddr() net.Addr       { return s.c.LocalAddr() }
func (s *quicSession) RemoteAddr() net.Addr      { return s.c.RemoteAddr() }
func (s *quicSession) Transport() string         { return "quic" }
func (s *quicSession) RTT() time.Duration        { return s.c.ConnectionStats().SmoothedRTT }
func (s *quicSession) Done() <-chan struct{}     { return s.c.Context().Done() }

type quicStream struct {
	*quic.Stream
	s *quic.Conn
}

func (q *quicStream) Close() error {
	q.CancelRead(0)
	return q.Stream.Close()
}
func (q *quicStream) CloseWrite() error    { return q.Stream.Close() }
func (q *quicStream) LocalAddr() net.Addr  { return q.s.LocalAddr() }
func (q *quicStream) RemoteAddr() net.Addr { return q.s.RemoteAddr() }

// ---------------------------------------------------------------- TCP+TLS mit yamux (Ausweichweg)

type yamuxSession struct {
	s   *yamux.Session
	rtt atomic.Int64 // zuletzt gemessen (Ping alle 15 s im Hintergrund, RTT blockiert nie)
}

func newYamux(c net.Conn, server bool) (*yamuxSession, error) {
	var s *yamux.Session
	var err error
	if server { // die Node oeffnet nur den Steuer-Stream: kleiner Rueckstau (yamux-Standard) statt 1024 x 256 KB vor der Anmeldung
		conf := yamuxConfig()
		conf.AcceptBacklog = 256
		s, err = yamux.Server(c, conf)
	} else {
		s, err = yamux.Client(c, yamuxConfig())
	}
	if err != nil {
		return nil, err
	}
	y := &yamuxSession{s: s}
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			if d, err := s.Ping(); err == nil {
				y.rtt.Store(int64(d))
			}
			select {
			case <-s.CloseChan():
				return
			case <-t.C:
			}
		}
	}()
	return y, nil
}

func (y *yamuxSession) OpenStream(context.Context) (Stream, error) {
	st, err := y.s.OpenStream()
	if err != nil {
		return nil, err
	}
	return &yamuxStream{st}, nil
}

func (y *yamuxSession) AcceptStream(ctx context.Context) (Stream, error) {
	st, err := y.s.AcceptStreamWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return &yamuxStream{st}, nil
}

func (y *yamuxSession) Close(string) error   { return y.s.Close() }
func (y *yamuxSession) LocalAddr() net.Addr  { return y.s.LocalAddr() }
func (y *yamuxSession) RemoteAddr() net.Addr { return y.s.RemoteAddr() }
func (y *yamuxSession) Transport() string    { return "tcp" }
func (y *yamuxSession) Done() <-chan struct{} {
	return y.s.CloseChan()
}

func (y *yamuxSession) RTT() time.Duration { return time.Duration(y.rtt.Load()) }

// yamuxStream: Close von yamux schliesst nur die eigene Richtung (FIN); fuer "ganz zu" zusaetzlich Lesen beenden.
type yamuxStream struct{ *yamux.Stream }

func (y *yamuxStream) CloseWrite() error { return y.Stream.Close() }
func (y *yamuxStream) Close() error {
	_ = y.Stream.SetReadDeadline(time.Now())
	return y.Stream.Close()
}

// tlsConfigFor: TLS fuer beide Wege (TLS 1.3, eigene ALPN).
func tlsConfigFor(base *tls.Config) *tls.Config {
	c := base.Clone()
	c.MinVersion = tls.VersionTLS13
	c.NextProtos = []string{ALPN}
	return c
}
