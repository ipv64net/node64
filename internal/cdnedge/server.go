package cdnedge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/ipv64net/node64/internal/tunnel"
)

// Server ist der laufende Dienst: /health und ACME auf Port 80, Tunnel-Ende auf tunnel_listen (UDP+TCP), in T1
// ausserdem ein lokaler Testeingang. Der Besucher-Eingang (443/80 nach Namen) folgt in T2.
type Server struct {
	cfg     *Config
	log     *slog.Logger
	version string
	started time.Time
	http    *http.Server
	tun     *tunnel.Server
	acme    *autocert.Manager

	mu      sync.Mutex
	peers   map[string][]*tunnel.Peer // je Tunnel die angemeldeten Verbindungen (neueste zuletzt)
	streams atomic.Int64              // offene Daten-Streams
	total   atomic.Int64
}

// New legt den Dienst an.
func New(cfg *Config, log *slog.Logger, version string) *Server {
	s := &Server{cfg: cfg, log: log, version: version, started: time.Now(), peers: map[string][]*tunnel.Peer{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("/", notFound)
	var h http.Handler = mux
	if cfg.TunnelListen != "" && cfg.TLSCert == "" {
		s.acme = &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(cfg.PublicHost),
			Cache: autocert.DirCache(filepath.Join(cfg.DataDir, "acme"))}
		h = s.acme.HTTPHandler(mux) // HTTP-01 fuer den eigenen Namen, sonst unveraendert
	}
	s.http = &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	return s
}

// Run oeffnet die Ports und laeuft bis ctx endet; danach sauber beenden: Nodes bekommen GOAWAY, laufende Streams
// duerfen bis 10 s weiterlaufen, Anfragen bis 20 s.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenHTTP)
	if err != nil {
		return err
	}
	s.log.Info("cdn64-edge listening", "http", ln.Addr().String(), "name", s.cfg.Name, "version", s.version)
	errc := make(chan error, 2)
	go func() { errc <- s.http.Serve(ln) }()
	if s.cfg.TunnelListen != "" {
		if err := s.startTunnel(); err != nil {
			_ = s.http.Close()
			return err
		}
	}
	if s.cfg.DebugListen != "" {
		dl, err := net.Listen("tcp", s.cfg.DebugListen)
		if err != nil {
			return err
		}
		defer dl.Close()
		go s.serveDebug(dl)
	}
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	s.shutdown()
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = s.http.Shutdown(sctx)
	if errors.Is(err, context.DeadlineExceeded) {
		err = nil
	}
	s.log.Info("cdn64-edge stopped")
	return err
}

func (s *Server) tlsConfig() (*tls.Config, error) {
	if s.cfg.TLSCert != "" {
		crt, err := tls.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{crt}}, nil
	}
	// Zertifikat gleich beim Start holen (nicht erst bei der ersten Node)
	go func() {
		hello := &tls.ClientHelloInfo{ServerName: s.cfg.PublicHost, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
			SupportedCurves: []tls.CurveID{tls.CurveP256}, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}}
		if _, err := s.acme.GetCertificate(hello); err != nil {
			s.log.Warn("certificate not obtained", "host", s.cfg.PublicHost, "err", err)
		} else {
			s.log.Info("certificate ready", "host", s.cfg.PublicHost)
		}
	}()
	return &tls.Config{GetCertificate: s.acme.GetCertificate}, nil
}

func (s *Server) startTunnel() error {
	conf, err := s.tlsConfig()
	if err != nil {
		return err
	}
	s.tun = &tunnel.Server{Name: s.cfg.Name, TLS: conf, Log: s.log, Auth: s.auth, Up: s.up, Down: s.down}
	if _, err := s.tun.ServeQUIC(s.cfg.TunnelListen); err != nil {
		return err
	}
	if _, err := s.tun.ServeTCP(s.cfg.TunnelListen); err != nil {
		return err
	}
	s.log.Info("tunnel listening", "addr", s.cfg.TunnelListen)
	return nil
}

// auth: Tunnel bekannt und Token passt (Vergleich der Hashes in konstanter Zeit).
func (s *Server) auth(h tunnel.Hello) error {
	sum := sha256.Sum256([]byte(h.Token))
	for _, t := range s.cfg.Tunnels {
		want, err := hex.DecodeString(t.TokenSHA256)
		if t.ID == h.Tunnel && err == nil && subtle.ConstantTimeCompare(want, sum[:]) == 1 {
			return nil
		}
	}
	return errors.New("unknown tunnel or token")
}

func (s *Server) up(p *tunnel.Peer) {
	s.mu.Lock()
	s.peers[p.Tunnel] = append(s.peers[p.Tunnel], p)
	s.mu.Unlock()
}

func (s *Server) down(p *tunnel.Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.peers[p.Tunnel]
	for i, x := range list {
		if x == p {
			list = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(s.peers, p.Tunnel)
	} else {
		s.peers[p.Tunnel] = list
	}
}

// peer: neueste Verbindung eines Tunnels (nil = nicht verbunden).
func (s *Server) peer(id string) *tunnel.Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" { // T1-Testeingang ohne feste Zuordnung: irgendein Tunnel
		for _, l := range s.peers {
			return l[len(l)-1]
		}
		return nil
	}
	if l := s.peers[id]; len(l) > 0 {
		return l[len(l)-1]
	}
	return nil
}

// open: Daten-Stream zu einem Tunnel mit Kopf; zaehlt offene Streams.
func (s *Server) open(ctx context.Context, id string, h tunnel.Header) (net.Conn, error) {
	p := s.peer(id)
	if p == nil {
		return nil, errors.New("tunnel not connected")
	}
	h.Edge, h.Ray = s.cfg.Name, ray()
	st, err := tunnel.OpenStream(ctx, p, h)
	if err != nil {
		return nil, err
	}
	s.streams.Add(1)
	s.total.Add(1)
	return &counted{Stream: st, n: &s.streams}, nil
}

type counted struct {
	tunnel.Stream
	n    *atomic.Int64
	once sync.Once
}

func (c *counted) Close() error {
	err := c.Stream.Close()
	c.once.Do(func() { c.n.Add(-1) })
	return err
}

func ray() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// serveDebug (T1): lokale Verbindungen roh als "http80" in den Tunnel, z. B. fuer Durchsatz-Messungen per curl.
func (s *Server) serveDebug(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			st, err := s.open(ctx, s.cfg.DebugTunnel, tunnel.Header{Kind: tunnel.KindHTTP80, Client: c.RemoteAddr().String(), Port: 80})
			cancel()
			if err != nil {
				s.log.Debug("debug: no tunnel", "err", err)
				_ = c.Close()
				return
			}
			tunnel.Join(c, st)
		}()
	}
}

// shutdown: Nodes vorwarnen, keine neuen Tunnels, laufende Streams kurz enden lassen, dann trennen.
func (s *Server) shutdown() {
	if s.tun == nil {
		return
	}
	s.mu.Lock()
	var all []*tunnel.Peer
	for _, l := range s.peers {
		all = append(all, l...)
	}
	s.mu.Unlock()
	for _, p := range all {
		p.GoAway()
	}
	s.tun.Close()
	for i := 0; i < 100 && s.streams.Load() > 0; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	for _, p := range all {
		_ = p.Session.Close("server restart")
	}
}

// Health ist die Antwort von /health. Von aussen nur Status, Name und Version; Einzelheiten nur lokal.
type Health struct {
	Status   string       `json:"status"`
	Name     string       `json:"name"`
	Version  string       `json:"version"`
	Location string       `json:"location,omitempty"`
	Started  string       `json:"started,omitempty"`
	UptimeS  int64        `json:"uptime_s,omitempty"`
	Go       string       `json:"go,omitempty"`
	Tunnels  []TunnelInfo `json:"tunnels,omitempty"`
	Streams  int64        `json:"streams,omitempty"`
	Total    int64        `json:"streams_total,omitempty"`
}

// TunnelInfo: eine angemeldete Verbindung (nur lokal sichtbar).
type TunnelInfo struct {
	ID        string  `json:"id"`
	Node      string  `json:"node,omitempty"`
	Version   string  `json:"node_version,omitempty"`
	Transport string  `json:"transport"`
	From      string  `json:"from"`
	Since     string  `json:"since"`
	RTTms     float64 `json:"rtt_ms"`
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	h := Health{Status: "ok", Name: s.cfg.Name, Version: s.version}
	if local(r) {
		h.Location, h.Started, h.UptimeS, h.Go = s.cfg.Location, s.started.UTC().Format(time.RFC3339), int64(time.Since(s.started).Seconds()), runtime.Version()
		h.Streams, h.Total = s.streams.Load(), s.total.Load()
		s.mu.Lock()
		for id, l := range s.peers {
			for _, p := range l {
				h.Tunnels = append(h.Tunnels, TunnelInfo{ID: id, Node: p.Node, Version: p.Version, Transport: p.Session.Transport(),
					From: p.Session.RemoteAddr().String(), Since: p.Since.UTC().Format(time.RFC3339), RTTms: float64(p.Session.RTT().Microseconds()) / 1000})
			}
		}
		s.mu.Unlock()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(h)
}

func local(r *http.Request) bool {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	return err == nil && ap.Addr().Unmap().IsLoopback()
}

// notFound: neutrale Antwort ohne Hinweis auf den Dienst.
func notFound(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("404 not found\n"))
}
