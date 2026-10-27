package cdnedge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
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
	rr      atomic.Uint64             // Startpunkt reihum fuer die Auswahl der Verbindung (leastLoaded)
	streams atomic.Int64              // offene Daten-Streams
	total   atomic.Int64

	tlsConf    *tls.Config               // Zertifikat fuer Tunnel- und Nachbar-Port
	routes     atomic.Pointer[routes]    // Name -> Tunnel
	live       liveConns                 // offene Verbindungen je Name (live.go)
	stats      *stats                    // je Name
	guard      *guard                    // grober Schutz
	peeking    atomic.Int64              // Blocklisten-Treffer, die gerade ihren Namen lesen (blockedPeek)
	ja4List    atomic.Pointer[ja4Set]    // JA4 aus Honeypot64 (ja4.go)
	local      *chanListener             // Port 80 ohne bekannten Namen -> eigene Seite
	own        *chanListener             // Port 443 des eigenen Namens ohne Tunnel-ALPN (Browser) -> Infoseite
	ownSrv     *http.Server              // Infoseite fuer own
	peerRoots  *x509.CertPool            // Tests: CA der Nachbarn (sonst System)
	apiCfg     atomic.Pointer[apiConfig] // letzter Stand von ipv64
	apist      *apiState
	bw         *bandwidth
	lns        []net.Listener            // offene Besucher-/Nachbar-Ports
	term       *terminator               // Modus 2: TLS endet hier
	certs      *certStore                // Modus 2: Zertifikate je Name
	cache      *respCache                // Modus 3: Cache
	pm         *portmapper               // Modus 3: Portmapper
	qd         atomic.Pointer[quicDemux] // Modus 1: QUIC durchreichen (fuer /health; gesetzt in listenUDP443)
	mx         edgeCounters              // Zaehler nur fuer Prometheus (promexport.go)
	acmeTokens tokenStore                // HTTP-01 (Ausweg)
	acmeMu     sync.Mutex
	ca         *caState // Zertifizierungsstellen: Konten, Zaehlung (acmeca.go)
	// Tests: Zertifikat ohne ACME
	obtainHook func(ctx context.Context, name string) ([]byte, []byte, error)
	targetOK   func(netip.Addr) bool // Tests: Modus-3-Ziele auf 127.0.0.1 erlauben
}

// New legt den Dienst an.
func New(cfg *Config, log *slog.Logger, version string) *Server {
	s := &Server{cfg: cfg, log: log, version: version, started: time.Now(), peers: map[string][]*tunnel.Peer{},
		stats: &stats{m: map[string]*hostStat{}}, guard: newGuard(cfg.Shield), local: newChanListener(&net.TCPAddr{}),
		apist: &apiState{sent: map[string][repN]int64{}, client: &http.Client{Timeout: 30 * time.Second}}, bw: newBandwidth()}
	s.routes.Store(newRoutes(cfg.Hosts, nil))
	s.certs = newCertStore(filepath.Join(cfg.DataDir, "certs"))
	s.cache = newRespCache(filepath.Join(cfg.DataDir, "cache"), cfg.CacheTotalMB)
	s.pm = newPortmapper(s, cfg.PortRange)
	s.ca = newCAState(cfg.DataDir)
	capMbit := cfg.CapacityMbit
	if capMbit == 0 {
		capMbit = 1000
	}
	s.bw.setCapacity(capMbit)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("/", s.infoPage) // Infoseite (errorpage.go), andere Pfade 404 im selben Stil
	var h http.Handler = mux
	if cfg.TunnelListen != "" && cfg.TLSCert == "" {
		s.acme = &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(cfg.PublicHost),
			Cache: autocert.DirCache(filepath.Join(cfg.DataDir, "acme"))}
		h = s.acme.HTTPHandler(mux) // HTTP-01 fuer den eigenen Namen, sonst unveraendert
	}
	s.http = &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	// Port 80 wird je Verbindung nach dem Host der ersten Anfrage verteilt: die eigene Seite ohne Keep-Alive, damit
	// eine Folgeanfrage fuer einen Kunden-Namen auf einer neuen (richtig verteilten) Verbindung kommt.
	s.http.SetKeepAlivesEnabled(false)
	return s
}

// Run oeffnet die Ports und laeuft bis ctx endet; danach sauber beenden: Nodes bekommen GOAWAY, laufende Streams
// duerfen bis 10 s weiterlaufen, Anfragen bis 20 s.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenHTTP)
	if err != nil {
		return err
	}
	s.lns = append(s.lns, ln)
	s.log.Info("cdn64-edge listening", "http", ln.Addr().String(), "name", s.cfg.Name, "version", s.version)
	errc := make(chan error, 2)
	s.termInit() // vor dem ersten Besucher: handle80 gibt Modus 2/3 an s.term weiter
	go func() { errc <- s.http.Serve(s.local) }()
	go s.acceptLoop(ln, s.handle80, peek80)
	bctx, bcancel := context.WithCancel(ctx)
	defer bcancel()
	go s.blocklistLoop(bctx)
	go s.ja4Loop(bctx)
	go s.certLoop(bctx)
	go s.apiLoop(bctx)
	go s.rateLoop(bctx)
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-bctx.Done():
				return
			case <-t.C:
				s.guard.sweep()
				s.cacheSweep()
			}
		}
	}()
	go func() { // faire Drossel: jede Sekunde neu verteilen
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-bctx.Done():
				return
			case <-t.C:
				s.bw.fairRound()
			}
		}
	}()
	if s.cfg.TunnelListen != "" || s.cfg.PeerListen != "" {
		if s.tlsConf, err = s.tlsConfig(); err != nil {
			_ = s.http.Close()
			return err
		}
	}
	if s.cfg.TunnelListen != "" {
		if err := s.startTunnel(); err != nil {
			_ = s.http.Close()
			return err
		}
	}
	s.listenUDP443()
	if s.cfg.ListenHTTPS != "" && s.tlsConf != nil { // Browser auf https://<eigener Name>: Infoseite
		s.own = newChanListener(&net.TCPAddr{})
		s.ownSrv = &http.Server{Handler: http.HandlerFunc(s.infoPage), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
			MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0),
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.tlsConf.GetCertificate, Certificates: s.tlsConf.Certificates,
				NextProtos: []string{"h2", "http/1.1"}}}
		go func() { _ = s.ownSrv.ServeTLS(s.own, "", "") }()
	}
	if s.cfg.ListenHTTPS != "" {
		l, err := net.Listen("tcp", s.cfg.ListenHTTPS)
		if err != nil {
			return err
		}
		s.lns = append(s.lns, l)
		go s.acceptLoop(l, s.handle443, peek443)
		s.log.Info("visitors listening", "https", l.Addr().String(), "hosts", len(s.cfg.Hosts))
	}
	if s.cfg.PeerListen != "" {
		l, err := tls.Listen("tcp", s.cfg.PeerListen, &tls.Config{GetCertificate: s.tlsConf.GetCertificate, Certificates: s.tlsConf.Certificates,
			MinVersion: tls.VersionTLS13})
		if err != nil {
			return err
		}
		s.lns = append(s.lns, l)
		go s.servePeer(l)
	}
	if err := s.startMetrics(); err != nil {
		return err
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
	for _, l := range s.lns { // keine neuen Besucher; laufende duerfen enden
		_ = l.Close()
	}
	s.pm.close()
	s.shutdown()
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s.termClose(sctx)
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
	s.tun = &tunnel.Server{Name: s.cfg.Name, TLS: s.tlsConf, Log: s.log, Auth: s.auth, Up: s.up, Down: s.down, Sessions: s.sessionsFor}
	if s.cfg.ListenHTTPS != "" { // QUIC (HTTP/3) fuer Modus 1 durchreichen (quicpass.go)
		s.tun.Caps = []string{tunnel.CapQUIC}
	}
	if _, err := s.tun.ServeQUIC(s.cfg.TunnelListen); err != nil {
		return err
	}
	if _, err := s.tun.ServeTCP(s.cfg.TunnelListen); err != nil {
		return err
	}
	s.log.Info("tunnel listening", "addr", s.cfg.TunnelListen)
	return nil
}

// auth: Tunnel bekannt (feste Konfiguration oder ipv64, nicht gesperrt) und Token passt (Hashes in konstanter Zeit).
func (s *Server) auth(h tunnel.Hello) error {
	sum := sha256.Sum256([]byte(h.Token))
	match := func(id, hash string) bool {
		want, err := hex.DecodeString(hash)
		return id == h.Tunnel && err == nil && subtle.ConstantTimeCompare(want, sum[:]) == 1
	}
	for _, t := range s.cfg.Tunnels {
		if match(t.ID, t.TokenSHA256) {
			return nil
		}
	}
	if c := s.apiCfg.Load(); c != nil {
		for _, t := range c.Tunnels {
			if match(t.ID, t.TokenSHA256) {
				if t.Blocked {
					return errors.New("tunnel blocked")
				}
				return nil
			}
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

// sessionsFor: erlaubte parallele Verbindungen eines Tunnels (ipv64 je Klasse, feste Konfiguration; mindestens eine,
// hoechstens tunnel.MaxSessions).
func (s *Server) sessionsFor(id string) int {
	n := 0
	for _, t := range s.cfg.Tunnels {
		if t.ID == id {
			n = t.Sessions
		}
	}
	if c := s.apiCfg.Load(); c != nil {
		for _, t := range c.Tunnels {
			if t.ID == id {
				n = t.Sessions
			}
		}
	}
	return min(max(n, 1), tunnel.MaxSessions)
}

// peer: am wenigsten belastete Verbindung eines Tunnels (offene Streams; gleich viele: die neueste), nil = nicht
// verbunden. Mehrere Verbindungen gibt es bei parallelen Sessions (Business/Company) und kurz beim Neuverbinden.
func (s *Server) peer(id string) *tunnel.Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" { // T1-Testeingang ohne feste Zuordnung: irgendein Tunnel
		for _, l := range s.peers {
			return leastLoaded(l, nil, int(s.rr.Add(1)))
		}
		return nil
	}
	return leastLoaded(s.peers[id], nil, int(s.rr.Add(1)))
}

// leastLoaded: Verbindung mit den wenigsten offenen Streams ausser skip. Bei Gleichstand reihum ab start: viele
// Besucher gleichzeitig (bevor die Zaehler steigen) verteilen sich so trotzdem.
func leastLoaded(l []*tunnel.Peer, skip map[*tunnel.Peer]bool, start int) *tunnel.Peer {
	var best *tunnel.Peer
	for i := range l {
		p := l[(start+i)%len(l)]
		if skip[p] {
			continue
		}
		if best == nil || p.Streams.Load() < best.Streams.Load() {
			best = p
		}
	}
	return best
}

// peerFor: erste verbundene Node aus einer Liste von Tunnels (Reihenfolge = Prioritaet).
func (s *Server) peerFor(ids []string) *tunnel.Peer {
	for _, id := range ids {
		if id != "" {
			if p := s.peer(id); p != nil {
				return p
			}
		}
	}
	return nil
}

// open: Daten-Stream zu einem Tunnel mit Kopf; zaehlt offene Streams.
func (s *Server) open(ctx context.Context, id string, h tunnel.Header) (net.Conn, error) {
	return s.openPeer(ctx, s.peer(id), h)
}

func (s *Server) openPeer(ctx context.Context, p *tunnel.Peer, h tunnel.Header) (net.Conn, error) {
	if p == nil {
		return nil, errors.New("tunnel not connected")
	}
	h.Edge, h.Ray = s.cfg.Name, ray()
	st, err := tunnel.OpenStream(ctx, p, h)
	for tried := map[*tunnel.Peer]bool{p: true}; err != nil && ctx.Err() == nil; { // andere Verbindung desselben Tunnels
		s.mu.Lock()
		next := leastLoaded(s.peers[p.Tunnel], tried, 0)
		s.mu.Unlock()
		if next == nil {
			break
		}
		tried[next] = true
		st, err = tunnel.OpenStream(ctx, next, h)
	}
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
	Status   string              `json:"status"`
	Name     string              `json:"name"`
	Version  string              `json:"version"`
	Location string              `json:"location,omitempty"`
	Started  string              `json:"started,omitempty"`
	UptimeS  int64               `json:"uptime_s,omitempty"`
	Go       string              `json:"go,omitempty"`
	Tunnels  []TunnelInfo        `json:"tunnels,omitempty"`
	Streams  int64               `json:"streams,omitempty"`
	Total    int64               `json:"streams_total,omitempty"`
	Hosts    map[string]HostInfo `json:"hosts,omitempty"`
	Open     int64               `json:"conns_open,omitempty"` // Besucher-Verbindungen gerade
	Rejected int64               `json:"rejected,omitempty"`   // vom Schutz abgewiesen seit dem Start
	Blocked  int                 `json:"blocklist_entries,omitempty"`
	API      *APIInfo            `json:"api,omitempty"`
	Certs    map[string]string   `json:"certs,omitempty"`     // Modus 2: Name -> gueltig bis
	QUICPass int                 `json:"quic_pass,omitempty"` // Modus 1: durchgereichte QUIC-Besucher gerade
	LoadMbit float64             `json:"load_mbit,omitempty"` // Durchsatz gerade (alle Accounts)
	CapMbit  float64             `json:"capacity_mbit,omitempty"`
	Throttle map[int]float64     `json:"throttled_mbit,omitempty"` // faire Drossel: Account -> Mbit/s
	ACME     string              `json:"acme,omitempty"`           // ok | warn (Domain bei 80 % der Woche oder Grenze erreicht) | error (Ausweg fehlt)
	CA       *caInfo             `json:"ca,omitempty"`             // Einzelheiten (nur lokal)
}

// APIInfo: Stand der Steuerung von ipv64 (nur lokal sichtbar).
type APIInfo struct {
	Version string `json:"config_version,omitempty"`
	Hosts   int    `json:"hosts"`
	Tunnels int    `json:"tunnels"`
	LastOK  string `json:"last_ok,omitempty"`
	Error   string `json:"error,omitempty"`
}

// HostInfo: Zaehler eines Namens seit dem Start (nur lokal sichtbar).
type HostInfo struct {
	Conns    int64 `json:"conns"`
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
	ViaPeer  int64 `json:"via_peer,omitempty"`
	NoTunnel int64 `json:"no_tunnel,omitempty"`
	Requests int64 `json:"requests,omitempty"` // Modus 2
	Rejected int64 `json:"rejected,omitempty"` // Modus 2: Anfrage-Limit
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
	if s.cfg.APIURL != "" { // auch von aussen sichtbar, z. B. fuer einen Healthcheck mit Stichwort
		ci := s.caInfo()
		h.ACME = "ok"
		if len(ci.Warn) > 0 || len(ci.Cooldown) > 0 {
			h.ACME = "warn"
			if ci.Fallback == "off" || ci.LastErrors[caZeroSSL] != "" {
				h.ACME = "error"
			}
		}
		if local(r) {
			h.CA = &ci
		}
	}
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
		h.Open, h.Rejected, h.Blocked = s.guard.open.Load(), s.guard.rejected.Load(), s.guard.set.Load().Total()
		if qd := s.qd.Load(); qd != nil {
			h.QUICPass = qd.open()
		}
		h.LoadMbit, h.CapMbit, h.Throttle = s.bw.fairStatus()
		if len(h.Throttle) == 0 {
			h.Throttle = nil
		}
		s.stats.mu.Lock()
		if len(s.stats.m) > 0 {
			h.Hosts = map[string]HostInfo{}
		}
		for n, st := range s.stats.m {
			h.Hosts[n] = HostInfo{Conns: st.Conns.Load(), BytesIn: st.BytesIn.Load(), BytesOut: st.BytesOut.Load(), ViaPeer: st.ViaPeer.Load(),
				NoTunnel: st.NoTunnel.Load(), Requests: st.Requests.Load(), Rejected: st.Rejected.Load()}
		}
		s.stats.mu.Unlock()
		for n, na := range s.certs.list() {
			if h.Certs == nil {
				h.Certs = map[string]string{}
			}
			h.Certs[n] = na.UTC().Format(time.RFC3339)
		}
		if s.cfg.APIURL != "" {
			ai := &APIInfo{}
			if c := s.apiCfg.Load(); c != nil {
				ai.Version, ai.Hosts, ai.Tunnels = c.Version, len(c.Hosts), len(c.Tunnels)
			}
			s.apist.mu.Lock()
			if !s.apist.lastOK.IsZero() {
				ai.LastOK = s.apist.lastOK.UTC().Format(time.RFC3339)
			}
			ai.Error = s.apist.lastErr
			s.apist.mu.Unlock()
			h.API = ai
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(h)
}

func local(r *http.Request) bool {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	return err == nil && ap.Addr().Unmap().IsLoopback()
}
