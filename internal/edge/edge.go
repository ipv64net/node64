// Package edge ist der gemeinsame Eingang von Node64 fuer HTTP (Port 80) und HTTPS (443, ueber TCP und fuer
// HTTP/3 ueber UDP). Ein Port laesst sich je Adresse nur einmal oeffnen; deshalb gehoeren 80/443 dem Kern und
// nicht einem Modul. Module melden Namen an (Proxy-Hosts von CDN64, DoH von DNS64, ACME), Edge waehlt bei TLS
// das Zertifikat nach dem Namen in der ersten Nachricht des Browsers (SNI) und verteilt Anfragen nach dem
// Host-Kopf. Ein Name gehoert genau einem Teil.
//
// Edge oeffnet seine Ports nur, solange es Abnehmer gibt; meldet sich der letzte ab, schliesst es sie wieder.
// Fuer die Freigabe eines Abnehmers (z. B. DNS nur fuers eigene Netz) zaehlt immer die echte Gegenstelle der
// Verbindung, nie ein Kopf wie X-Forwarded-For.
package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/ipv64net/node64/internal/ports"
)

// Owner ist der Name, unter dem Edge seine Ports in der Port-Verwaltung fuehrt.
const Owner = "edge"

// Antwort bei unbekanntem Namen.
const (
	DefaultNotFound = "404"      // neutrale Seite "404 Not Found"
	DefaultClose    = "close"    // Verbindung ohne Antwort schliessen (wie nginx 444)
	DefaultRedirect = "redirect" // Weiterleitung auf DefaultURL
	DefaultHTML     = "html"     // eigene Seite (DefaultHTML)
)

const maxDefaultHTML = 64 << 10

// Config sind die Einstellungen des Eingangs.
type Config struct {
	Bind       string `json:"bind"`        // Adresse, "" = alle
	HTTPPort   int    `json:"http_port"`   // 0 = aus
	HTTPSPort  int    `json:"https_port"`  // 0 = aus
	PublicPort int    `json:"public_port"` // HTTPS-Port aus Sicht der Besucher (Weiterleitung, Alt-Svc), 0 = HTTPSPort
	HTTP3      bool   `json:"http3"`       // HTTP/3 (QUIC) auf HTTPSPort/UDP
	Default    string `json:"default"`     // DefaultNotFound, DefaultClose, DefaultRedirect, DefaultHTML
	DefaultURL string `json:"default_url"` // Ziel bei DefaultRedirect (http/https)
	// DefaultHTML: eigene Seite bei DefaultHTML (hoechstens 64 KB)
	DefaultPage string `json:"default_html"`
}

// DefaultConfig: 80/443 auf allen Adressen, HTTP/3 an, unbekannte Namen bekommen 404.
func DefaultConfig() Config {
	return Config{HTTPPort: 80, HTTPSPort: 443, HTTP3: true, Default: DefaultNotFound}
}

// Public: HTTPS-Port aus Sicht der Besucher.
func (c Config) Public() int { return c.publicPort() }

func (c Config) publicPort() int {
	if c.PublicPort > 0 {
		return c.PublicPort
	}
	return c.HTTPSPort
}

// Validate prueft die Einstellungen.
func (c *Config) Validate() error {
	for _, p := range []int{c.HTTPPort, c.HTTPSPort, c.PublicPort} {
		if p < 0 || p > 65535 {
			return fmt.Errorf("port %d out of range", p)
		}
	}
	if c.HTTPPort > 0 && c.HTTPPort == c.HTTPSPort {
		return errors.New("http and https port must differ")
	}
	if c.Bind != "" {
		if _, err := netip.ParseAddr(strings.Trim(c.Bind, "[]")); err != nil {
			return fmt.Errorf("bind address %q invalid", c.Bind)
		}
	}
	switch c.Default {
	case "":
		c.Default = DefaultNotFound
	case DefaultNotFound, DefaultClose:
	case DefaultRedirect:
		u, err := url.Parse(c.DefaultURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("default_url must be an http or https address")
		}
	case DefaultHTML:
		if strings.TrimSpace(c.DefaultPage) == "" {
			return errors.New("default_html must not be empty")
		}
	default:
		return fmt.Errorf("default %q unknown", c.Default)
	}
	if len(c.DefaultPage) > maxDefaultHTML {
		return errors.New("default_html larger than 64 KB")
	}
	return nil
}

// Certs liefert Zertifikate (Zertifikatsverwaltung des Kerns).
type Certs interface {
	ForName(name string) *tls.Certificate // passendes gueltiges Zertifikat (auch Wildcard), nil = keins
	ByID(id int64) *tls.Certificate       // ein bestimmtes, nil = unbekannt oder ungueltig
}

// Route ist ein angemeldeter Name eines Abnehmers.
type Route struct {
	Names   []string     // exakt ("nas.example.com") oder Wildcard ("*.example.com", eine Ebene)
	Path    string       // Praefix, "" = alles; z. B. "/dns-query"
	Handler http.Handler // HTTPS (TCP und HTTP/3); nil = nur HTTP
	HTTP    http.Handler // Port 80; nil = Weiterleitung auf HTTPS (wenn Handler gesetzt), sonst 404
	CertID  int64        // festes Zertifikat, 0 = passendes nach Namen
	MinTLS  uint16       // tls.VersionTLS12 (Standard) oder tls.VersionTLS13
	BSI     bool         // TLS nach BSI TR-02102-2 (bsiSuites, bsiGroups)
	NoHTTP2 bool         // nur HTTP/1.1 ueber TCP
	HTTP3   bool         // auch ueber HTTP/3 (wenn der Eingang es anbietet)
	// Passthrough: TLS nicht hier beenden, sondern die Verbindung roh an dieses Ziel (host:port) geben (nur TCP,
	// Handler bleibt nil). Count zaehlt durchgereichte Verbindungen (optional).
	Passthrough string
	Count       func()
	// GetCert liefert das Zertifikat fuer diese Route bei jedem Handshake (z. B. die eigene CA von DNS64, Wechsel
	// ohne Neuanmeldung); nil = CertID bzw. passendes Zertifikat nach Namen.
	GetCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// Fallback: die Route gilt auch fuer Anfragen, deren Name zu keiner Route gehoert (Aufruf per IP, ohne SNI),
	// z. B. DoH unter https://<node-ip>/dns-query. Das Zertifikat dieser Route gilt dann fuer alle Aufrufe per IP
	// (andere Pfade bekommen die Standardseite). Hoechstens ein Abnehmer darf Fallback setzen.
	Fallback bool
	// NoHTTP: kein Port 80 fuer diese Route (keine Weiterleitung). Gibt es nur solche Routen, bleibt 80 zu.
	NoHTTP bool
	// Allow begrenzt auf bestimmte Clients (echte Gegenstelle der Verbindung); alle anderen bekommen eine
	// neutrale 404, als gaebe es den Namen nicht. nil = alle.
	Allow func(ip netip.Addr) bool
}

// NameTakenError: ein Name gehoert schon einem anderen Abnehmer.
type NameTakenError struct{ Name, Owner string }

func (e *NameTakenError) Error() string {
	return fmt.Sprintf("name %s is already used by %s", e.Name, e.Owner)
}

const acmePath = "/.well-known/acme-challenge/"

// Edge ist der gemeinsame Eingang.
type Edge struct {
	log   *slog.Logger
	certs Certs
	check func(ctx context.Context, want []ports.Claim) error // Port-Verwaltung (nil = keine Pruefung)

	mu       sync.Mutex
	cfg      Config
	owners   map[string][]Route
	tokens   map[string]string // ACME HTTP-01: Token -> Antwort
	lst      map[string]*listener
	retry    *time.Timer
	closed   bool
	stopping sync.WaitGroup

	passMu     sync.Mutex
	pass       map[net.Conn]struct{} // durchgereichte Verbindungen
	passClosed bool

	table    atomic.Pointer[table]
	cfgNow   atomic.Pointer[Config] // Kopie von cfg fuer Config(): Abnehmer fragen sie auch waehrend e.mu (Port-Pruefung)
	h3On     atomic.Bool
	block    atomic.Pointer[BlockFunc] // Sperrliste (z. B. ipv64-Blocklisten von CDN64), vor TLS geprueft
	gate     atomic.Pointer[ConnGate]  // Verbindungs-Limits (z. B. Schutz vor Ueberlastung von CDN64), nach der Sperrliste
	defClose atomic.Bool
	vonce    sync.Once // interne Server fuer ServeConn (conn.go)
	virt     *virtual
	qonce    sync.Once // HTTP/3 ueber den Tunnel (quictunnel.go)
	vq       *virtQUIC
	tunH3    atomic.Pointer[func() bool]
	unk      atomic.Pointer[unknownHook] // Anfragen ohne passenden Namen (SetUnknown)
	probes   sync.Map                    // Pruefwerte "auf dem Docker-Host veroeffentlicht?" (published.go) -> angekommen
	pub      atomic.Pointer[pubCache]
	fallback struct {
		once sync.Once
		crt  *tls.Certificate
	}
}

// listener ist einer der drei Dienste (http, https, http3).
type listener struct {
	claim ports.Claim
	addr  string
	err   string
	stop  func(ctx context.Context) error // nil = laeuft nicht
}

// New legt den Eingang an (noch ohne offene Ports). check ist die Pruefung der Port-Verwaltung.
func New(cfg Config, certs Certs, check func(ctx context.Context, want []ports.Claim) error, log *slog.Logger) (*Edge, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	e := &Edge{log: log.With("module", "edge"), certs: certs, check: check, cfg: cfg, owners: map[string][]Route{}, tokens: map[string]string{},
		lst: map[string]*listener{"http": {}, "https": {}, "http3": {}}, pass: map[net.Conn]struct{}{}}
	e.defClose.Store(cfg.Default == DefaultClose)
	e.cfgNow.Store(&cfg)
	e.table.Store(buildTable(nil))
	return e, nil
}

// Set meldet die Namen eines Abnehmers an (ersetzt seine bisherigen). Ein leerer Satz meldet ihn ab.
func (e *Edge) Set(owner string, routes []Route) error {
	norm := make([]Route, 0, len(routes))
	for _, rt := range routes {
		var names []string
		for _, n := range rt.Names {
			nn, err := NormalizeName(n)
			if err != nil {
				return err
			}
			names = append(names, nn)
		}
		if len(names) == 0 && !rt.Fallback {
			return errors.New("route without names")
		}
		if rt.Fallback && (rt.Handler == nil && rt.HTTP == nil || rt.Passthrough != "") {
			return errors.New("fallback route needs a handler")
		}
		if rt.Path != "" && !strings.HasPrefix(rt.Path, "/") {
			return fmt.Errorf("path %q must start with /", rt.Path)
		}
		if rt.Passthrough != "" && (rt.Handler != nil || rt.Path != "") {
			return errors.New("passthrough route without handler and path")
		}
		rt.Names = names
		norm = append(norm, rt)
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return errors.New("edge stopped")
	}
	for o, list := range e.owners {
		if o == owner {
			continue
		}
		for _, rt := range list {
			for _, want := range norm {
				if rt.Fallback && want.Fallback {
					e.mu.Unlock()
					return &NameTakenError{Name: "*", Owner: o} // Ersatz-Route hat schon ein anderer Abnehmer
				}
			}
			for _, n := range rt.Names {
				for _, want := range norm {
					for _, w := range want.Names {
						if w == n {
							e.mu.Unlock()
							return &NameTakenError{Name: n, Owner: o}
						}
					}
				}
			}
		}
	}
	if len(norm) == 0 {
		delete(e.owners, owner)
	} else {
		e.owners[owner] = norm
	}
	e.table.Store(buildTable(e.owners))
	stops := e.reconcileLocked()
	e.mu.Unlock()
	e.runStops(stops)
	return nil
}

// Remove meldet einen Abnehmer ab.
func (e *Edge) Remove(owner string) { _ = e.Set(owner, nil) }

// Configure uebernimmt neue Einstellungen; offene Ports werden dafuer neu geoeffnet.
func (e *Edge) Configure(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	e.mu.Lock()
	if e.cfg == cfg {
		e.mu.Unlock()
		return nil
	}
	e.cfg = cfg
	e.cfgNow.Store(&cfg)
	e.defClose.Store(cfg.Default == DefaultClose)
	stops := e.stopAllLocked()
	e.mu.Unlock()
	e.runStops(stops) // erst schliessen, dann auf den neuen Ports oeffnen
	e.stopping.Wait()
	e.mu.Lock()
	stops = e.reconcileLocked()
	e.mu.Unlock()
	e.runStops(stops)
	return nil
}

// UnknownFunc beantwortet eine Anfrage ohne passenden Namen (nur IP, fremde Domain, leere SNI); def ist die
// Standardseite nach den Einstellungen.
type UnknownFunc func(w http.ResponseWriter, r *http.Request, def http.Handler)

type unknownHook struct {
	f      UnknownFunc
	active func() bool // true: auch bei Standard "schliessen" TLS mit dem Ersatz-Zertifikat annehmen
}

// SetUnknown setzt die Behandlung unbekannter Namen (nil = Standardseite). Ist active wahr, nimmt der Eingang auch
// TLS fuer unbekannte Namen mit dem Ersatz-Zertifikat an, sonst wie bisher nach den Einstellungen.
func (e *Edge) SetUnknown(f UnknownFunc, active func() bool) {
	if f == nil {
		e.unk.Store(nil)
		return
	}
	e.unk.Store(&unknownHook{f: f, active: active})
}

func (e *Edge) unknownActive() bool {
	h := e.unk.Load()
	return h != nil && h.active != nil && h.active()
}

// BlockFunc meldet, ob eine Gegenstelle abgewiesen wird.
type BlockFunc func(netip.Addr) bool

// SetBlocker setzt die Sperrliste (nil = keine). Gesperrte Gegenstellen werden gleich nach dem Annehmen der
// Verbindung getrennt (HTTP, HTTPS, durchgereichtes TLS) bzw. bei HTTP/3 mit 403 abgewiesen, vor jeder Verteilung.
func (e *Edge) SetBlocker(f BlockFunc) {
	if f == nil {
		e.block.Store(nil)
		return
	}
	e.block.Store(&f)
}

func (e *Edge) blocked(a net.Addr) bool {
	f := e.block.Load()
	return f != nil && (*f)(addrIP(a))
}

// ConnGate entscheidet beim Annehmen einer Verbindung (z. B. Limits je IP). ok=false trennt sofort; release
// (darf nil sein) wird genau einmal gerufen, wenn die Verbindung endet.
type ConnGate func(netip.Addr) (release func(), ok bool)

// SetGate setzt die Verbindungs-Limits (nil = keine). Geprueft wird nach der Sperrliste, vor TLS.
func (e *Edge) SetGate(g ConnGate) {
	if g == nil {
		e.gate.Store(nil)
		return
	}
	e.gate.Store(&g)
}

// admit: Sperrliste und Limits beim Annehmen; nil = getrennt.
func (e *Edge) admit(c net.Conn) net.Conn {
	if e.blocked(c.RemoteAddr()) {
		_ = c.Close()
		return nil
	}
	if g := e.gate.Load(); g != nil {
		release, ok := (*g)(addrIP(c.RemoteAddr()))
		if !ok {
			_ = c.Close()
			return nil
		}
		if release != nil {
			return &gateConn{Conn: c, release: release}
		}
	}
	return c
}

// gateConn gibt den Platz beim Limit frei, sobald die Verbindung geschlossen wird.
type gateConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *gateConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// CloseWrite: halb schliessen wie die TCP-Verbindung darunter (TLS durchreichen).
func (c *gateConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

// blockListener trennt gesperrte Gegenstellen beim Annehmen (Port 80).
type blockListener struct {
	net.Listener
	e *Edge
}

func (l blockListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return c, err
		}
		if c = l.e.admit(c); c != nil {
			return c, nil
		}
	}
}

// Config liefert die aktuellen Einstellungen. Ohne Sperre: die Port-Pruefung beim Oeffnen laeuft unter e.mu und
// fragt dabei die Abnehmer (DNS64 liest dort Config), das darf nicht haengen.
func (e *Edge) Config() Config {
	return *e.cfgNow.Load()
}

// Present beantwortet eine ACME-HTTP-01-Pruefung auf Port 80 (fuer jeden Namen), bis release aufgerufen wird.
// Port 80 ist dafuer offen, auch ohne andere Abnehmer.
func (e *Edge) Present(token, keyAuth string) (release func(), err error) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, errors.New("edge stopped")
	}
	e.tokens[token] = keyAuth
	stops := e.reconcileLocked()
	l := e.lst["http"]
	running, lerr, port := l.stop != nil, l.err, e.cfg.HTTPPort
	e.mu.Unlock()
	e.runStops(stops)
	release = func() {
		e.mu.Lock()
		delete(e.tokens, token)
		stops := e.reconcileLocked()
		e.mu.Unlock()
		e.runStops(stops)
	}
	if !running {
		release()
		if port == 0 {
			return nil, errors.New("http port of the edge is switched off (needed for http-01)")
		}
		return nil, fmt.Errorf("http port %d not open: %s", port, lerr)
	}
	return release, nil
}

// Close schliesst alle Ports; danach nimmt Edge nichts mehr an.
func (e *Edge) Close(ctx context.Context) {
	e.mu.Lock()
	e.closed = true
	if e.retry != nil {
		e.retry.Stop()
		e.retry = nil
	}
	stops := e.stopAllLocked()
	e.mu.Unlock()
	for _, s := range stops {
		_ = s(ctx)
	}
	e.closePassthrough(true)
	e.closeVirtual(ctx)
	e.closeVirtualQUIC(ctx)
	e.stopping.Wait()
}

// Claims: die eingestellten Ports fuer die Port-Verwaltung (aktiv = offen, Error = warum nicht).
func (e *Edge) Claims(context.Context) []ports.Claim {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []ports.Claim
	for _, name := range []string{"http", "https", "http3"} {
		c := e.claimLocked(name)
		if c.Port == 0 {
			continue
		}
		c.Active, c.Error = e.lst[name].stop != nil, e.lst[name].err
		out = append(out, c)
	}
	return out
}

func (e *Edge) claimLocked(name string) ports.Claim {
	switch name {
	case "http":
		return ports.Claim{Owner: Owner, Purpose: "HTTP", Proto: ports.TCP, Port: e.cfg.HTTPPort, Bind: e.cfg.Bind}
	case "https":
		return ports.Claim{Owner: Owner, Purpose: "HTTPS", Proto: ports.TCP, Port: e.cfg.HTTPSPort, Bind: e.cfg.Bind}
	}
	if !e.cfg.HTTP3 {
		return ports.Claim{}
	}
	return ports.Claim{Owner: Owner, Purpose: "HTTP/3", Proto: ports.UDP, Port: e.cfg.HTTPSPort, Bind: e.cfg.Bind}
}

// Status ist der Zustand fuer Oberflaeche und API.
type Status struct {
	Config    Config           `json:"config"`
	Listeners []ListenerStatus `json:"listeners"`
	Names     []NameStatus     `json:"names"`
	// UnknownReplaced: unbekannte Namen beantwortet gerade ein anderer Handler (z. B. der Honeypot-Koeder ueber
	// PROXY64), die Standardseite gilt solange nicht
	UnknownReplaced bool `json:"unknown_replaced,omitempty"`
}

type ListenerStatus struct {
	Name    string      `json:"name"` // http, https, http3
	Proto   ports.Proto `json:"proto"`
	Port    int         `json:"port"`
	Needed  bool        `json:"needed"`  // ein Abnehmer braucht ihn
	Running bool        `json:"running"` // offen
	Addr    string      `json:"addr,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type NameStatus struct {
	Name  string `json:"name"`
	Path  string `json:"path,omitempty"`
	Owner string `json:"owner"`
}

func (e *Edge) Status() Status {
	replaced := e.unknownActive() // fragt den Abnehmer, nicht unter e.mu
	e.mu.Lock()
	defer e.mu.Unlock()
	st := Status{Config: e.cfg, UnknownReplaced: replaced}
	need := e.needLocked()
	for _, name := range []string{"http", "https", "http3"} {
		c, l := e.claimLocked(name), e.lst[name]
		if c.Port == 0 {
			continue
		}
		st.Listeners = append(st.Listeners, ListenerStatus{Name: name, Proto: c.Proto, Port: c.Port, Needed: need[name], Running: l.stop != nil, Addr: l.addr, Error: l.err})
	}
	for o, list := range e.owners {
		for _, rt := range list {
			for _, n := range rt.Names {
				st.Names = append(st.Names, NameStatus{Name: n, Path: rt.Path, Owner: o})
			}
			if rt.Fallback {
				st.Names = append(st.Names, NameStatus{Name: "*", Path: rt.Path, Owner: o}) // jeder andere Name, IP
			}
		}
	}
	sort.Slice(st.Names, func(i, j int) bool {
		if st.Names[i].Name != st.Names[j].Name {
			return st.Names[i].Name < st.Names[j].Name
		}
		return st.Names[i].Path < st.Names[j].Path
	})
	return st
}

// ---------------------------------------------------------------- Ports oeffnen und schliessen

// needLocked: welche Dienste gebraucht werden.
func (e *Edge) needLocked() map[string]bool {
	anyRoute, https, h3 := len(e.tokens) > 0, false, false
	for _, list := range e.owners {
		for _, rt := range list {
			anyRoute = anyRoute || !rt.NoHTTP
			if rt.Handler != nil {
				https = true
				h3 = h3 || rt.HTTP3
			}
			if rt.Passthrough != "" {
				https = true
			}
		}
	}
	return map[string]bool{
		"http":  anyRoute && e.cfg.HTTPPort > 0,
		"https": https && e.cfg.HTTPSPort > 0,
		"http3": https && h3 && e.cfg.HTTP3 && e.cfg.HTTPSPort > 0,
	}
}

// reconcileLocked oeffnet, was gebraucht wird, und liefert die Stopp-Funktionen dessen, was nicht mehr
// gebraucht wird (ausserhalb der Sperre aufrufen).
func (e *Edge) reconcileLocked() []func(context.Context) error {
	if e.closed {
		return nil
	}
	need := e.needLocked()
	var stops []func(context.Context) error
	failed := false
	for _, name := range []string{"http", "https", "http3"} {
		l := e.lst[name]
		switch {
		case need[name] && l.stop == nil:
			if err := e.startLocked(name); err != nil {
				l.err = err.Error()
				failed = true
				e.log.Warn("edge port not opened", "service", name, "err", err)
			}
		case !need[name] && l.stop != nil:
			stops = append(stops, l.stop)
			l.stop, l.addr, l.err = nil, "", ""
		case !need[name]:
			l.err = ""
		}
	}
	e.h3On.Store(e.lst["http3"].stop != nil)
	if failed && e.retry == nil { // z. B. Port kurz belegt: in 30 s noch einmal
		e.retry = time.AfterFunc(30*time.Second, func() {
			e.mu.Lock()
			e.retry = nil
			stops := e.reconcileLocked()
			e.mu.Unlock()
			e.runStops(stops)
		})
	}
	return stops
}

func (e *Edge) stopAllLocked() []func(context.Context) error {
	var stops []func(context.Context) error
	for _, l := range e.lst {
		if l.stop != nil {
			stops = append(stops, l.stop)
		}
		l.stop, l.addr, l.err = nil, "", ""
	}
	e.h3On.Store(false)
	return stops
}

// runStops schliesst Dienste im Hintergrund (laufende Anfragen bekommen bis zu 5 s).
func (e *Edge) runStops(stops []func(context.Context) error) {
	for _, s := range stops {
		e.stopping.Add(1)
		go func() {
			defer e.stopping.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s(ctx)
		}()
	}
}

func (e *Edge) startLocked(name string) error {
	c := e.claimLocked(name)
	if e.check != nil {
		if err := e.check(context.Background(), []ports.Claim{c}); err != nil {
			return err
		}
	}
	addr := net.JoinHostPort(strings.Trim(e.cfg.Bind, "[]"), strconv.Itoa(c.Port))
	l := e.lst[name]
	errLog := log.New(io.Discard, "", 0) // Handshake-Fehler von Scannern gehoeren nicht ins Log
	switch name {
	case "http", "https":
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10, ErrorLog: errLog}
		if name == "http" {
			srv.Handler = http.HandlerFunc(e.serveHTTP)
			go func() { _ = srv.Serve(blockListener{ln, e}) }()
			l.addr, l.err = ln.Addr().String(), ""
			l.stop = func(ctx context.Context) error {
				err := srv.Shutdown(ctx)
				_ = ln.Close() // Shutdown vor dem Anlaufen von Serve kennt den Listener noch nicht: Port sonst belegt
				return err
			}
		} else {
			// erst den Namen lesen (TLS durchreichen), dann an den TLS-Server
			srv.Handler = http.HandlerFunc(e.serveHTTPS)
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}, GetConfigForClient: e.tcpConfig}
			tlsLn := newChanListener(ln.Addr())
			go func() { _ = srv.ServeTLS(tlsLn, "", "") }()
			go e.acceptSNI(ln, tlsLn)
			l.addr, l.err = ln.Addr().String(), ""
			l.stop = func(ctx context.Context) error {
				_ = ln.Close()
				err := srv.Shutdown(ctx)
				_ = tlsLn.Close()
				e.closePassthrough(false)
				return err
			}
		}
	case "http3":
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return err
		}
		srv := &http3.Server{Handler: http.HandlerFunc(e.serveHTTPS), IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, GetConfigForClient: e.quicConfig}}
		go func() { _ = srv.Serve(pc) }()
		l.addr, l.err = pc.LocalAddr().String(), ""
		l.stop = func(ctx context.Context) error {
			err := srv.Shutdown(ctx)
			_ = pc.Close()
			return err
		}
	}
	e.log.Info("edge listening", "service", name, "addr", l.addr)
	return nil
}

// ---------------------------------------------------------------- TLS

var errUnknownName = errors.New("unknown server name")

// tcpConfig waehlt Zertifikat und TLS-Einstellungen nach dem Namen (SNI).
func (e *Edge) tcpConfig(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	return e.configFor(hello, false)
}

func (e *Edge) quicConfig(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	return e.configFor(hello, true)
}

func (e *Edge) configFor(hello *tls.ClientHelloInfo, quic bool) (*tls.Config, error) {
	name, _ := NormalizeName(hello.ServerName)
	t := e.table.Load()
	_, routes := t.lookup(name)
	rt := tlsRoute(routes)
	if rt == nil {
		rt = tlsRoute(t.fallback) // per IP bzw. unbekannter Name: Zertifikat der Ersatz-Route
	}
	if rt == nil {
		if e.defClose.Load() && !e.unknownActive() {
			return nil, errUnknownName
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{*e.fallbackCert()}}, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	if rt.MinTLS > cfg.MinVersion {
		cfg.MinVersion = rt.MinTLS
	}
	if rt.NoHTTP2 {
		cfg.NextProtos = []string{"http/1.1"}
	}
	if rt.BSI {
		cfg.CipherSuites, cfg.CurvePreferences = bsiSuites, bsiGroups
	}
	if quic {
		if !rt.HTTP3 {
			return nil, errors.New("http/3 not enabled for " + name)
		}
		cfg.MinVersion = tls.VersionTLS13
	}
	if rt.GetCert != nil { // je Handshake (Zertifikat kann wechseln); ohne Ergebnis das Ersatz-Zertifikat
		get := rt.GetCert
		cfg.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c, err := get(h); err == nil && c != nil {
				return c, nil
			}
			return e.fallbackCert(), nil
		}
		return cfg, nil
	}
	crt := e.certFor(rt, name)
	cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return crt, nil }
	return cfg, nil
}

// tlsRoute: die Route, deren TLS-Einstellungen fuer den Namen gelten (die fuer den ganzen Namen, sonst die erste).
func tlsRoute(routes []*Route) *Route {
	var first *Route
	for _, rt := range routes {
		if rt.Handler == nil {
			continue
		}
		if rt.Path == "" {
			return rt
		}
		if first == nil {
			first = rt
		}
	}
	return first
}

func (e *Edge) certFor(rt *Route, name string) *tls.Certificate {
	if e.certs != nil {
		if rt.CertID > 0 {
			if c := e.certs.ByID(rt.CertID); c != nil {
				return c
			}
		} else if c := e.certs.ForName(name); c != nil {
			return c
		}
	}
	return e.fallbackCert()
}

// ---------------------------------------------------------------- Anfragen

// serveHTTPS verteilt HTTPS-Anfragen (TCP und HTTP/3).
func (e *Edge) serveHTTPS(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor == 3 { // TCP ist schon beim Annehmen geprueft
		if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
			if f := e.block.Load(); f != nil && (*f)(ap.Addr().Unmap()) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
	}
	t := e.table.Load()
	host := hostOf(r.Host)
	key, routes := t.lookup(host)
	if r.TLS != nil && r.TLS.ServerName != "" { // Host muss zum Namen der Verbindung gehoeren
		sni, _ := NormalizeName(r.TLS.ServerName)
		if skey, _ := t.lookup(sni); skey != key {
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
	}
	rt := pick(routes, r.URL.Path, true)
	if rt == nil && key == "" {
		rt = pick(t.fallback, r.URL.Path, true) // per IP bzw. unbekannter Name
	}
	if rt == nil {
		e.unknown(w, r)
		return
	}
	if rt.Allow != nil && !rt.Allow(peerIP(r)) {
		notFound(w)
		return
	}
	if rt.HTTP3 && r.ProtoMajor < 3 && e.h3On.Load() && !viaTunnel(r) {
		w.Header().Set("Alt-Svc", `h3=":`+strconv.Itoa(e.Config().publicPort())+`"; ma=86400`)
	} else if rt.HTTP3 && r.ProtoMajor < 3 && viaTunnel(r) && !terminatedReq(r) && e.tunnelHTTP3() { // Modus 1: HTTP/3 ueber die CDN64-Server
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
	}
	rt.Handler.ServeHTTP(w, r)
}

// serveHTTP: Port 80 (ACME-Pruefungen, Weiterleitung auf HTTPS, reine HTTP-Abnehmer).
func (e *Edge) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if !routedOK(r) { // aus dem Tunnel: nur der Name, fuer den der CDN64-Server durchreicht
		misdirected(w)
		return
	}
	if nonce, ok := strings.CutPrefix(r.URL.Path, probePath); ok && e.probeHit(nonce) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if tok, ok := strings.CutPrefix(r.URL.Path, acmePath); ok {
		e.mu.Lock()
		ka, found := e.tokens[tok]
		e.mu.Unlock()
		if found {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, ka)
			return
		}
	}
	host := hostOf(r.Host)
	t := e.table.Load()
	key, routes := t.lookup(host)
	rt := pick(routes, r.URL.Path, false)
	if rt == nil && key == "" && e.serveFallbackHTTP(t, w, r) {
		return
	}
	if rt == nil {
		e.unknown(w, r)
		return
	}
	if rt.Allow != nil && !rt.Allow(peerIP(r)) {
		notFound(w)
		return
	}
	switch {
	case rt.HTTP != nil:
		rt.HTTP.ServeHTTP(w, r)
	case rt.Handler != nil:
		cfg := e.Config()
		target := "https://" + host
		if p := cfg.publicPort(); p != 443 {
			target += ":" + strconv.Itoa(p)
		}
		http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusMovedPermanently)
	default:
		notFound(w)
	}
}

// serveFallbackHTTP: unbekannter Name auf Port 80 - eine Ersatz-Route mit eigenem HTTP-Handler antwortet, wenn
// ihr Allow die Gegenstelle zulaesst (z. B. die Hinweisseite von DNS64 fuer gesperrte Geraete); sonst false und
// es bleibt bei der Standardseite.
func (e *Edge) serveFallbackHTTP(t *table, w http.ResponseWriter, r *http.Request) bool {
	for _, rt := range t.fallback {
		if rt.HTTP == nil || rt.NoHTTP || !pathMatches(rt.Path, r.URL.Path) {
			continue
		}
		if rt.Allow != nil && !rt.Allow(peerIP(r)) {
			continue
		}
		rt.HTTP.ServeHTTP(w, r)
		return true
	}
	return false
}

// unknown: Antwort fuer unbekannte Namen (ueber SetUnknown, sonst die Standardseite).
func (e *Edge) unknown(w http.ResponseWriter, r *http.Request) {
	if h := e.unk.Load(); h != nil {
		h.f(w, r, http.HandlerFunc(e.unknownDefault))
		return
	}
	e.unknownDefault(w, r)
}

// unknownDefault: Standardseite fuer unbekannte Namen nach den Einstellungen.
func (e *Edge) unknownDefault(w http.ResponseWriter, r *http.Request) {
	if e.defClose.Load() {
		panic(http.ErrAbortHandler) // Verbindung ohne Antwort beenden
	}
	cfg := e.Config()
	switch cfg.Default {
	case DefaultRedirect:
		http.Redirect(w, r, cfg.DefaultURL, http.StatusFound)
	case DefaultHTML:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, cfg.DefaultPage)
	default:
		notFound(w)
	}
}

const notFoundPage = "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>404 Not Found</title></head>" +
	"<body style=\"font-family:sans-serif;text-align:center;margin-top:15vh;color:#555\"><h1>404</h1><p>Not Found</p></body></html>\n"

// notFound: neutrale Seite, die nichts ueber die Node verraet.
func notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, notFoundPage)
}

func addrIP(a net.Addr) netip.Addr {
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// peerIP ist die echte Gegenstelle der Verbindung.
func peerIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func hostOf(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	n, _ := NormalizeName(h)
	return n
}

// TLS nach BSI TR-02102-2 (Fassung 2026-01): TLS 1.2 nur ECDHE mit AES-GCM (Tabelle 3, ohne CBC), Gruppen nach
// Tabelle 6/10 (NIST-Kurven, Brainpool bietet Go nicht an) und die hybriden ML-KEM-Verfahren, die das BSI schon jetzt
// als TR-konform nennt; kein X25519 allein. Die TLS-1.3-Suites legt Go selbst fest (AES-GCM bevorzugt, ChaCha20 nur,
// wenn der Client es vorzieht).
var (
	bsiSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}
	bsiGroups = []tls.CurveID{tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024, tls.X25519MLKEM768, tls.CurveP256, tls.CurveP384, tls.CurveP521}
)
