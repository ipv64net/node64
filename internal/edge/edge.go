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
	NoHTTP2 bool         // nur HTTP/1.1 ueber TCP
	HTTP3   bool         // auch ueber HTTP/3 (wenn der Eingang es anbietet)
	// Passthrough: TLS nicht hier beenden, sondern die Verbindung roh an dieses Ziel (host:port) geben (nur TCP,
	// Handler bleibt nil). Count zaehlt durchgereichte Verbindungen (optional).
	Passthrough string
	Count       func()
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
	h3On     atomic.Bool
	defClose atomic.Bool
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
		if len(names) == 0 {
			return errors.New("route without names")
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

// Config liefert die aktuellen Einstellungen.
func (e *Edge) Config() Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
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
	e.stopping.Wait()
}

// Claims: die eingestellten Ports fuer die Port-Verwaltung (aktiv = offen).
func (e *Edge) Claims(context.Context) []ports.Claim {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []ports.Claim
	for _, name := range []string{"http", "https", "http3"} {
		c := e.claimLocked(name)
		if c.Port == 0 {
			continue
		}
		c.Active = e.lst[name].stop != nil
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
	e.mu.Lock()
	defer e.mu.Unlock()
	st := Status{Config: e.cfg}
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
			anyRoute = true
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
			go func() { _ = srv.Serve(ln) }()
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
	_, routes := e.table.Load().lookup(name)
	rt := tlsRoute(routes)
	if rt == nil {
		if e.defClose.Load() {
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
	if quic {
		if !rt.HTTP3 {
			return nil, errors.New("http/3 not enabled for " + name)
		}
		cfg.MinVersion = tls.VersionTLS13
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
	if rt == nil {
		e.unknown(w, r)
		return
	}
	if rt.Allow != nil && !rt.Allow(peerIP(r)) {
		notFound(w)
		return
	}
	if rt.HTTP3 && r.ProtoMajor < 3 && e.h3On.Load() {
		w.Header().Set("Alt-Svc", `h3=":`+strconv.Itoa(e.Config().publicPort())+`"; ma=86400`)
	}
	rt.Handler.ServeHTTP(w, r)
}

// serveHTTP: Port 80 (ACME-Pruefungen, Weiterleitung auf HTTPS, reine HTTP-Abnehmer).
func (e *Edge) serveHTTP(w http.ResponseWriter, r *http.Request) {
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
	_, routes := e.table.Load().lookup(host)
	rt := pick(routes, r.URL.Path, false)
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

// unknown: Antwort fuer unbekannte Namen.
func (e *Edge) unknown(w http.ResponseWriter, r *http.Request) {
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
