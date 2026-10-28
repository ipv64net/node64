package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// Edge ist ein CDN64-Server, zu dem die Node einen Tunnel haelt (Liste kommt ab T3 von ipv64, G2).
type Edge struct {
	Name string   `json:"name"`          // srv07
	Host string   `json:"host"`          // srv07.cdn64.de (Zertifikatsname)
	Port int      `json:"port"`          // 7844
	IPs  []string `json:"ips,omitempty"` // Rueckfall, wenn der DNS der Node klemmt
}

// ClientConfig: Anmeldedaten, Server und was mit eingehenden Streams passiert.
type ClientConfig struct {
	Tunnel      string
	Token       string
	Node        string
	NodeVersion string
	Edges       []Edge
	Handler     func(st Stream, h Header) // je Daten-Stream (eigene Goroutine); muss den Stream schliessen (auch spaeter)
	RootCAs     *x509.CertPool            // nil = System
	Log         *slog.Logger
	AltPort     int      // zweiter Port, wenn der Tunnel-Port nicht geht (0 = 443, -1 = keiner; G1)
	TCPOnly     bool     // nur TCP+TLS (Tests, Netze ohne UDP)
	Caps        []string // Faehigkeiten der Node im Hello (z. B. CapQUIC)
	// Sessions: parallele Verbindungen je Server (Business/Company; < 1 = eine, hoechstens MaxSessions). Der Server
	// verteilt neue Besucher auf die am wenigsten belastete; faellt eine aus, laufen die anderen weiter.
	Sessions int
}

// MaxSessions: hoechstens so viele parallele Verbindungen je Server.
const MaxSessions = 8

// EdgeStatus ist der Zustand des Tunnels zu einem Server (Anzeige in der Node).
type EdgeStatus struct {
	Name       string    `json:"name"`
	Host       string    `json:"host"`
	Connected  bool      `json:"connected"`
	Transport  string    `json:"transport,omitempty"` // quic | tcp
	Via        string    `json:"via,omitempty"`       // quic | quic443 | tls (Weg zum Server, nur verbunden)
	Addr       string    `json:"addr,omitempty"`      // Adresse des Servers
	Since      time.Time `json:"since,omitzero"`      // verbunden seit bzw. getrennt seit
	RTTms      float64   `json:"rtt_ms,omitempty"`
	Streams    int64     `json:"streams"`    // offene Besucher-Streams
	Total      int64     `json:"total"`      // Streams seit dem Start
	Reconnects int       `json:"reconnects"` // Neuverbindungen seit dem Start
	LastError  string    `json:"last_error,omitempty"`
	UDPBlocked bool      `json:"udp_blocked,omitempty"` // QUIC scheitert, TCP genutzt
	Caps       []string  `json:"caps,omitempty"`        // Faehigkeiten des Servers (Welcome)
	Sessions   int       `json:"sessions"`              // verbundene parallele Verbindungen
	Wanted     int       `json:"sessions_wanted"`       // gewuenschte (Konfiguration bzw. Grenze des Servers)
}

// Client haelt die Tunnels zu allen Servern.
type Client struct {
	cfg      ClientConfig
	mu       sync.Mutex
	st       map[string][]*edgeState                    // je Server eine Verbindung je Slot
	resolve  func(ctx context.Context, e Edge) []net.IP // Tests: feste Adressen
	forceTCP bool                                       // Tests: nur der Ausweichweg
	offWait  time.Duration                              // Tests: Pause eines abgelehnten Slots (Standard 2-5 Minuten)
}

type edgeState struct {
	EdgeStatus
	streams atomic.Int64
	total   atomic.Int64
	sess    Session
	off     bool // Slot ueber der Grenze des Servers: aus
}

// NewClient legt den Client an (Run startet ihn).
func NewClient(cfg ClientConfig) *Client {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	cfg.Sessions = min(max(cfg.Sessions, 1), MaxSessions)
	c := &Client{cfg: cfg, st: map[string][]*edgeState{}, resolve: addrs, forceTCP: cfg.TCPOnly}
	for _, e := range cfg.Edges {
		for range cfg.Sessions {
			c.st[e.Name] = append(c.st[e.Name], &edgeState{EdgeStatus: EdgeStatus{Name: e.Name, Host: e.Host}})
		}
	}
	return c
}

// Run haelt zu jedem Server cfg.Sessions Tunnel-Verbindungen, bis ctx endet.
func (c *Client) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, e := range c.cfg.Edges {
		for slot := range c.cfg.Sessions {
			wg.Add(1)
			go func() { defer wg.Done(); c.loop(ctx, e, slot) }()
		}
	}
	wg.Wait()
}

// Status: Zustand je Server in der Reihenfolge der Konfiguration; mehrere Verbindungen zusammengefasst (Angaben der
// ersten verbundenen, Streams zusammengezaehlt).
func (c *Client) Status() []EdgeStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]EdgeStatus, 0, len(c.st))
	for _, e := range c.cfg.Edges {
		slots := c.st[e.Name]
		base := slots[0]
		for _, s := range slots {
			if s.Connected {
				base = s
				break
			}
		}
		x := base.EdgeStatus
		x.Streams, x.Total, x.Reconnects, x.Sessions, x.Wanted = 0, 0, 0, 0, 0
		for _, s := range slots {
			x.Streams += s.streams.Load()
			x.Total += s.total.Load()
			x.Reconnects += s.Reconnects
			if s.Connected {
				x.Sessions++
			}
			if !s.off {
				x.Wanted++
			}
		}
		x.Via = via(x)
		out = append(out, x)
	}
	return out
}

// via: Verbindungsweg fuer die Anzeige – QUIC auf dem Tunnel-Port, QUIC ueber 443 (G1) oder TLS ueber TCP (Rueckfall).
func via(s EdgeStatus) string {
	if !s.Connected {
		return ""
	}
	if s.Transport == "tcp" {
		return "tls"
	}
	if _, p, err := net.SplitHostPort(s.Addr); err == nil && p == "443" {
		return "quic443"
	}
	return "quic"
}

// AllHave: mindestens ein Server verbunden und alle verbundenen haben die Faehigkeit.
func (c *Client) AllHave(capability string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, slots := range c.st {
		for _, s := range slots {
			if !s.Connected {
				continue
			}
			if !HasCap(s.Caps, capability) {
				return false
			}
			n++
		}
	}
	return n > 0
}

func (c *Client) update(name string, slot int, f func(s *edgeState)) {
	c.mu.Lock()
	f(c.st[name][slot])
	c.mu.Unlock()
}

// errSlotOff: der Server erlaubt diesem Tunnel weniger Verbindungen; der Slot bleibt aus und versucht es nach einer
// Pause erneut (Wechsel der Klasse, Neustart des Servers waehrend eines Updates).
var errSlotOff = errors.New("session limit of the server")

// errRejected: der Server hat die Anmeldung abgelehnt (kein UDP-Problem).
type errRejected struct{ msg string }

func (e errRejected) Error() string { return "rejected by server: " + e.msg }

func (c *Client) loop(ctx context.Context, e Edge, slot int) {
	backoff := time.Second
	quicFails := 0
	var lastQUIC time.Time
	port := 0 // zuletzt erfolgreicher Port (0 = noch keiner)
	for ctx.Err() == nil {
		useTCP := c.forceTCP || quicFails >= 2 && time.Since(lastQUIC) < 5*time.Minute // alle 5 Minuten QUIC erneut versuchen
		sess, err := c.connect(ctx, e, slot, useTCP, port)
		if errors.Is(err, errSlotOff) {
			c.update(e.Name, slot, func(s *edgeState) { s.off, s.Connected, s.LastError = true, false, err.Error() })
			c.cfg.Log.Info("tunnel: parallel session not allowed by the server", "edge", e.Name, "slot", slot)
			wait := c.offWait
			if wait <= 0 {
				wait = 2*time.Minute + rand.N(3*time.Minute)
			}
			select {
			case <-ctx.Done():
			case <-time.After(wait):
			}
			continue
		}
		if err == nil {
			if _, p, perr := net.SplitHostPort(sess.RemoteAddr().String()); perr == nil {
				port, _ = strconv.Atoi(p)
			}
		}
		if !useTCP {
			lastQUIC = time.Now()
			var rej errRejected
			if err != nil && !errors.As(err, &rej) && ctx.Err() == nil {
				quicFails++
			} else if err == nil {
				quicFails = 0
			}
		}
		if err == nil {
			start := time.Now()
			c.serve(ctx, e, slot, sess)
			if time.Since(start) > 30*time.Second {
				backoff = time.Second
			}
			err = errors.New("connection closed")
		}
		if ctx.Err() != nil {
			break
		}
		c.update(e.Name, slot, func(s *edgeState) {
			s.LastError, s.UDPBlocked = err.Error(), quicFails >= 2
			if s.Connected || s.Since.IsZero() {
				s.Since = time.Now()
			}
			s.Connected, s.Transport, s.Addr, s.sess = false, "", "", nil
		})
		c.cfg.Log.Debug("tunnel: retry", "edge", e.Name, "slot", slot, "in", backoff, "err", err)
		wait := time.Duration(float64(backoff) * (0.5 + rand.Float64()))
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
		backoff = min(backoff*2, time.Minute)
	}
	c.update(e.Name, slot, func(s *edgeState) { s.Connected, s.sess = false, nil })
}

// addrs: Adressen des Servers, IPv6 zuerst (Zielgruppe nur IPv6), bei DNS-Fehler die hinterlegten IPs.
func addrs(ctx context.Context, e Edge) []net.IP {
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var ips []net.IP
	if list, err := net.DefaultResolver.LookupIPAddr(rctx, e.Host); err == nil {
		for _, a := range list {
			ips = append(ips, a.IP)
		}
	}
	if len(ips) == 0 {
		for _, s := range e.IPs {
			if ip := net.ParseIP(s); ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	sort.SliceStable(ips, func(i, j int) bool { return ips[i].To4() == nil && ips[j].To4() != nil })
	return ips
}

func (c *Client) tlsConfig(e Edge) *tls.Config {
	return &tls.Config{ServerName: e.Host, RootCAs: c.cfg.RootCAs, MinVersion: tls.VersionTLS13, NextProtos: []string{ALPN}}
}

// connect: Verbindung aufbauen (je Adresse und Port hoechstens 5 s) und anmelden. Ports: der Tunnel-Port, sonst 443
// (G1, Netze, die nur 443 hinauslassen); prefer zuerst.
func (c *Client) connect(ctx context.Context, e Edge, slot int, useTCP bool, prefer int) (Session, error) {
	alt := c.cfg.AltPort
	if alt == 0 {
		alt = 443
	}
	ports := []int{e.Port, alt}
	if ports[0] == 0 {
		ports[0] = 7844
	}
	if alt < 0 || ports[0] == alt {
		ports = ports[:1]
	}
	if prefer == ports[len(ports)-1] && len(ports) > 1 {
		ports[0], ports[1] = ports[1], ports[0]
	}
	ips := c.resolve(ctx, e)
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s: no address", e.Host)
	}
	var lastErr error
	for _, port := range ports {
		for _, ip := range ips {
			dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			addr := hostPort(ip.String(), port)
			var sess Session
			var err error
			if useTCP {
				sess, err = dialTCP(dctx, addr, c.tlsConfig(e))
			} else {
				var qc *quic.Conn
				if qc, err = quic.DialAddr(dctx, addr, c.tlsConfig(e), QUICConfig()); err == nil {
					sess = &quicSession{qc}
				}
			}
			cancel()
			if err == nil { // Anmeldung mit eigener Frist (der Handschlag darf die 5 s fast aufbrauchen)
				hctx, hcancel := context.WithTimeout(ctx, 10*time.Second)
				err = c.hello(hctx, sess, e.Name, slot)
				hcancel()
				if err != nil {
					_ = sess.Close("hello")
				}
			}
			if err == nil {
				return sess, nil
			}
			var rej errRejected
			if errors.As(err, &rej) || errors.Is(err, errSlotOff) {
				return nil, err
			}
			lastErr = fmt.Errorf("%s: %w", addr, err)
		}
	}
	return nil, lastErr
}

func dialTCP(ctx context.Context, addr string, conf *tls.Config) (Session, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{KeepAlive: 15 * time.Second}, Config: conf}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if conn.(*tls.Conn).ConnectionState().NegotiatedProtocol != ALPN {
		_ = conn.Close()
		return nil, errors.New("alpn not accepted")
	}
	ys, err := newYamux(conn, false)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ys, nil
}

// hello: Steuer-Stream oeffnen, anmelden, Welcome lesen. Der Steuer-Stream bleibt offen (GOAWAY vom Server).
func (c *Client) hello(ctx context.Context, sess Session, edge string, slot int) error {
	ctrl, err := sess.OpenStream(ctx)
	if err != nil {
		return err
	}
	dl, _ := ctx.Deadline()
	_ = ctrl.SetDeadline(dl)
	if err := writeMsg(ctrl, Hello{Version: Version, Tunnel: c.cfg.Tunnel, Token: c.cfg.Token, Node: c.cfg.Node, NodeVersion: c.cfg.NodeVersion, Caps: c.cfg.Caps, Slot: slot}); err != nil {
		return err
	}
	br := bufio.NewReaderSize(ctrl, 64<<10)
	var w Welcome
	if err := readMsg(br, &w); err != nil {
		return err
	}
	if w.Error != "" {
		if w.Sessions > 0 && slot >= w.Sessions {
			return errSlotOff
		}
		return errRejected{w.Error}
	}
	if slot > 0 && w.Sessions == 0 { // aelterer Server: nur eine Verbindung je Tunnel sinnvoll
		return errSlotOff
	}
	c.update(edge, slot, func(s *edgeState) { s.Caps = w.Caps })
	_ = ctrl.SetDeadline(time.Time{})
	go func() { // Steuer-Nachrichten des Servers
		var m Control
		for readMsg(br, &m) == nil {
			if m.Type == "goaway" {
				c.cfg.Log.Info("tunnel: server restarts", "edge", w.Edge)
			}
		}
	}()
	return nil
}

// serve nimmt Daten-Streams an, bis die Verbindung endet.
func (c *Client) serve(ctx context.Context, e Edge, slot int, sess Session) {
	c.update(e.Name, slot, func(s *edgeState) {
		s.Connected, s.Transport, s.Addr, s.Since, s.LastError, s.sess, s.off = true, sess.Transport(), sess.RemoteAddr().String(), time.Now(), "", sess, false
		s.RTTms = float64(sess.RTT().Microseconds()) / 1000
		s.Reconnects++
	})
	c.cfg.Log.Info("tunnel: connected", "edge", e.Name, "slot", slot, "transport", sess.Transport(), "addr", sess.RemoteAddr().String())
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-sctx.Done():
				_ = sess.Close("shutdown")
				return
			case <-sess.Done():
				return
			case <-t.C:
				rtt := float64(sess.RTT().Microseconds()) / 1000
				c.update(e.Name, slot, func(s *edgeState) { s.RTTms = rtt })
			}
		}
	}()
	c.mu.Lock()
	es := c.st[e.Name][slot]
	c.mu.Unlock()
	for {
		st, err := sess.AcceptStream(sctx)
		if err != nil {
			return
		}
		go func() {
			_ = st.SetReadDeadline(time.Now().Add(10 * time.Second))
			h, err := ReadHeader(st)
			if err != nil {
				_ = st.Close()
				return
			}
			_ = st.SetReadDeadline(time.Time{})
			if h.Edge == "" {
				h.Edge = e.Name
			}
			es.streams.Add(1)
			es.total.Add(1)
			c.cfg.Handler(&countedStream{Stream: st, n: &es.streams}, h)
		}()
	}
}

// countedStream zaehlt offene Streams bis zum Schliessen (der Handler darf asynchron weitermachen).
type countedStream struct {
	Stream
	n    *atomic.Int64
	once sync.Once
}

func (c *countedStream) Close() error {
	err := c.Stream.Close()
	c.once.Do(func() { c.n.Add(-1) })
	return err
}
