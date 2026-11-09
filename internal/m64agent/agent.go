// Package m64agent ist der Monitor64-Agent: ein kleiner SSH-Server (x/crypto/ssh), der genau vier Anfragen kennt
// (info, collect, update, keys) und sonst nichts (Plan docs/PLAN-NODE64-MONITOR64.md, Abschnitte "Monitor64-Agent"
// und "Sicherheit"). Er haengt ausser von m64proto (und m64linux fuer die Werte) von keinem Node64-Paket ab.
package m64agent

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Name des Agents (Info.Agent).
const Name = "monitor64-agent"

// Standardwerte.
const (
	DefaultMaxConns     = 32
	maxChannelsPerConn  = 4
	maxKeysFileBytes    = m64proto.MaxKeysBytes
	defaultHandshake    = 10 * time.Second
	defaultIdle         = 15 * time.Minute
	defaultCollect      = 15 * time.Second // Node bricht nach 24-30 s ab (Verbindung, Handshake und Uebertragung dazu)
	maxCollect          = 20 * time.Second
	keysTimeout         = 30 * time.Second
	revokeEvery         = 5 * time.Second // offene Verbindungen gegen die aktuelle Schluesselliste pruefen
	updateTimeout       = 10 * time.Minute
	maxExecCommandBytes = 1024
)

// ErrServerClosed liefert Serve nach Close.
var ErrServerClosed = errors.New("monitor64-agent: server closed")

// Collector liefert die Werte fuer "collect" (unter Linux m64linux). sections leer = alle.
type Collector interface {
	Collect(ctx context.Context, sections []string) *m64proto.Report
}

// CapsProvider (optional am Collector): verfuegbare Abschnitte fuer Info.Caps.
type CapsProvider interface {
	Caps() []string
}

// Config des Agents.
type Config struct {
	HostKey     ssh.Signer           // Pflicht (LoadOrCreateHostKey)
	KeysFile    string               // Pflicht: erlaubte Schluessel (authorized_keys-Format)
	LocalDir    string               // eigene Skripte (local.d); leer = keine
	Collector   Collector            // nil = keine Werte (nur Fehler im Report)
	Version     string               // SemVer des Agents
	ReleaseKeys []ed25519.PublicKey  // Schluessel fuer Updates; leer = update abgelehnt
	ExePath     string               // Datei, die update ersetzt; leer = os.Executable()
	OnUpdated   func(version string) // nach erfolgreichem Update (Aufrufer beendet den Prozess)
	MaxConns    int                  // gleichzeitige angemeldete Verbindungen (0 = DefaultMaxConns)
	Logger      *slog.Logger

	// Probe (optional) startet die neue Datei nach update probeweise; Fehler = alte Datei zurueck, update abgelehnt.
	Probe func(exe, version string) error

	HandshakeTimeout time.Duration // 0 = 10 s
	IdleTimeout      time.Duration // Verbindung ohne offenen Kanal schliessen (0 = 15 min)
	CollectTimeout   time.Duration // 0 = 15 s, hoechstens 20 s

	// Push-Betrieb (push.go): Wartezeit vor dem naechsten Verbindungsversuch nach einem Fehlschlag, verdoppelt sich
	// von PushRetryMin (0 = 5 s) bis PushRetryMax (0 = 5 min).
	PushRetryMin time.Duration
	PushRetryMax time.Duration
}

// Server ist der laufende Agent.
type Server struct {
	cfg   Config
	log   *slog.Logger
	keys  *keyStore
	lim   limiter
	gate  preAuthGate   // Verbindungen ohne Anmeldung
	sem   chan struct{} // angemeldete Verbindungen
	local *localRunner

	revokeEvery time.Duration
	authMu      sync.Mutex
	authed      map[*ssh.ServerConn][]byte // angemeldete Verbindungen -> Schluessel (Wire-Format)
	sweepOnce   sync.Once
	done        chan struct{}

	pushKeepaliveEvery time.Duration // Push-Betrieb: Keepalive-Abstand (Tests setzen weniger)

	collectMu chan struct{} // collect nacheinander (mehrere Nodes gleichzeitig)
	updateMu  sync.Mutex

	mu     sync.Mutex
	ln     map[net.Listener]struct{}
	conns  map[net.Conn]struct{}
	closed atomic.Bool
	wg     sync.WaitGroup
}

// New prueft die Konfiguration und legt den Server an.
func New(cfg Config) (*Server, error) {
	if cfg.HostKey == nil {
		return nil, errors.New("monitor64-agent: host key missing")
	}
	if cfg.KeysFile == "" {
		return nil, errors.New("monitor64-agent: keys file missing")
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = defaultHandshake
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdle
	}
	if cfg.CollectTimeout <= 0 {
		cfg.CollectTimeout = defaultCollect
	}
	cfg.CollectTimeout = min(cfg.CollectTimeout, maxCollect)
	if cfg.Version == "" {
		cfg.Version = "0.0.0"
	}
	if cfg.PushRetryMin <= 0 {
		cfg.PushRetryMin = defaultPushRetryMin
	}
	if cfg.PushRetryMax <= 0 {
		cfg.PushRetryMax = defaultPushRetryMax
	}
	cfg.PushRetryMax = max(cfg.PushRetryMax, cfg.PushRetryMin)
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{
		cfg:       cfg,
		log:       log,
		keys:      &keyStore{path: cfg.KeysFile, log: log.Warn},
		sem:       make(chan struct{}, cfg.MaxConns),
		collectMu: make(chan struct{}, 1),
		ln:        map[net.Listener]struct{}{},
		conns:     map[net.Conn]struct{}{},

		revokeEvery: revokeEvery,
		authed:      map[*ssh.ServerConn][]byte{},
		done:        make(chan struct{}),

		pushKeepaliveEvery: pushKeepaliveEvery,
	}
	if cfg.LocalDir != "" {
		s.local = newLocalRunner(cfg.LocalDir)
	}
	return s, nil
}

// Serve nimmt Verbindungen an, bis Close aufgerufen wird.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		_ = ln.Close()
		return ErrServerClosed
	}
	s.ln[ln] = struct{}{}
	s.startSweepLocked()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.ln, ln)
		s.mu.Unlock()
	}()
	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if s.closed.Load() {
				return ErrServerClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0
		p := peerOf(c.RemoteAddr())
		now := time.Now()
		if s.lim.refused(p, now) {
			_ = c.Close()
			continue
		}
		// Bis zur Anmeldung zaehlt die Verbindung nur gegen die kleineren Grenzen fuer Verbindungen ohne Anmeldung.
		// Abgewiesen ist kein Fehlversuch (volle Plaetze kann ein Angreifer verursachen); seine eigenen Verbindungen
		// zaehlen ueber das Zeitlimit des Handshakes.
		slot := s.gate.acquire(p, s.lim.known(p.ip, now), c, now)
		if slot == nil {
			s.log.Debug("monitor64-agent: too many connections without login", "remote", c.RemoteAddr().String())
			_ = c.Close()
			continue
		}
		if !s.track(c, true) {
			s.gate.release(slot)
			_ = c.Close()
			return ErrServerClosed
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.track(c, false)
			defer c.Close()
			s.handleConn(c, p, slot, false)
		}()
	}
}

// startSweepLocked startet die Pruefung offener Verbindungen gegen die Schluesselliste (einmal; s.mu gehalten).
func (s *Server) startSweepLocked() {
	s.sweepOnce.Do(func() {
		s.wg.Add(1)
		go s.sweepLoop()
	})
}

// Close beendet alle Listener und Verbindungen und wartet auf laufende Anfragen.
func (s *Server) Close() error {
	s.mu.Lock()
	if !s.closed.Swap(true) {
		close(s.done)
	}
	for ln := range s.ln {
		_ = ln.Close()
	}
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	if s.local != nil {
		s.local.close()
	}
	return nil
}

func (s *Server) track(c net.Conn, add bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		if s.closed.Load() {
			return false
		}
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
	return true
}

// sshConfig baut die Konfiguration je Verbindung (rejected merkt fehlgeschlagene Anmeldeversuche).
func (s *Server) sshConfig(rejected *atomic.Bool) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		ServerVersion:           "SSH-2.0-monitor64-agent",
		MaxAuthTries:            6,
		PublicKeyAuthAlgorithms: pubKeyAuthAlgos,
		PublicKeyCallback: func(meta ssh.ConnMetadata, pub ssh.PublicKey) (*ssh.Permissions, error) {
			wire := pub.Marshal()
			e, err := s.keys.allowed(wire, meta.RemoteAddr())
			if err != nil {
				return nil, err
			}
			// Der Schluessel wird gemerkt: jede weitere Anfrage prueft ihn erneut gegen die aktuelle Liste.
			return &ssh.Permissions{Extensions: map[string]string{
				"fp":      Fingerprint(pub),
				"comment": e.comment,
				"key":     string(wire),
			}}, nil
		},
		AuthLogCallback: func(meta ssh.ConnMetadata, method string, err error) {
			if err != nil && method != "none" {
				rejected.Store(true)
			}
		},
	}
	cfg.AddHostKey(s.cfg.HostKey)
	return cfg
}

// handleConn bedient eine Verbindung; liefert, ob sich die Node angemeldet hat. push: die Verbindung hat der Agent
// selbst aufgebaut (push.go) - Fehlversuche zaehlen dann nicht im Limiter (die Wartezeit des Push-Betriebs bremst),
// und ein Keepalive erkennt tote Verbindungen.
func (s *Server) handleConn(c net.Conn, p peer, slot *preAuthSlot, push bool) bool {
	remote := c.RemoteAddr().String()
	_ = c.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	var rejected atomic.Bool
	sc, chans, reqs, err := ssh.NewServerConn(c, s.sshConfig(&rejected))
	s.gate.release(slot)
	if err != nil {
		// Jede Verbindung ohne Anmeldung zaehlt als Fehlversuch (auch Zeitlimit und abgebrochener Handshake),
		// sonst koennten stille Verbindungen beliebig oft Plaetze belegen (bekannte Adressen: siehe failPeer).
		if !push {
			s.lim.failPeer(p, time.Now())
		}
		var ae *ssh.ServerAuthError
		if errors.As(err, &ae) && rejected.Load() {
			s.log.Warn("monitor64-agent: login refused", "remote", remote)
		} else {
			s.log.Debug("monitor64-agent: handshake failed", "remote", remote, "err", err)
		}
		return false
	}
	defer sc.Close()
	_ = c.SetDeadline(time.Time{})
	if !push {
		s.lim.ok(p.ip, time.Now())
	}
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		s.log.Warn("monitor64-agent: too many connections", "remote", remote)
		return true
	}
	wire := []byte(sc.Permissions.Extensions["key"])
	s.authMu.Lock()
	s.authed[sc] = wire
	s.authMu.Unlock()
	defer func() {
		s.authMu.Lock()
		delete(s.authed, sc)
		s.authMu.Unlock()
	}()
	// allowed prueft vor jedem Kanal und jeder Anfrage, ob der Schluessel noch in der Liste steht.
	allowed := func() bool {
		if _, err := s.keys.allowed(wire, c.RemoteAddr()); err != nil {
			s.log.Warn("monitor64-agent: key no longer allowed - connection closed", "remote", remote, "err", err)
			_ = sc.Close()
			return false
		}
		return true
	}
	fp := sc.Permissions.Extensions["fp"]
	s.log.Info("monitor64-agent: connected", "remote", remote, "key", fp, "comment", sc.Permissions.Extensions["comment"])
	defer s.log.Info("monitor64-agent: disconnected", "remote", remote)

	// Globale Anfragen (tcpip-forward, keepalive ...) werden abgelehnt.
	go ssh.DiscardRequests(reqs)

	var wg sync.WaitGroup
	defer wg.Wait() // laeuft nach cancel: laufende Anfragen sehen das Ende der Verbindung
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if push {
		wg.Add(1)
		go func() { defer wg.Done(); s.pushKeepalive(ctx, sc) }()
	}

	// Leerlauf: ohne offenen Kanal wird die Verbindung nach IdleTimeout geschlossen.
	var active atomic.Int32
	idle := time.AfterFunc(s.cfg.IdleTimeout, func() {
		if active.Load() == 0 {
			s.log.Debug("monitor64-agent: idle connection closed", "remote", remote)
			_ = sc.Close()
		}
	})
	defer idle.Stop()

	for nc := range chans {
		if !allowed() {
			_ = nc.Reject(ssh.Prohibited, "key no longer allowed")
			continue
		}
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only session channels")
			continue
		}
		if active.Load() >= maxChannelsPerConn {
			_ = nc.Reject(ssh.ResourceShortage, "too many channels")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		active.Add(1)
		idle.Stop()
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleSession(ctx, ch, chReqs, remote, fp, allowed)
			if active.Add(-1) == 0 {
				idle.Reset(s.cfg.IdleTimeout)
			}
		}()
	}
	return true
}

// sweepLoop prueft regelmaessig die offenen Verbindungen gegen die Schluesselliste (Datei geaendert).
func (s *Server) sweepLoop() {
	defer s.wg.Done()
	t := time.NewTicker(s.revokeEvery)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.revoke()
		case <-s.done:
			return
		}
	}
}

// revoke schliesst angemeldete Verbindungen, deren Schluessel (oder Adresse) nicht mehr erlaubt ist.
func (s *Server) revoke() {
	s.authMu.Lock()
	conns := make(map[*ssh.ServerConn][]byte, len(s.authed))
	for sc, w := range s.authed {
		conns[sc] = w
	}
	s.authMu.Unlock()
	for sc, w := range conns {
		if _, err := s.keys.allowed(w, sc.RemoteAddr()); err != nil {
			s.log.Warn("monitor64-agent: key no longer allowed - connection closed", "remote", sc.RemoteAddr().String(),
				"key", sc.Permissions.Extensions["fp"], "err", err)
			_ = sc.Close()
		}
	}
}

// exitStatus sendet den Rueckgabewert und schliesst den Kanal.
func exitStatus(ch ssh.Channel, code uint32) {
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{code}))
	_ = ch.CloseWrite()
	_ = ch.Close()
}

// fail schreibt eine kurze Fehlermeldung nach stderr und beendet mit Status 1.
func fail(ch ssh.Channel, msg string) {
	_, _ = fmt.Fprintln(ch.Stderr(), msg)
	exitStatus(ch, 1)
}
