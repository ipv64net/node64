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
	"net/netip"
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
	defaultCollect      = 45 * time.Second
	infoTimeout         = 10 * time.Second
	keysTimeout         = 30 * time.Second
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
	MaxConns    int                  // gleichzeitige Verbindungen (0 = DefaultMaxConns)
	Logger      *slog.Logger

	HandshakeTimeout time.Duration // 0 = 10 s
	IdleTimeout      time.Duration // Verbindung ohne offenen Kanal schliessen (0 = 15 min)
	CollectTimeout   time.Duration // 0 = 45 s
}

// Server ist der laufende Agent.
type Server struct {
	cfg   Config
	log   *slog.Logger
	keys  *keyStore
	lim   limiter
	sem   chan struct{}
	local *localRunner

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
	if cfg.Version == "" {
		cfg.Version = "0.0.0"
	}
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
	}
	if cfg.LocalDir != "" {
		s.local = &localRunner{dir: cfg.LocalDir}
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
		key := limiterKey(c.RemoteAddr())
		if s.lim.blocked(key, time.Now()) {
			_ = c.Close()
			continue
		}
		select {
		case s.sem <- struct{}{}:
		default:
			s.log.Warn("monitor64-agent: too many connections", "remote", c.RemoteAddr().String())
			_ = c.Close()
			continue
		}
		if !s.track(c, true) {
			<-s.sem
			_ = c.Close()
			return ErrServerClosed
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			defer s.track(c, false)
			defer c.Close()
			s.handleConn(c, key)
		}()
	}
}

// Close beendet alle Listener und Verbindungen und wartet auf laufende Anfragen.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed.Store(true)
	for ln := range s.ln {
		_ = ln.Close()
	}
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
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
			e := s.keys.lookup(pub)
			if e == nil {
				return nil, errors.New("unknown key")
			}
			if len(e.from) > 0 {
				ap, err := netip.ParseAddrPort(meta.RemoteAddr().String())
				if err != nil || !fromAllows(e.from, ap.Addr()) {
					return nil, errors.New("address not allowed for this key")
				}
			}
			return &ssh.Permissions{Extensions: map[string]string{
				"fp":      Fingerprint(pub),
				"comment": e.comment,
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

func (s *Server) handleConn(c net.Conn, limKey string) {
	remote := c.RemoteAddr().String()
	_ = c.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	var rejected atomic.Bool
	sc, chans, reqs, err := ssh.NewServerConn(c, s.sshConfig(&rejected))
	if err != nil {
		var ae *ssh.ServerAuthError
		if errors.As(err, &ae) && rejected.Load() {
			s.lim.fail(limKey, time.Now())
			s.log.Warn("monitor64-agent: login refused", "remote", remote)
		} else {
			s.log.Debug("monitor64-agent: handshake failed", "remote", remote, "err", err)
		}
		return
	}
	defer sc.Close()
	_ = c.SetDeadline(time.Time{})
	s.lim.ok(limKey)
	fp := sc.Permissions.Extensions["fp"]
	s.log.Info("monitor64-agent: connected", "remote", remote, "key", fp, "comment", sc.Permissions.Extensions["comment"])
	defer s.log.Info("monitor64-agent: disconnected", "remote", remote)

	// Globale Anfragen (tcpip-forward, keepalive ...) werden abgelehnt.
	go ssh.DiscardRequests(reqs)

	var wg sync.WaitGroup
	defer wg.Wait() // laeuft nach cancel: laufende Anfragen sehen das Ende der Verbindung
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
			s.handleSession(ctx, ch, chReqs, remote, fp)
			if active.Add(-1) == 0 {
				idle.Reset(s.cfg.IdleTimeout)
			}
		}()
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
