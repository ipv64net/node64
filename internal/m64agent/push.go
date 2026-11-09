package m64agent

// Push-Betrieb fuer Hosts hinter NAT oder auf einem VPS (Plan docs/PLAN-NODE64-MONITOR64.md, Phase 3): Der Agent baut
// die TCP-Verbindung zur Node selbst auf, sonst bleibt alles wie beim Abfragen. Er ist weiter SSH-Server und prueft
// die Node ueber keys (samt from=, bezogen auf die Adresse der Node), die Node ist weiter SSH-Client und prueft den
// gemerkten Hostschluessel des Agents (TOFU). Nur die Richtung des Verbindungsaufbaus dreht sich.
//
// Ablauf je Verbindung:
//
//	Agent -> Node  "M64PUSH1 <token> <fingerabdruck>\n"  (Kennung, hoechstens 160 Byte)
//	Node  -> Agent "W"                                    (Token bekannt, Verbindung wartet bei der Node)
//	Node  -> Agent "S"                                    (Node braucht die Verbindung: SSH beginnt)
//	danach SSH wie beim Abfragen (Agent = Server, Node = Client)
//
// Der Token ist nur ein Wegweiser zum Zugang (zufaellig, zeigt der Assistent im Installationsbefehl; er steht in
// <dir>/connect, nicht in der Befehlszeile). Er ersetzt keine Pruefung: die Node nimmt nur eine Verbindung, deren
// SSH-Handshake zum gemerkten Hostschluessel passt, und der Agent nimmt nur Schluessel aus keys.
//
// Kein TLS um die TCP-Verbindung: SSH verschluesselt und authentisiert beide Seiten bereits (Hostschluessel des
// Agents fest bei der Node, Schluessel der Node in keys). TLS braeuchte ein eigenes Zertifikat der Node, das der
// Agent pruefen muesste - das schuetzte nur die Kennung (Token, Fingerabdruck), und die ist kein Geheimnis, das
// Zugriff gibt: Wer sie mitliest, kann hoechstens beim allerersten Kontakt (vor dem Merken des Hostschluessels)
// zuvorkommen - genau wie ein Angreifer im Netz beim ersten Abfragen (TOFU). Den Fingerabdruck zum Vergleich zeigt
// die Installation an.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Push-Protokoll und Standardwerte.
const (
	DefaultPushPort = 6466       // Standard-Port des Lauschers der Node (TCP)
	PushMagic       = "M64PUSH1" // Kennung, Version 1
	PushFile        = "connect"  // Ziele in <dir>/connect, eine Zeile je Node: token@host[:port]

	maxPushTargets      = 8
	maxPushFileBytes    = 4 << 10
	maxPushHello        = 160
	pushDialTimeout     = 10 * time.Second
	pushAckTimeout      = 10 * time.Second
	pushParkMax         = 15 * time.Minute // auf "S" warten (die Node raeumt wartende Verbindungen nach 10 min)
	pushKeepaliveEvery  = 30 * time.Second
	pushKeepaliveWait   = 15 * time.Second
	defaultPushRetryMin = 5 * time.Second
	defaultPushRetryMax = 5 * time.Minute

	pushAck   = 'W'
	pushStart = 'S'
)

// PushTarget ist eine Node, zu der der Agent die Verbindung aufbaut.
type PushTarget struct {
	Token string // Wegweiser zum Zugang bei der Node ([a-z0-9], 16-64 Zeichen)
	Addr  string // host:port
}

// String liefert die Adresse ohne Token (fuer das Log).
func (t PushTarget) String() string { return t.Addr }

// ValidPushToken prueft einen Token: 16 bis 64 Zeichen aus a-z und 0-9.
func ValidPushToken(s string) bool {
	if len(s) < 16 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// ParsePushTarget liest "token@host[:port]" (IPv6 in Klammern; ohne Port DefaultPushPort).
func ParsePushTarget(s string) (PushTarget, error) {
	s = strings.TrimSpace(s)
	tok, addr, ok := strings.Cut(s, "@")
	if !ok {
		return PushTarget{}, errors.New("expected token@host[:port]")
	}
	if !ValidPushToken(tok) {
		return PushTarget{}, errors.New("invalid token (16-64 characters a-z, 0-9)")
	}
	if addr == "" || len(addr) > 255 || strings.ContainsAny(addr, "@/\\ \t\"'") {
		return PushTarget{}, errors.New("invalid address")
	}
	for _, r := range addr {
		if r < 0x21 || r > 0x7e {
			return PushTarget{}, errors.New("invalid address")
		}
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// ohne Port ("node.example", "[2001:db8::1]", "2001:db8::1")
		if strings.HasPrefix(addr, "[") != strings.HasSuffix(addr, "]") {
			return PushTarget{}, errors.New("invalid address")
		}
		host, port = strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]"), strconv.Itoa(DefaultPushPort)
		if strings.ContainsAny(host, "[]") {
			return PushTarget{}, errors.New("invalid address")
		}
	}
	if host == "" {
		return PushTarget{}, errors.New("host missing")
	}
	if p, err := strconv.Atoi(port); err != nil || p <= 0 || p > 65535 {
		return PushTarget{}, fmt.Errorf("invalid port %q", port)
	}
	return PushTarget{Token: tok, Addr: net.JoinHostPort(host, port)}, nil
}

// ParsePushTargets liest die Ziele (eine Zeile je Node, # Kommentar, Leerzeilen erlaubt). Doppelte Ziele zaehlen
// einmal, hoechstens 8.
func ParsePushTargets(data []byte) ([]PushTarget, error) {
	var out []PushTarget
	seen := map[PushTarget]bool{}
	for i, raw := range bytes.Split(data, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if line == "" || line[0] == '#' {
			continue
		}
		t, err := ParsePushTarget(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if seen[t] {
			continue
		}
		if len(out) >= maxPushTargets {
			return nil, fmt.Errorf("more than %d nodes", maxPushTargets)
		}
		seen[t] = true
		out = append(out, t)
	}
	return out, nil
}

// ReadPushFile liest <dir>/connect. Fehlt die Datei, gibt es keine Ziele (nil, nil). Zu offene Rechte werden wie
// beim Hostschluessel auf 0600 gesetzt (der Token soll nicht fuer alle Benutzer lesbar sein).
func ReadPushFile(path string) ([]PushTarget, error) {
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	if fi.Size() > maxPushFileBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxPushFileBytes)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		_ = os.Chmod(path, 0o600)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPushFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPushFileBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxPushFileBytes)
	}
	t, err := ParsePushTargets(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return t, nil
}

// WritePushFile schreibt die Ziele nach path (0600, atomar; install).
func WritePushFile(path string, targets []PushTarget) error {
	var b strings.Builder
	b.WriteString("# Monitor64-Agent: nodes this agent connects to (token@host:port, one per line)\n")
	for _, t := range targets {
		if !ValidPushToken(t.Token) || t.Addr == "" {
			return errors.New("invalid push target")
		}
		b.WriteString(t.Token + "@" + t.Addr + "\n")
	}
	return writeFileAtomic(path, []byte(b.String()), 0o600)
}

// AddPushTargets nimmt neue Ziele in eine vorhandene Liste auf (install): ein Ziel mit derselben Adresse wird
// ersetzt (neuer Token derselben Node), sonst angehaengt; hoechstens 8.
func AddPushTargets(old, add []PushTarget) ([]PushTarget, error) {
	out := append([]PushTarget(nil), old...)
	for _, t := range add {
		if !ValidPushToken(t.Token) || t.Addr == "" {
			return nil, errors.New("invalid push target")
		}
		found := false
		for i := range out {
			if out[i].Addr == t.Addr {
				out[i], found = t, true
			}
		}
		if !found {
			out = append(out, t)
		}
	}
	if len(out) > maxPushTargets {
		return nil, fmt.Errorf("more than %d nodes", maxPushTargets)
	}
	return out, nil
}

// pushHello baut die Kennung fuer t.
func (s *Server) pushHello(t PushTarget) string {
	return PushMagic + " " + t.Token + " " + Fingerprint(s.cfg.HostKey.PublicKey()) + "\n"
}

// Ergebnis eines Verbindungsversuchs.
type pushResult int

const (
	pushFailed pushResult = iota // Verbindung, Kennung oder Anmeldung gescheitert: Wartezeit verdoppeln
	pushRouted                   // Node kennt den Token, hat die wartende Verbindung aber ohne SSH beendet
	pushServed                   // die Node war angemeldet
)

// Push haelt eine ausgehende Verbindung zur Node t (je Ziel ein Aufruf, z. B. in einer eigenen Goroutine). Auf der
// Verbindung laeuft der SSH-Server wie beim Lauschen; endet sie, wird neu verbunden. Nach Fehlschlaegen (keine
// Verbindung, Token unbekannt, Anmeldung abgelehnt) waechst die Wartezeit von PushRetryMin bis PushRetryMax (mit
// Zufallsanteil, damit nach einem Neustart der Node nicht alle Agents gleichzeitig kommen); nach einer Anmeldung
// beginnt sie wieder vorne. Laeuft bis Close und liefert dann ErrServerClosed.
//
// Die Bremse vor der Anmeldung gilt hier sinngemaess: die Gegenstelle ist fest eingestellt, Fehlversuche verlaengern
// die Wartezeit (Fehlversuche zaehlen nicht im Limiter des Lauschers, damit eine falsch eingerichtete Node nicht die
// Abfragen derselben Adresse sperrt).
func (s *Server) Push(t PushTarget) error {
	if !ValidPushToken(t.Token) || t.Addr == "" {
		return errors.New("monitor64-agent: invalid push target")
	}
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		return ErrServerClosed
	}
	s.startSweepLocked()
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()

	delay := s.cfg.PushRetryMin
	lastErr := ""
	for {
		res, err := s.pushOnce(t)
		switch {
		case err != nil && err.Error() != lastErr:
			s.log.Warn("monitor64-agent: push connection failed", "node", t.String(), "err", err)
			lastErr = err.Error()
		case err != nil:
			s.log.Debug("monitor64-agent: push connection failed", "node", t.String(), "err", err)
		default:
			lastErr = ""
		}
		wait := delay
		if res == pushFailed {
			delay = min(2*delay, s.cfg.PushRetryMax)
		} else {
			delay = s.cfg.PushRetryMin
			wait = delay
		}
		tm := time.NewTimer(jitter(wait))
		select {
		case <-s.done:
			tm.Stop()
			return ErrServerClosed
		case <-tm.C:
		}
	}
}

// jitter streut d um +-20 %.
func jitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
}

// pushOnce baut eine Verbindung auf, meldet sich mit der Kennung, wartet auf den Start durch die Node und bedient
// dann eine SSH-Verbindung.
func (s *Server) pushOnce(t PushTarget) (pushResult, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-s.done: // Close bricht den Verbindungsaufbau ab
			cancel()
		case <-ctx.Done():
		}
	}()
	d := net.Dialer{Timeout: pushDialTimeout, KeepAlive: 30 * time.Second}
	c, err := d.DialContext(ctx, "tcp", t.Addr)
	if err != nil {
		if s.closed.Load() {
			return pushFailed, nil
		}
		return pushFailed, err
	}
	if !s.track(c, true) {
		_ = c.Close()
		return pushFailed, nil
	}
	defer s.track(c, false)
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(pushAckTimeout))
	if _, err := io.WriteString(c, s.pushHello(t)); err != nil {
		return pushFailed, fmt.Errorf("send hello: %w", err)
	}
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return pushFailed, errors.New("node did not accept the connection (unknown token or node not ready)")
	}
	if b[0] != pushAck {
		return pushFailed, errors.New("node sent an unexpected answer")
	}
	// Warten, bis die Node die Verbindung braucht. Beendet sie sie vorher (aufgeraeumt, ersetzt), ist das kein Fehler.
	_ = c.SetDeadline(time.Now().Add(pushParkMax))
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return pushRouted, nil
	}
	if b[0] != pushStart {
		return pushFailed, errors.New("node sent an unexpected answer")
	}
	_ = c.SetDeadline(time.Time{})
	if !s.handleConn(c, peerOf(c.RemoteAddr()), nil, true) {
		if s.closed.Load() {
			return pushFailed, nil
		}
		return pushFailed, errors.New("SSH login of the node failed (is its key in keys?)")
	}
	return pushServed, nil
}

// pushKeepalive prueft eine angemeldete Push-Verbindung regelmaessig (globale Anfrage, die Node antwortet immer) und
// schliesst sie, wenn die Antwort ausbleibt: eine tote Verbindung (NAT-Eintrag verfallen, Node neu gestartet) wird
// so erkannt, und der Agent verbindet neu. Der Verkehr haelt ausserdem den NAT-Eintrag offen.
func (s *Server) pushKeepalive(ctx context.Context, sc *ssh.ServerConn) {
	every := s.pushKeepaliveEvery
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		res := make(chan error, 1)
		go func() {
			_, _, err := sc.SendRequest("keepalive@openssh.com", true, nil)
			res <- err
		}()
		wait := time.NewTimer(min(pushKeepaliveWait, every))
		select {
		case err := <-res:
			wait.Stop()
			if err == nil {
				continue
			}
		case <-wait.C:
		case <-ctx.Done():
			wait.Stop()
			return
		}
		s.log.Info("monitor64-agent: push connection lost (no keepalive answer)", "remote", sc.RemoteAddr().String())
		_ = sc.Close()
		return
	}
}
