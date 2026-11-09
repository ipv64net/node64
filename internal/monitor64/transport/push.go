package transport

// Push-Betrieb fuer Agents hinter NAT oder auf einem VPS (Gegenstueck zu m64agent/push.go): Der Agent baut die
// TCP-Verbindung zur Node auf, die Node nimmt sie hier an und gibt sie dem AgentClient des Zugangs als Ergebnis des
// "Waehlens". Die SSH-Rollen bleiben: der Agent ist Server (prueft die Node ueber keys), die Node ist Client und prueft
// den gemerkten Hostschluessel des Agents (TOFU) - das Sicherheitsmodell ist dasselbe wie beim Abfragen.
//
// Kennung: "M64PUSH1 <token> <fingerabdruck>\n" (hoechstens 160 Byte, 5 s Zeitlimit). Der Token ordnet die Verbindung
// einem Zugang zu (zufaellig, 128 Bit, steht im Installationsbefehl). Er ist nur ein Wegweiser: verwendet wird eine
// Verbindung erst, wenn der SSH-Handshake zum gemerkten Hostschluessel passt. Wer den Fingerabdruck kennt (er ist
// nicht geheim), kommt ohne Token gar nicht bis zum Zugang, und mit Token scheitert er am Handshake (er hat den
// privaten Schluessel nicht); seine Verbindung wird verworfen, eine passende des echten Agents bevorzugt. Vor dem
// ersten Kontakt (noch kein Hostschluessel gemerkt) muss der angebotene Schluessel zum angekuendigten Fingerabdruck
// passen und wird dann gemerkt - wie beim ersten Abfragen.
//
// Kein TLS: SSH verschluesselt und authentisiert beide Seiten (Begruendung in m64agent/push.go).
//
// Grenzen gegen fremde Gegenstellen: Verbindungen in der Kennungsphase je Netz (IPv6 /64, IPv4 je Adresse) und
// gesamt, wartende Verbindungen je Token, je Netz und Token, je Netz und gesamt; Fehlversuche (unbekannter Token,
// kaputte Kennung, Zeitlimit) sperren ein Netz fuer kurze Zeit, nie aber ein Netz, aus dem schon ein Agent mit
// gueltigem Token kam (viele Agents hinter einer NAT-Adresse).

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Push-Protokoll und Standardwerte.
const (
	DefaultPushPort = 6466       // Standard-Port des Lauschers (TCP)
	PushMagic       = "M64PUSH1" // Kennung, Version 1
	DefaultPushWait = 5 * time.Second

	pushHelloMax          = 160
	pushHelloTimeout      = 5 * time.Second
	pushWriteTimeout      = 5 * time.Second
	defaultPushParkMax    = 10 * time.Minute // wartende Verbindung danach schliessen (der Agent verbindet neu)
	pushPendingTotal      = 128              // Verbindungen in der Kennungsphase gesamt
	pushPendingPerNet     = 16               // ... je Netz (mehrere Agents hinter einer NAT-Adresse)
	pushParkedPerToken    = 4                // wartende Verbindungen je Zugang
	pushParkedPerNetToken = 2                // ... davon je Netz (ein Netz verdraengt nicht alle anderen)
	pushParkedPerNet      = 256
	pushParkedTotal       = 4096
	pushFailFree          = 20 // Fehlversuche je Netz ohne Sperre
	pushFailBlock         = 5 * time.Minute
	pushFailForget        = 10 * time.Minute
	pushGoodForget        = 24 * time.Hour
	pushMaxNets           = 4096
	pushProbeWait         = 5 * time.Second // alte Verbindung muss so schnell auf ein Keepalive antworten
	pushMaxAttempts       = 4               // je Anfrage so viele wartende Verbindungen versuchen

	pushAck   = 'W'
	pushStart = 'S'
)

// ErrNotConnected: im Push-Betrieb ist innerhalb der Wartezeit keine Verbindung des Agents da.
var ErrNotConnected = errors.New("monitor64: agent not connected (push)")

var tokenEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// NewPushToken erzeugt einen Token fuer einen Push-Zugang (128 Bit, 26 Zeichen a-z/2-7).
func NewPushToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("monitor64: random: " + err.Error()) // crypto/rand scheitert nicht (Go >= 1.24)
	}
	return tokenEncoding.EncodeToString(b[:])
}

// ValidPushToken prueft einen Token: 16 bis 64 Zeichen aus a-z und 0-9 (wie m64agent.ValidPushToken).
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

// validFingerprint: "SHA256:" und 43 Zeichen Base64 ohne Auffuellung (ssh.FingerprintSHA256).
func validFingerprint(s string) bool {
	if len(s) != 50 || !strings.HasPrefix(s, "SHA256:") {
		return false
	}
	for i := 7; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '+' && c != '/' {
			return false
		}
	}
	return true
}

// parseHello prueft die Kennung (ohne Zeilenende).
func parseHello(line string) (token, fp string, ok bool) {
	f := strings.Split(line, " ")
	if len(f) != 3 || f[0] != PushMagic || !ValidPushToken(f[1]) || !validFingerprint(f[2]) {
		return "", "", false
	}
	return f[1], f[2], true
}

// PushConfig stellt den Lauscher ein.
type PushConfig struct {
	Logger  *slog.Logger
	ParkMax time.Duration // wartende Verbindung nach so langer Zeit schliessen (0 = 10 min)
}

// PushListener nimmt Push-Verbindungen von Agents an und haelt sie fuer die Clients der Zugaenge bereit. Ein
// Lauscher fuer alle Zugaenge; Clients melden sich ueber AgentConfig.Push mit ihrem Token an.
type PushListener struct {
	log          *slog.Logger
	parkMax      time.Duration
	helloTimeout time.Duration // Tests setzen weniger

	mu      sync.Mutex
	boxes   map[string]*pushBox // Token -> Zugang
	lns     map[net.Listener]struct{}
	conns   map[net.Conn]struct{} // Kennungsphase und wartend (Close schliesst sie)
	pending int
	pendNet map[string]int
	parked  int
	parkNet map[string]int
	fails   map[string]*pushFail
	good    map[string]time.Time // Netze, aus denen ein gueltiger Token kam
	closed  bool
	done    chan struct{}
	wg      sync.WaitGroup
}

type pushBox struct {
	owner  *conn         // Client des Zugangs
	parked []*parkedConn // aelteste zuerst
	wake   chan struct{} // wird bei neuer Verbindung geschlossen und ersetzt
}

type parkedConn struct {
	c       net.Conn
	net     string
	claimed string // angekuendigter Fingerabdruck
	box     *pushBox
	taken   bool
	expire  *time.Timer
	done    chan struct{} // Wache beendet
}

type pushFail struct {
	n     int
	last  time.Time
	until time.Time
}

// NewPushListener legt den Lauscher an; Listen oder Serve starten ihn.
func NewPushListener(cfg PushConfig) *PushListener {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.ParkMax <= 0 {
		cfg.ParkMax = defaultPushParkMax
	}
	return &PushListener{log: log, parkMax: cfg.ParkMax, helloTimeout: pushHelloTimeout, boxes: map[string]*pushBox{}, lns: map[net.Listener]struct{}{},
		conns: map[net.Conn]struct{}{}, pendNet: map[string]int{}, parkNet: map[string]int{},
		fails: map[string]*pushFail{}, good: map[string]time.Time{}, done: make(chan struct{})}
}

// Listen lauscht auf addr (z. B. ":6466") und nimmt im Hintergrund an, bis Close. Liefert die tatsaechliche Adresse.
func (l *PushListener) Listen(addr string) (net.Addr, error) {
	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		_ = ln.Close()
		return nil, ErrClosed
	}
	l.wg.Add(1)
	l.mu.Unlock()
	go func() {
		defer l.wg.Done()
		if err := l.Serve(ln); err != nil && !errors.Is(err, ErrClosed) {
			l.log.Warn("monitor64: push listener stopped", "addr", ln.Addr().String(), "err", err)
		}
	}()
	return ln.Addr(), nil
}

// Serve nimmt Verbindungen an, bis Close aufgerufen wird (liefert dann ErrClosed).
func (l *PushListener) Serve(ln net.Listener) error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		_ = ln.Close()
		return ErrClosed
	}
	l.lns[ln] = struct{}{}
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		delete(l.lns, ln)
		l.mu.Unlock()
	}()
	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			l.mu.Lock()
			_, active := l.lns[ln]
			closed := l.closed || !active // Close bzw. StopListening
			l.mu.Unlock()
			if closed {
				return ErrClosed
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
		n := pushNet(c.RemoteAddr())
		if !l.admit(c, n, time.Now()) {
			_ = c.Close()
			continue
		}
		go func() {
			defer l.wg.Done()
			l.handleHello(c, n)
		}()
	}
}

// Close schliesst Lauscher, wartende Verbindungen und Verbindungen in der Kennungsphase. Uebergebene Verbindungen
// gehoeren den Clients.
func (l *PushListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	close(l.done)
	for ln := range l.lns {
		_ = ln.Close()
	}
	for c := range l.conns {
		_ = c.Close()
	}
	for _, b := range l.boxes {
		for _, pc := range b.parked {
			pc.expire.Stop()
		}
		b.parked = nil
	}
	l.mu.Unlock()
	l.wg.Wait()
	return nil
}

// StopListening schliesst die Ports (z. B. kein Push-Zugang mehr, Port geaendert), behaelt aber angemeldete
// Clients und wartende Verbindungen; Listen oeffnet wieder.
func (l *PushListener) StopListening() {
	l.mu.Lock()
	lns := make([]net.Listener, 0, len(l.lns))
	for ln := range l.lns {
		lns = append(lns, ln)
		delete(l.lns, ln)
	}
	l.mu.Unlock()
	for _, ln := range lns {
		_ = ln.Close()
	}
}

// Listening liefert die Adressen der offenen Ports (leer = keiner).
func (l *PushListener) Listening() []net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]net.Addr, 0, len(l.lns))
	for ln := range l.lns {
		out = append(out, ln.Addr())
	}
	return out
}

// PushStats: Zahlen fuer Anzeige und Tests.
type PushStats struct {
	Tokens  int // angemeldete Zugaenge
	Pending int // Verbindungen in der Kennungsphase
	Parked  int // wartende Verbindungen
}

// Stats liefert die aktuellen Zahlen.
func (l *PushListener) Stats() PushStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	return PushStats{Tokens: len(l.boxes), Pending: l.pending, Parked: l.parked}
}

// Waiting meldet, ob fuer token eine Verbindung des Agents wartet (z. B. fuer "Agent verbunden" in der Oberflaeche;
// eine schon genutzte Verbindung zaehlt hier nicht).
func (l *PushListener) Waiting(token string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.boxes[token]
	return b != nil && len(b.parked) > 0
}

// pushNet: Netz einer Gegenstelle (IPv6 /64, IPv4 = Adresse).
func pushNet(addr net.Addr) string {
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return addr.String()
	}
	ip := ap.Addr().Unmap().WithZone("")
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.String()
	}
	return ip.String()
}

// admit prueft Sperre und Grenzen der Kennungsphase und belegt einen Platz (samt wg fuer handleHello, unter l.mu,
// damit Close nicht gleichzeitig wartet).
func (l *PushListener) admit(c net.Conn, n string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.refusedLocked(n, now) || l.pending >= pushPendingTotal || l.pendNet[n] >= pushPendingPerNet {
		return false
	}
	l.pending++
	l.pendNet[n]++
	l.conns[c] = struct{}{}
	l.wg.Add(1)
	return true
}

func (l *PushListener) releasePendingLocked(n string) {
	l.pending--
	decr(l.pendNet, n)
}

func decr(m map[string]int, k string) {
	if m[k] <= 1 {
		delete(m, k)
	} else {
		m[k]--
	}
}

// refusedLocked: Netz gesperrt (nie, wenn von dort schon ein gueltiger Token kam).
func (l *PushListener) refusedLocked(n string, now time.Time) bool {
	if t, ok := l.good[n]; ok && now.Sub(t) < pushGoodForget {
		return false
	}
	f := l.fails[n]
	return f != nil && now.Before(f.until)
}

func (l *PushListener) failLocked(n string, now time.Time) {
	if t, ok := l.good[n]; ok && now.Sub(t) < pushGoodForget {
		return
	}
	f := l.fails[n]
	if f == nil {
		if len(l.fails) >= pushMaxNets {
			evictOldest(l.fails, func(f *pushFail) time.Time { return f.last }, func(f *pushFail) bool {
				return now.Sub(f.last) > pushFailForget && !now.Before(f.until)
			})
		}
		f = &pushFail{}
		l.fails[n] = f
	}
	if now.Sub(f.last) > pushFailForget {
		f.n = 0
	}
	f.n++
	f.last = now
	if f.n >= pushFailFree {
		f.until = now.Add(pushFailBlock)
	}
}

func (l *PushListener) okLocked(n string, now time.Time) {
	delete(l.fails, n)
	if _, ok := l.good[n]; !ok && len(l.good) >= pushMaxNets {
		evictOldest(l.good, func(t time.Time) time.Time { return t }, func(t time.Time) bool {
			return now.Sub(t) >= pushGoodForget
		})
	}
	l.good[n] = now
}

// evictOldest entfernt verfallene Eintraege, sonst den aeltesten.
func evictOldest[V any](m map[string]V, at func(V) time.Time, stale func(V) bool) {
	var oldest string
	var t time.Time
	for k, v := range m {
		if stale(v) {
			delete(m, k)
			continue
		}
		if oldest == "" || at(v).Before(t) {
			oldest, t = k, at(v)
		}
	}
	if oldest != "" && len(m) >= pushMaxNets {
		delete(m, oldest)
	}
}

// readHello liest die Kennung byteweise bis "\n" (nichts darueber hinaus: danach kommt SSH).
func readHello(c net.Conn) (string, bool) {
	var buf [pushHelloMax]byte
	for i := 0; i < len(buf); i++ {
		if _, err := io.ReadFull(c, buf[i:i+1]); err != nil {
			return "", false
		}
		if buf[i] == '\n' {
			return string(buf[:i]), true
		}
	}
	return "", false
}

// handleHello liest die Kennung, ordnet die Verbindung einem Zugang zu und stellt sie bereit.
func (l *PushListener) handleHello(c net.Conn, n string) {
	_ = c.SetDeadline(time.Now().Add(l.helloTimeout))
	line, ok := readHello(c)
	var token, fp string
	if ok {
		token, fp, ok = parseHello(line)
	}
	now := time.Now()
	l.mu.Lock()
	l.releasePendingLocked(n)
	var b *pushBox
	if ok && !l.closed {
		b = l.boxes[token]
	}
	if b == nil {
		if !l.closed {
			l.failLocked(n, now)
		}
		delete(l.conns, c)
		l.mu.Unlock()
		_ = c.Close()
		l.log.Debug("monitor64: push connection refused (unknown token or invalid hello)", "remote", c.RemoteAddr().String())
		return
	}
	l.okLocked(n, now)
	l.mu.Unlock()

	// Bestaetigen (ausserhalb der Sperre: ein langsamer Empfaenger haelt sonst alle auf).
	_ = c.SetWriteDeadline(time.Now().Add(pushWriteTimeout))
	if _, err := c.Write([]byte{pushAck}); err != nil {
		l.mu.Lock()
		delete(l.conns, c)
		l.mu.Unlock()
		_ = c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	l.park(c, n, token, fp)
}

// park stellt die Verbindung fuer den Zugang bereit. Zu viele wartende Verbindungen verdraengen erst die aelteren
// desselben Netzes beim Zugang (Neustart des Agents), dann die aelteste des Zugangs.
func (l *PushListener) park(c net.Conn, n, token, fp string) {
	pc := &parkedConn{c: c, net: n, claimed: fp, done: make(chan struct{})}
	l.mu.Lock()
	b := l.boxes[token]
	same := 0
	if b != nil {
		for _, o := range b.parked {
			if o.net == n {
				same++
			}
		}
	}
	free := max(0, same-pushParkedPerNetToken+1) // so viele eigene werden gleich verdraengt
	if l.closed || b == nil || l.parkNet[n]-free >= pushParkedPerNet || l.parked-free >= pushParkedTotal {
		delete(l.conns, c)
		l.mu.Unlock()
		_ = c.Close()
		return
	}
	var drop []*parkedConn
	for i := 0; i < len(b.parked) && same >= pushParkedPerNetToken; {
		if o := b.parked[i]; o.net == n {
			drop = append(drop, o)
			l.unparkLocked(o)
			same--
			continue
		}
		i++
	}
	if len(b.parked) >= pushParkedPerToken {
		drop = append(drop, b.parked[0])
		l.unparkLocked(b.parked[0])
	}
	pc.box = b
	b.parked = append(b.parked, pc)
	l.parked++
	l.parkNet[n]++
	pc.expire = time.AfterFunc(l.parkMax, func() { l.expire(pc) })
	close(b.wake)
	b.wake = make(chan struct{})
	owner := b.owner
	l.wg.Add(1)
	l.mu.Unlock()
	l.closeParked(drop)
	go func() {
		defer l.wg.Done()
		l.watch(pc)
	}()
	// Haengt beim Zugang noch eine (vielleicht tote) Verbindung, wird sie geprueft: die neue des Agents kommt meist,
	// weil die alte nicht mehr lebt (Neustart des Agents, neue NAT-Adresse).
	if owner != nil {
		owner.probeStale(pushProbeWait)
	}
}

// unparkLocked nimmt eine wartende Verbindung aus ihrem Zugang (l.mu gehalten; schliesst sie nicht).
func (l *PushListener) unparkLocked(pc *parkedConn) bool {
	b := pc.box
	if b == nil {
		return false
	}
	for i, o := range b.parked {
		if o == pc {
			b.parked = append(b.parked[:i:i], b.parked[i+1:]...)
			l.parked--
			decr(l.parkNet, pc.net)
			pc.box = nil
			if pc.expire != nil {
				pc.expire.Stop()
			}
			return true
		}
	}
	return false
}

// closeParked schliesst verdraengte Verbindungen (ohne l.mu).
func (l *PushListener) closeParked(list []*parkedConn) {
	for _, pc := range list {
		l.mu.Lock()
		delete(l.conns, pc.c)
		l.mu.Unlock()
		_ = pc.c.Close()
	}
}

func (l *PushListener) expire(pc *parkedConn) {
	l.mu.Lock()
	ok := !pc.taken && l.unparkLocked(pc)
	if ok {
		delete(l.conns, pc.c)
	}
	l.mu.Unlock()
	if ok {
		_ = pc.c.Close()
	}
}

// watch liest von einer wartenden Verbindung: der Agent schickt bis "S" nichts. Endet das Lesen (Agent weg, Daten
// entgegen dem Protokoll), wird die Verbindung verworfen - ausser sie wurde gerade uebernommen (take setzt dazu
// eine abgelaufene Lesefrist).
func (l *PushListener) watch(pc *parkedConn) {
	defer close(pc.done)
	var b [1]byte
	_, _ = pc.c.Read(b[:])
	l.mu.Lock()
	if pc.taken {
		l.mu.Unlock()
		return
	}
	l.unparkLocked(pc)
	delete(l.conns, pc.c)
	l.mu.Unlock()
	_ = pc.c.Close()
}

// register meldet den Client eines Zugangs an (ersetzt einen vorigen Client desselben Tokens; wartende
// Verbindungen bleiben).
func (l *PushListener) register(token string, owner *conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.boxes[token]; b != nil {
		b.owner = owner
		return
	}
	l.boxes[token] = &pushBox{owner: owner, wake: make(chan struct{})}
}

// unregister meldet den Client ab (nur, wenn er noch angemeldet ist) und schliesst wartende Verbindungen.
func (l *PushListener) unregister(token string, owner *conn) {
	l.mu.Lock()
	b := l.boxes[token]
	if b == nil || b.owner != owner {
		l.mu.Unlock()
		return
	}
	delete(l.boxes, token)
	drop := append([]*parkedConn(nil), b.parked...)
	for _, pc := range drop {
		l.unparkLocked(pc)
	}
	close(b.wake)
	l.mu.Unlock()
	l.closeParked(drop)
}

// take liefert eine wartende Verbindung fuer token und gibt dem Agent das Startzeichen. Bevorzugt wird eine, deren
// angekuendigter Fingerabdruck zum gemerkten passt, sonst die neueste. Wartet hoechstens bis until (ctx und life
// brechen ab); ohne Verbindung ErrNotConnected.
func (l *PushListener) take(ctx, life context.Context, token, pinned string, until time.Time) (*parkedConn, error) {
	for {
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return nil, ErrNotConnected
		}
		b := l.boxes[token]
		if b == nil {
			l.mu.Unlock()
			return nil, ErrNotConnected
		}
		var pc *parkedConn
		for i := len(b.parked) - 1; i >= 0; i-- {
			if o := b.parked[i]; pinned == "" || o.claimed == pinned {
				pc = o
				break
			}
		}
		if pc == nil && len(b.parked) > 0 {
			pc = b.parked[len(b.parked)-1]
		}
		if pc != nil {
			pc.taken = true
			l.unparkLocked(pc)
			delete(l.conns, pc.c)
			l.mu.Unlock()
			// Wache beenden (abgelaufene Lesefrist), dann Startzeichen.
			_ = pc.c.SetReadDeadline(time.Unix(1, 0))
			<-pc.done
			_ = pc.c.SetDeadline(time.Now().Add(pushWriteTimeout))
			if _, err := pc.c.Write([]byte{pushStart}); err != nil {
				_ = pc.c.Close()
				continue // Agent inzwischen weg: naechste
			}
			_ = pc.c.SetDeadline(time.Time{})
			return pc, nil
		}
		wake := b.wake
		l.mu.Unlock()
		wait := time.Until(until)
		if wait <= 0 {
			return nil, ErrNotConnected
		}
		t := time.NewTimer(wait)
		select {
		case <-wake:
			t.Stop()
		case <-t.C:
			return nil, ErrNotConnected
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-life.Done():
			t.Stop()
			return nil, ErrClosed
		case <-l.done:
			t.Stop()
			return nil, ErrNotConnected
		}
	}
}

// rejected protokolliert eine verworfene Push-Verbindung (ohne Token).
func (l *PushListener) rejected(pc *parkedConn, err error) {
	l.log.Warn("monitor64: push connection rejected", "remote", pc.c.RemoteAddr().String(), "err", CleanError(err).Error())
}
