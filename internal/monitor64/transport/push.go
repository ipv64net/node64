package transport

// Push-Betrieb fuer Agents hinter NAT oder auf einem VPS (Gegenstueck zu m64agent/push.go): Der Agent baut die
// TCP-Verbindung zur Node auf, die Node nimmt sie hier an und gibt sie dem AgentClient des Zugangs als Ergebnis des
// "Waehlens". Die SSH-Rollen bleiben: der Agent ist Server (prueft die Node ueber keys), die Node ist Client und prueft
// den gemerkten Hostschluessel des Agents (TOFU) - das Sicherheitsmodell ist dasselbe wie beim Abfragen.
//
// Kennung: "M64PUSH1 <token> <fingerabdruck>\n" (m64proto, hoechstens 160 Byte, 5 s Zeitlimit). Der Token ordnet die
// Verbindung einem Zugang zu (zufaellig, 128 Bit, steht im Installationsbefehl). Er gibt keinen Zugriff: verwendet
// wird eine Verbindung erst, wenn der SSH-Handshake zum gemerkten Hostschluessel passt. Wer den Token kennt, kann
// aber Verbindungen beim Zugang abstellen; er ist deshalb wie ein Geheimnis zu behandeln. Gegen einen Token-Inhaber
// ohne den privaten Schluessel des Agents:
//   - Verbindungen aus Netzen ohne erfolgreichen Handshake fuer diesen Zugang sind je Zugang begrenzt und verdraengen
//     nie eine Verbindung aus einem bestaetigten Netz.
//   - Kuendigt eine Verbindung den gemerkten Fingerabdruck an und zeigt im Handshake einen anderen Schluessel (das tut
//     der echte Agent nie), wird ihr Netz fuer den Zugang gesperrt (ErrPushForeignKey statt "Schluessel geaendert").
//     Andere gescheiterte Handshakes zaehlen je Netz und Zugang und sperren ab pushBadFree.
//   - Vor dem ersten Kontakt (bzw. nach "neuen uebernehmen") muss der angebotene Schluessel zum angekuendigten
//     Fingerabdruck passen. Gemerkt wird nur, wenn alle in Frage kommenden Verbindungen (bevorzugt aus bestaetigten
//     Netzen) denselben Fingerabdruck ankuendigen; sonst ErrPushAmbiguous.
//
// Kein TLS: SSH verschluesselt und authentisiert beide Seiten (Begruendung in m64agent/push.go).
//
// Grenzen gegen fremde Gegenstellen: Verbindungen in der Kennungsphase je Netz (IPv6 /64, IPv4 je Adresse), je /48
// und gesamt (mit Reserve fuer Netze, aus denen schon ein gueltiger Token kam), wartende Verbindungen je Token, je
// Netz und Token, je Netz und gesamt; Fehlversuche (unbekannter Token, kaputte Kennung, Zeitlimit) sperren ein Netz
// fuer kurze Zeit, nie aber ein Netz, aus dem schon ein Agent mit gueltigem Token kam (viele Agents hinter einer
// NAT-Adresse).
//
// Die Anmeldung eines Tokens (pushBox) haengt nicht an einem einzelnen Client: mehrere Clients koennen denselben
// Token anmelden, abgemeldet wird nur die eigene Anmeldung, und nach dem letzten Client bleibt sie noch boxGrace
// (Neubau des Clients bei einer Aenderung, ReloadHost).

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Push-Protokoll (m64proto) und Standardwerte.
const (
	DefaultPushWait = 5 * time.Second

	pushHelloMax          = m64proto.PushHelloMax
	pushHelloTimeout      = 5 * time.Second
	pushWriteTimeout      = 5 * time.Second
	defaultPushParkMax    = 10 * time.Minute // wartende Verbindung danach schliessen (der Agent verbindet neu)
	defaultPushBoxGrace   = 2 * time.Minute  // Anmeldung eines Tokens nach dem letzten Client so lange halten
	pushPendingTotal      = 128              // Verbindungen in der Kennungsphase gesamt
	pushPendingReserve    = 32               // ... davon nur fuer Netze, aus denen schon ein gueltiger Token kam
	pushPendingPerNet     = 16               // ... je Netz (mehrere Agents hinter einer NAT-Adresse)
	pushPendingPer48      = 32               // ... je IPv6-/48 (ein Anschluss hat viele /64)
	pushParkedPerToken    = 4                // wartende Verbindungen je Zugang
	pushParkedPerNetToken = 2                // ... davon je Netz (ein Netz verdraengt nicht alle anderen)
	pushParkedUnverified  = 2                // ... davon aus Netzen ohne erfolgreichen Handshake fuer den Zugang
	pushParkedPerNet      = 256
	pushParkedTotal       = 4096
	pushFailFree          = 20  // Fehlversuche je Netz ohne Sperre
	pushFail48Free        = 100 // ... je IPv6-/48 (Wechsel des /64 umgeht die Sperre je Netz)
	pushFailBlock         = 5 * time.Minute
	pushFailForget        = 10 * time.Minute
	pushGoodForget        = 24 * time.Hour
	pushMaxNets           = 4096
	pushBadFree           = 5                // gescheiterte Handshakes je Netz und Zugang ohne Sperre
	pushLiarBlock         = 30 * time.Minute // Sperre nach falsch angekuendigtem Schluessel
	pushVerifiedForget    = 30 * 24 * time.Hour
	pushLastErrKeep       = 15 * time.Minute // letzten Handshake-Fehler so lange statt ErrNotConnected melden
	pushBoxNets           = 64               // je Zugang gemerkte Netze (bestaetigt bzw. gescheitert)
	pushProbeWait         = 5 * time.Second  // alte Verbindung muss so schnell auf ein Keepalive antworten
	pushMaxAttempts       = 4                // je Anfrage so viele wartende Verbindungen versuchen

	pushAck   = m64proto.PushAck
	pushStart = m64proto.PushStart
)

var (
	// ErrNotConnected: im Push-Betrieb ist innerhalb der Wartezeit keine Verbindung des Agents da.
	ErrNotConnected = errors.New("monitor64: agent not connected (push)")
	// ErrPushAmbiguous: vor dem ersten Kontakt (bzw. nach "neuen uebernehmen") warten Verbindungen mit verschiedenen
	// angekuendigten Schluesseln; welche der echte Agent ist, ist offen, daher wird nichts gemerkt.
	ErrPushAmbiguous = errors.New("monitor64: push: connections with different host keys use this token (renew the token)")
	// ErrPushForeignKey: eine Verbindung kuendigte den gemerkten Schluessel an, zeigte im Handshake aber einen anderen.
	// Der echte Agent tut das nie: der Token ist vermutlich bekannt geworden.
	ErrPushForeignKey = errors.New("monitor64: push: a connection with this token claimed the known host key but presented another one (renew the token)")
)

var tokenEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// NewPushToken erzeugt einen Token fuer einen Push-Zugang (128 Bit, 26 Zeichen a-z/2-7).
func NewPushToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("monitor64: random: " + err.Error()) // crypto/rand scheitert nicht (Go >= 1.24)
	}
	return tokenEncoding.EncodeToString(b[:])
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
	if len(f) != 3 || f[0] != m64proto.PushMagic || !m64proto.ValidPushToken(f[1]) || !validFingerprint(f[2]) {
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
	boxGrace     time.Duration // Tests setzen weniger

	mu      sync.Mutex
	boxes   map[string]*pushBox // Token -> Zugang
	lns     map[net.Listener]struct{}
	conns   map[net.Conn]struct{} // Kennungsphase und wartend (Close schliesst sie)
	pending int
	pendNet map[string]int
	pend48  map[string]int
	parked  int
	parkNet map[string]int
	fails   map[string]*pushFail
	good    map[string]time.Time // Netze, aus denen ein gueltiger Token kam
	closed  bool
	done    chan struct{}
	wg      sync.WaitGroup
}

type pushBox struct {
	owners   map[*conn]struct{} // angemeldete Clients des Zugangs (mehrere z. B. beim Ersetzen eines Clients)
	parked   []*parkedConn      // aelteste zuerst
	wake     chan struct{}      // wird bei neuer Verbindung geschlossen und ersetzt
	gone     *time.Timer        // Karenz nach dem Abmelden des letzten Clients
	verified map[string]time.Time
	bad      map[string]*pushFail // gescheiterte Handshakes je Netz
	lastErr  error                // letzter Handshake-Fehler (bis zum naechsten Erfolg)
	lastAt   time.Time
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
	return &PushListener{log: log, parkMax: cfg.ParkMax, helloTimeout: pushHelloTimeout, boxGrace: defaultPushBoxGrace,
		boxes: map[string]*pushBox{}, lns: map[net.Listener]struct{}{}, conns: map[net.Conn]struct{}{},
		pendNet: map[string]int{}, pend48: map[string]int{}, parkNet: map[string]int{},
		fails: map[string]*pushFail{}, good: map[string]time.Time{}, done: make(chan struct{})}
}

// Listen lauscht auf addr (z. B. ":6466") und nimmt im Hintergrund an, bis Close. Liefert die tatsaechliche Adresse;
// der Port zaehlt sofort bei Listening.
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
	l.lns[ln] = struct{}{}
	l.wg.Add(1)
	l.mu.Unlock()
	go func() {
		defer l.wg.Done()
		if err := l.serve(ln); err != nil && !errors.Is(err, ErrClosed) {
			l.log.Warn("monitor64: push listener stopped", "addr", ln.Addr().String(), "err", err)
		}
	}()
	return ln.Addr(), nil
}

// Rebind oeffnet addr und schliesst erst danach die bisherigen Ports (Portwechsel ohne Luecke). Scheitert das
// Oeffnen, bleiben die bisherigen offen. Belegt ein bisheriger Port denselben Port (andere Adresse), wird er kurz
// geschlossen und bei einem Fehler wieder geoeffnet.
func (l *PushListener) Rebind(addr string) (net.Addr, error) {
	old := l.listeners()
	a, err := l.Listen(addr)
	if err != nil {
		clash := samePort(old, addr)
		if len(clash) == 0 || errors.Is(err, ErrClosed) {
			return nil, err
		}
		l.closeListeners(clash)
		if a, err = l.Listen(addr); err != nil {
			for _, ln := range clash { // bisherigen Port wieder oeffnen
				if _, rerr := l.Listen(ln.Addr().String()); rerr != nil {
					l.log.Warn("monitor64: push listener not reopened", "addr", ln.Addr().String(), "err", rerr)
				}
			}
			return nil, err
		}
	}
	l.closeListeners(old)
	return a, nil
}

// listeners liefert die offenen Ports.
func (l *PushListener) listeners() []net.Listener {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]net.Listener, 0, len(l.lns))
	for ln := range l.lns {
		out = append(out, ln)
	}
	return out
}

// closeListeners schliesst die angegebenen Ports (Serve endet dann mit ErrClosed).
func (l *PushListener) closeListeners(list []net.Listener) {
	l.mu.Lock()
	for _, ln := range list {
		delete(l.lns, ln)
	}
	l.mu.Unlock()
	for _, ln := range list {
		_ = ln.Close()
	}
}

// samePort: Ports aus list mit derselben Portnummer wie addr.
func samePort(list []net.Listener, addr string) []net.Listener {
	_, ps, err := net.SplitHostPort(addr)
	p, perr := strconv.Atoi(ps)
	if err != nil || perr != nil || p == 0 {
		return nil
	}
	var out []net.Listener
	for _, ln := range list {
		if ta, ok := ln.Addr().(*net.TCPAddr); ok && ta.Port == p {
			out = append(out, ln)
		}
	}
	return out
}

// Serve nimmt Verbindungen an, bis Close aufgerufen wird (liefert dann ErrClosed). ln wird am Ende geschlossen.
func (l *PushListener) Serve(ln net.Listener) error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		_ = ln.Close()
		return ErrClosed
	}
	l.lns[ln] = struct{}{}
	l.mu.Unlock()
	return l.serve(ln)
}

// serve: Annahme-Schleife fuer einen schon eingetragenen Port. Voruebergehende Fehler (Zeitlimit, zu viele offene
// Dateien EMFILE/ENFILE, abgebrochene Verbindung ...) beenden sie nicht: kurz warten, weiter annehmen. Endet sie
// doch, wird der Port geschlossen (sonst bliebe er belegt, ohne dass jemand annimmt).
func (l *PushListener) serve(ln net.Listener) error {
	defer func() {
		l.mu.Lock()
		delete(l.lns, ln)
		l.mu.Unlock()
		_ = ln.Close()
	}()
	var delay time.Duration
	logged := false
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
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			if !logged {
				l.log.Warn("monitor64: push accept", "addr", ln.Addr().String(), "err", err)
				logged = true
			}
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			t := time.NewTimer(delay)
			select {
			case <-t.C:
			case <-l.done:
				t.Stop()
				return ErrClosed
			}
			continue
		}
		delay, logged = 0, false
		n, n48 := pushNets(c.RemoteAddr())
		if !l.admit(c, n, n48, time.Now()) {
			_ = c.Close()
			continue
		}
		go func() {
			defer l.wg.Done()
			l.handleHello(c, n, n48)
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
		if b.gone != nil {
			b.gone.Stop()
		}
	}
	l.mu.Unlock()
	l.wg.Wait()
	return nil
}

// StopListening schliesst die Ports (z. B. kein Push-Zugang mehr), behaelt aber angemeldete Clients und wartende
// Verbindungen; Listen oeffnet wieder.
func (l *PushListener) StopListening() {
	l.closeListeners(l.listeners())
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

// pushNets: Netz einer Gegenstelle (IPv6 /64, IPv4 = Adresse) und bei IPv6 das /48 (sonst "").
func pushNets(addr net.Addr) (n, n48 string) {
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return addr.String(), ""
	}
	ip := ap.Addr().Unmap().WithZone("")
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		q, _ := ip.Prefix(48)
		return p.String(), q.String()
	}
	return ip.String(), ""
}

// admit prueft Sperre und Grenzen der Kennungsphase und belegt einen Platz (samt wg fuer handleHello, unter l.mu,
// damit Close nicht gleichzeitig wartet). Bekannte Netze (gueltiger Token) haben eine Reserve und keine /48-Grenze.
func (l *PushListener) admit(c net.Conn, n, n48 string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.refusedLocked(n, now) || l.pending >= pushPendingTotal || l.pendNet[n] >= pushPendingPerNet {
		return false
	}
	if !l.goodLocked(n, now) && (l.pending >= pushPendingTotal-pushPendingReserve || (n48 != "" && l.pend48[n48] >= pushPendingPer48) ||
		(n48 != "" && l.refusedLocked("48:"+n48, now))) {
		return false
	}
	l.pending++
	l.pendNet[n]++
	if n48 != "" {
		l.pend48[n48]++
	}
	l.conns[c] = struct{}{}
	l.wg.Add(1)
	return true
}

func (l *PushListener) releasePendingLocked(n, n48 string) {
	l.pending--
	decr(l.pendNet, n)
	if n48 != "" {
		decr(l.pend48, n48)
	}
}

func decr(m map[string]int, k string) {
	if m[k] <= 1 {
		delete(m, k)
	} else {
		m[k]--
	}
}

func (l *PushListener) goodLocked(n string, now time.Time) bool {
	t, ok := l.good[n]
	return ok && now.Sub(t) < pushGoodForget
}

// refusedLocked: Netz gesperrt (nie, wenn von dort schon ein gueltiger Token kam).
func (l *PushListener) refusedLocked(n string, now time.Time) bool {
	if l.goodLocked(n, now) {
		return false
	}
	f := l.fails[n]
	return f != nil && now.Before(f.until)
}

func (l *PushListener) failLocked(n string, now time.Time) {
	if l.goodLocked(n, now) {
		return
	}
	countFail(l.fails, n, now, pushFailFree, pushFailBlock, pushMaxNets)
}

// countFail zaehlt einen Fehlversuch von n in m (nach pushFailForget ohne Versuch beginnt die Zaehlung neu) und
// sperrt ab free Versuchen fuer block. m hat hoechstens limit Eintraege.
func countFail(m map[string]*pushFail, n string, now time.Time, free int, block time.Duration, limit int) {
	f := m[n]
	if f == nil {
		if len(m) >= limit {
			evictOldest(m, limit, func(f *pushFail) time.Time { return f.last }, func(f *pushFail) bool {
				return now.Sub(f.last) > pushFailForget && !now.Before(f.until)
			})
		}
		f = &pushFail{}
		m[n] = f
	}
	if now.Sub(f.last) > pushFailForget {
		f.n = 0
	}
	f.n++
	f.last = now
	if f.n >= free {
		f.until = now.Add(block)
	}
}

func (l *PushListener) okLocked(n string, now time.Time) {
	delete(l.fails, n)
	if _, ok := l.good[n]; !ok && len(l.good) >= pushMaxNets {
		evictOldest(l.good, pushMaxNets, func(t time.Time) time.Time { return t }, func(t time.Time) bool {
			return now.Sub(t) >= pushGoodForget
		})
	}
	l.good[n] = now
}

// evictOldest entfernt verfallene Eintraege, sonst den aeltesten (wenn m noch limit Eintraege hat).
func evictOldest[V any](m map[string]V, limit int, at func(V) time.Time, stale func(V) bool) {
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
	if oldest != "" && len(m) >= limit {
		delete(m, oldest)
	}
}

// verifiedLocked: aus Netz n kam fuer diesen Zugang schon ein erfolgreicher Handshake.
func (b *pushBox) verifiedLocked(n string, now time.Time) bool {
	t, ok := b.verified[n]
	return ok && now.Sub(t) < pushVerifiedForget
}

// blockedLocked: Netz n ist fuer diesen Zugang gesperrt (gescheiterte Handshakes).
func (b *pushBox) blockedLocked(n string, now time.Time) bool {
	f := b.bad[n]
	return f != nil && now.Before(f.until)
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
func (l *PushListener) handleHello(c net.Conn, n, n48 string) {
	_ = c.SetDeadline(time.Now().Add(l.helloTimeout))
	line, ok := readHello(c)
	var token, fp string
	if ok {
		token, fp, ok = parseHello(line)
	}
	now := time.Now()
	l.mu.Lock()
	l.releasePendingLocked(n, n48)
	var b *pushBox
	if ok && !l.closed {
		b = l.boxes[token]
	}
	if b == nil || b.blockedLocked(n, now) {
		if b == nil && !l.closed {
			l.failLocked(n, now)
			if n48 != "" && !l.goodLocked(n, now) { // auch je /48: viele /64 eines Anschlusses umgehen die Sperre je Netz sonst
				countFail(l.fails, "48:"+n48, now, pushFail48Free, pushFailBlock, pushMaxNets)
			}
		}
		delete(l.conns, c)
		l.mu.Unlock()
		_ = c.Close()
		l.log.Debug("monitor64: push connection refused (unknown token, invalid hello or blocked network)", "remote", c.RemoteAddr().String())
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
// desselben Netzes beim Zugang (Neustart des Agents), dann die aelteste aus einem nicht bestaetigten Netz. Eine
// Verbindung aus einem nicht bestaetigten Netz verdraengt nie eine aus einem bestaetigten (sie wird dann abgewiesen).
func (l *PushListener) park(c net.Conn, n, token, fp string) {
	pc := &parkedConn{c: c, net: n, claimed: fp, done: make(chan struct{})}
	now := time.Now()
	l.mu.Lock()
	b := l.boxes[token]
	same, unver := 0, 0
	ver := false
	if b != nil {
		ver = b.verifiedLocked(n, now)
		for _, o := range b.parked {
			if o.net == n {
				same++
			}
			if !b.verifiedLocked(o.net, now) {
				unver++
			}
		}
	}
	free := max(0, same-pushParkedPerNetToken+1) // so viele eigene werden gleich verdraengt
	if l.closed || b == nil || l.parkNet[n]-free >= pushParkedPerNet || l.parked-free >= pushParkedTotal ||
		(!ver && unver == 0 && len(b.parked) >= pushParkedPerToken) { // alle Plaetze bei bestaetigten Netzen
		delete(l.conns, c)
		l.mu.Unlock()
		_ = c.Close()
		return
	}
	var drop []*parkedConn
	evict := func(match func(*parkedConn) bool) bool {
		for _, o := range b.parked { // aelteste zuerst
			if match(o) {
				drop = append(drop, o)
				l.unparkLocked(o)
				return true
			}
		}
		return false
	}
	unverified := func(o *parkedConn) bool { return !b.verifiedLocked(o.net, now) }
	for same >= pushParkedPerNetToken && evict(func(o *parkedConn) bool { return o.net == n }) {
		same--
	}
	if !ver && countParked(b, unverified) >= pushParkedUnverified {
		evict(unverified)
	}
	if len(b.parked) >= pushParkedPerToken && !evict(unverified) {
		evict(func(*parkedConn) bool { return true }) // nur bestaetigte da, neue ist bestaetigt: aelteste
	}
	pc.box = b
	b.parked = append(b.parked, pc)
	l.parked++
	l.parkNet[n]++
	pc.expire = time.AfterFunc(l.parkMax, func() { l.expire(pc) })
	close(b.wake)
	b.wake = make(chan struct{})
	owners := make([]*conn, 0, len(b.owners))
	for o := range b.owners {
		owners = append(owners, o)
	}
	l.wg.Add(1)
	l.mu.Unlock()
	l.closeParked(drop)
	go func() {
		defer l.wg.Done()
		l.watch(pc)
	}()
	// Haengt beim Zugang noch eine (vielleicht tote) Verbindung, wird sie geprueft: die neue des Agents kommt meist,
	// weil die alte nicht mehr lebt (Neustart des Agents, neue NAT-Adresse). Nur bei angekuendigtem gemerktem
	// Schluessel (so meldet sich der echte Agent); probeStale prueft nur eine Verbindung ohne laufende Anfrage.
	for _, o := range owners {
		if hk := o.HostKey(); hk != "" && hk == fp {
			o.probeStale(pushProbeWait)
		}
	}
}

func countParked(b *pushBox, match func(*parkedConn) bool) int {
	n := 0
	for _, o := range b.parked {
		if match(o) {
			n++
		}
	}
	return n
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

// register meldet einen Client fuer token an (weitere Clients desselben Tokens bleiben angemeldet; wartende
// Verbindungen bleiben).
func (l *PushListener) register(token string, owner *conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.boxes[token]
	if b == nil {
		b = &pushBox{owners: map[*conn]struct{}{}, wake: make(chan struct{}), verified: map[string]time.Time{}, bad: map[string]*pushFail{}}
		l.boxes[token] = b
	}
	b.owners[owner] = struct{}{}
	if b.gone != nil {
		b.gone.Stop()
		b.gone = nil
	}
}

// unregister meldet nur diesen Client ab. Ist es der letzte, bleibt die Anmeldung samt wartender Verbindungen noch
// boxGrace (der Client wird oft gleich neu gebaut); danach schliesst dropBox sie.
func (l *PushListener) unregister(token string, owner *conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.boxes[token]
	if b == nil {
		return
	}
	if _, ok := b.owners[owner]; !ok {
		return
	}
	delete(b.owners, owner)
	if len(b.owners) > 0 || l.closed {
		return
	}
	if b.gone != nil {
		b.gone.Stop()
	}
	b.gone = time.AfterFunc(l.boxGrace, func() { l.dropBox(token, b) })
}

// dropBox entfernt die Anmeldung eines Tokens ohne Clients und schliesst ihre wartenden Verbindungen.
func (l *PushListener) dropBox(token string, b *pushBox) {
	l.mu.Lock()
	if l.boxes[token] != b || len(b.owners) > 0 || l.closed {
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

// pickLocked waehlt die wartende Verbindung fuer eine Anfrage. Mit gemerktem Schluessel: bevorzugt angekuendigter
// gemerkter Schluessel, dann bestaetigtes Netz, dann die neueste. Ohne (erster Kontakt, "neuen uebernehmen"): nur,
// wenn alle in Frage kommenden Verbindungen (die aus bestaetigten Netzen, sonst alle) denselben Fingerabdruck
// ankuendigen - sonst ErrPushAmbiguous.
func (b *pushBox) pickLocked(pinned string, now time.Time) (*parkedConn, error) {
	if len(b.parked) == 0 {
		return nil, nil
	}
	if pinned == "" {
		var cands []*parkedConn
		for _, o := range b.parked {
			if b.verifiedLocked(o.net, now) {
				cands = append(cands, o)
			}
		}
		if len(cands) == 0 {
			cands = b.parked
		}
		for _, o := range cands {
			if o.claimed != cands[0].claimed {
				return nil, ErrPushAmbiguous
			}
		}
		return cands[len(cands)-1], nil
	}
	var best *parkedConn
	bestScore := -1
	for _, o := range b.parked {
		s := 0
		if o.claimed == pinned {
			s += 2
		}
		if b.verifiedLocked(o.net, now) {
			s++
		}
		if s >= bestScore { // bei Gleichstand die neuere
			best, bestScore = o, s
		}
	}
	return best, nil
}

// take liefert eine wartende Verbindung fuer token (Auswahl pickLocked) und gibt dem Agent das Startzeichen.
// Wartet hoechstens bis until (ctx und life brechen ab); ohne Verbindung ErrNotConnected bzw. der letzte
// Handshake-Fehler des Zugangs (z. B. *HostKeyError, solange der Agent nach dem Fehlschlag noch wartet).
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
		pc, err := b.pickLocked(pinned, time.Now())
		if err != nil {
			l.mu.Unlock()
			return nil, err
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
			return nil, l.notConnected(token)
		}
		t := time.NewTimer(wait)
		select {
		case <-wake:
			t.Stop()
		case <-t.C:
			return nil, l.notConnected(token)
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

// notConnected: der letzte Handshake-Fehler des Zugangs (hoechstens pushLastErrKeep alt), sonst ErrNotConnected.
func (l *PushListener) notConnected(token string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.boxes[token]; b != nil && b.lastErr != nil && time.Since(b.lastAt) < pushLastErrKeep {
		return b.lastErr
	}
	return ErrNotConnected
}

// handshakeOK: Handshake ueber eine Verbindung aus Netz n gelungen (Netz fuer den Zugang bestaetigt).
func (l *PushListener) handshakeOK(token, n string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.boxes[token]
	if b == nil {
		return
	}
	if _, ok := b.verified[n]; !ok && len(b.verified) >= pushBoxNets {
		evictOldest(b.verified, pushBoxNets, func(t time.Time) time.Time { return t }, func(t time.Time) bool {
			return now.Sub(t) >= pushVerifiedForget
		})
	}
	b.verified[n] = now
	delete(b.bad, n)
	b.lastErr = nil
}

// handshakeFailed: Handshake ueber pc gescheitert. liar (gemerkter Schluessel angekuendigt, anderer gezeigt) sperrt
// das Netz fuer den Zugang sofort - ausser es ist fuer den Zugang bestaetigt (der echte Agent hinter derselben
// NAT-Adresse); wartende Verbindungen aus dem Netz bleiben (darunter kann die des echten Agents sein, ein Erfolg
// hebt die Sperre auf). Ein ehrlich angekuendigter anderer Schluessel (Agent neu installiert) sperrt nicht, sonst
// saehe man "Schluessel geaendert" nicht; andere Fehler zaehlen und sperren ab pushBadFree.
func (l *PushListener) handshakeFailed(token string, pc *parkedConn, err error, liar bool) {
	now := time.Now()
	l.mu.Lock()
	if b := l.boxes[token]; b != nil {
		b.lastErr, b.lastAt = err, now
		var hk *HostKeyError
		switch {
		case b.verifiedLocked(pc.net, now):
		case liar:
			countFail(b.bad, pc.net, now, 1, pushLiarBlock, pushBoxNets)
		case errors.As(err, &hk):
		default:
			countFail(b.bad, pc.net, now, pushBadFree, pushFailBlock, pushBoxNets)
		}
	}
	l.mu.Unlock()
	l.log.Warn("monitor64: push connection rejected", "remote", pc.c.RemoteAddr().String(), "err", CleanError(err).Error())
}
