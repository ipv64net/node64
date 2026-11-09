// Package transport verbindet die Node mit Monitor64-Agents und mit Hosts ohne Agent (SSH). Beides laeuft ueber
// golang.org/x/crypto/ssh mit dem Schluessel der Node; der Hostschluessel wird beim ersten Kontakt gemerkt (TOFU)
// und danach fest geprueft. Verbindungen bleiben offen (eine je Host, je Anfrage ein neuer Kanal) und werden nach
// Leerlauf oder Fehler geschlossen bzw. neu aufgebaut (Plan docs/PLAN-NODE64-MONITOR64.md, "Gemeinsam fuer alle
// Zugaenge" und "Sicherheit").
//
// Alles, was ein Host liefert, ist nicht vertrauenswuerdig: Antworten werden auf m64proto.Max* begrenzt, Fehlertexte
// gekuerzt und von Steuerzeichen befreit.
package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// Standardwerte.
const (
	DefaultDialTimeout = 10 * time.Second
	DefaultIdleTimeout = 5 * time.Minute
	maxSessionsPerConn = 4 // wie der Agent (mehr Kanaele lehnt er ab)
	maxStderrBytes     = 4 << 10
	maxErrorText       = 300 // Fehlertexte vom Host (Disconnect, Algorithmen, stderr) hoechstens so lang
)

// Erlaubte Verfahren: nur Hostschluessel ohne Zertifikat (der Fingerabdruck bleibt bei erneuertem Zertifikat
// gleich), kein ssh-rsa mit SHA-1, kein DSA; Schluesseltausch, Verschluesselung und MAC ohne SHA-1/CBC.
var (
	hostKeyAlgos = []string{
		ssh.KeyAlgoED25519,
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
	}
	kexAlgos = []string{
		ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519,
		ssh.KeyExchangeECDHP256, ssh.KeyExchangeECDHP384, ssh.KeyExchangeECDHP521,
		ssh.KeyExchangeDH16SHA512, ssh.KeyExchangeDH14SHA256,
	}
	cipherAlgos = []string{
		ssh.CipherChaCha20Poly1305, ssh.CipherAES256GCM, ssh.CipherAES128GCM,
		ssh.CipherAES256CTR, ssh.CipherAES192CTR, ssh.CipherAES128CTR,
	}
	macAlgos = []string{ssh.HMACSHA256ETM, ssh.HMACSHA512ETM, ssh.HMACSHA256, ssh.HMACSHA512}
)

var (
	// ErrHostKeyChanged: der Hostschluessel weicht vom gemerkten ab (errors.Is; Details in *HostKeyError).
	ErrHostKeyChanged = errors.New("monitor64: host key changed")
	// ErrTooLarge: die Antwort ist groesser als erlaubt.
	ErrTooLarge = errors.New("monitor64: answer too large")
	// ErrClosed: der Client wurde geschlossen.
	ErrClosed = errors.New("monitor64: client closed")
	// ErrTimeout: keine vollstaendige Antwort innerhalb des Zeitlimits (errors.Is; trifft auch auf
	// context.DeadlineExceeded zu).
	ErrTimeout = errors.New("monitor64: timeout")
)

// HostKeyError meldet einen geaenderten Hostschluessel. Es wird nie nachgefragt; die Oberflaeche bietet
// "neuen uebernehmen" mit Got an.
type HostKeyError struct {
	Want    string // gemerkter Fingerabdruck
	Got     string // angebotener Fingerabdruck
	GotType string // Art des angebotenen Schluessels (ssh-ed25519, ecdsa-sha2-nistp256, ssh-rsa)
}

func (e *HostKeyError) Error() string {
	return fmt.Sprintf("monitor64: host key changed (expected %s, got %s)", e.Want, e.Got)
}

// Is macht errors.Is(err, ErrHostKeyChanged) moeglich.
func (e *HostKeyError) Is(target error) bool { return target == ErrHostKeyChanged }

// RemoteError: der Befehl auf dem Host endete mit einem Fehler.
type RemoteError struct {
	Status int
	Stderr string // gekuerzt, ohne Steuerzeichen
}

func (e *RemoteError) Error() string {
	if e.Stderr == "" {
		return fmt.Sprintf("monitor64: remote exit status %d", e.Status)
	}
	return fmt.Sprintf("monitor64: remote exit status %d: %s", e.Status, e.Stderr)
}

// TimeoutError: das Zeitlimit einer Anfrage ist abgelaufen (errors.Is ErrTimeout und context.DeadlineExceeded).
type TimeoutError struct {
	Limit time.Duration // Zeitlimit der Anfrage (0 = unbekannt)
}

func (e *TimeoutError) Error() string {
	if e.Limit <= 0 {
		return "monitor64: timeout (no answer)"
	}
	return fmt.Sprintf("monitor64: timeout (no answer within %s)", e.Limit.Round(100*time.Millisecond))
}

// Is macht errors.Is(err, ErrTimeout) und errors.Is(err, context.DeadlineExceeded) moeglich.
func (e *TimeoutError) Is(target error) bool {
	return target == ErrTimeout || target == context.DeadlineExceeded
}

// connConfig beschreibt eine Verbindung (gemeinsam fuer Agent und SSH ohne Agent).
type connConfig struct {
	addr        string
	user        string
	auth        []ssh.AuthMethod
	hostKey     string
	onHostKey   func(fingerprint string)
	dialTimeout time.Duration
	idleTimeout time.Duration
	// multiKey: der Host kann mehrere Schluesselarten haben (normaler sshd); bei abweichendem Schluessel die
	// uebrigen Arten versuchen. Der Agent hat genau einen ed25519-Schluessel (keine Wiederholung, sie zaehlt dort
	// als Fehlversuch).
	multiKey bool
}

// conn haelt eine SSH-Verbindung offen und baut sie bei Bedarf neu auf. Der Aufbau laeuft ohne c.mu (eigene
// Sperre dialing), damit Close, HostKey und andere Anfragen nicht hinter einem haengenden Host warten.
type conn struct {
	cfg        connConfig
	sess       chan struct{} // Obergrenze gleichzeitiger Kanaele
	dialing    chan struct{} // ein Verbindungsaufbau zur Zeit
	life       context.Context
	lifeCancel context.CancelFunc // Close bricht einen laufenden Aufbau ab

	mu      sync.Mutex
	client  *ssh.Client
	fp      string // gemerkter Fingerabdruck (bekannt oder beim ersten Kontakt uebernommen)
	hkTried string // fuer diesen gemerkten Fingerabdruck schon alle Schluesselarten versucht
	active  int
	lastUse time.Time
	idle    *time.Timer
	closed  bool
}

func newConn(cfg connConfig) *conn {
	if cfg.dialTimeout <= 0 {
		cfg.dialTimeout = DefaultDialTimeout
	}
	if cfg.idleTimeout <= 0 {
		cfg.idleTimeout = DefaultIdleTimeout
	}
	life, cancel := context.WithCancel(context.Background())
	return &conn{cfg: cfg, fp: NormalizeFingerprint(cfg.hostKey), sess: make(chan struct{}, maxSessionsPerConn),
		dialing: make(chan struct{}, 1), life: life, lifeCancel: cancel, lastUse: time.Now()}
}

// HostKey liefert den gemerkten Fingerabdruck ("" bis zum ersten Kontakt bei TOFU).
func (c *conn) HostKey() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fp
}

// usage: laufende Anfragen und Zeitpunkt der letzten Nutzung (fuer das Aufraeumen im Pool).
func (c *conn) usage() (active int, last time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active, c.lastUse
}

// Close schliesst die Verbindung; spaetere Anfragen liefern ErrClosed. Wartet nicht auf einen laufenden Aufbau.
func (c *conn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.lifeCancel()
	if c.idle != nil {
		c.idle.Stop()
	}
	cl := c.client
	c.client = nil
	c.mu.Unlock()
	if cl != nil {
		_ = cl.Close()
	}
	return nil
}

// take liefert die offene Verbindung (ok = true) oder ErrClosed; ok = false: Verbindung aufbauen.
func (c *conn) take() (cl *ssh.Client, ok bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, true, ErrClosed
	}
	if c.client == nil {
		return nil, false, nil
	}
	c.active++
	c.lastUse = time.Now()
	if c.idle != nil {
		c.idle.Stop()
	}
	return c.client, true, nil
}

// get liefert die offene Verbindung oder baut sie auf.
func (c *conn) get(ctx context.Context) (*ssh.Client, error) {
	if cl, ok, err := c.take(); ok {
		return cl, err
	}
	select {
	case c.dialing <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.life.Done():
		return nil, ErrClosed
	}
	defer func() { <-c.dialing }()
	if cl, ok, err := c.take(); ok { // inzwischen von einer anderen Anfrage aufgebaut
		return cl, err
	}
	cl, learned, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = cl.Close()
		return nil, ErrClosed
	}
	c.client = cl
	c.active++
	c.lastUse = time.Now()
	if c.idle != nil {
		c.idle.Stop()
	}
	c.mu.Unlock()
	go func() {
		_ = cl.Wait()
		c.mu.Lock()
		if c.client == cl {
			c.client = nil
		}
		c.mu.Unlock()
	}()
	if learned != "" && c.cfg.onHostKey != nil {
		c.cfg.onHostKey(learned)
	}
	return cl, nil
}

// release gibt die Verbindung nach einer Anfrage frei; broken schliesst sie (naechste Anfrage baut neu auf).
func (c *conn) release(cl *ssh.Client, broken bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active--
	c.lastUse = time.Now()
	if broken {
		_ = cl.Close()
		if c.client == cl {
			c.client = nil
		}
	}
	if c.active == 0 && c.client != nil && !c.closed {
		if c.idle == nil {
			c.idle = time.AfterFunc(c.cfg.idleTimeout, c.closeIdle)
		} else {
			c.idle.Reset(c.cfg.idleTimeout)
		}
	}
}

func (c *conn) closeIdle() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active == 0 && c.client != nil && time.Since(c.lastUse) >= c.cfg.idleTimeout-time.Second {
		_ = c.client.Close()
		c.client = nil
	}
}

// dial baut die Verbindung auf (ohne c.mu, unter c.dialing) und prueft den Hostschluessel. learned ist der beim
// ersten Kontakt uebernommene Fingerabdruck (TOFU), sonst "".
func (c *conn) dial(ctx context.Context) (cl *ssh.Client, learned string, err error) {
	cl, learned, err = c.dialOnce(ctx, hostKeyAlgos)
	var hk *HostKeyError
	if err == nil || !errors.As(err, &hk) || !c.cfg.multiKey {
		return cl, learned, err
	}
	// Der Host zeigt je nach Algorithmus einen anderen Schluessel (ed25519, ecdsa, rsa). Gemerkt ist der vom ersten
	// Kontakt: die uebrigen Schluesselarten je einmal versuchen; "geaendert" nur, wenn keine zum gemerkten passt.
	// Nach einem erfolglosen Durchgang nicht jede Runde erneut (der Agent zaehlt abgebrochene Handshakes).
	c.mu.Lock()
	tried := c.hkTried == hk.Want
	c.hkTried = hk.Want
	c.mu.Unlock()
	if tried {
		return nil, "", err
	}
	for _, fam := range hostKeyFamilies {
		if fam.typ == hk.GotType || ctx.Err() != nil || c.life.Err() != nil {
			continue
		}
		if cl2, l2, err2 := c.dialOnce(ctx, fam.algos); err2 == nil {
			c.mu.Lock()
			c.hkTried = ""
			c.mu.Unlock()
			return cl2, l2, nil
		}
	}
	return nil, "", err
}

// hostKeyFamilies: je Schluesselart die erlaubten Algorithmen (fuer den Abgleich mit dem gemerkten Schluessel).
var hostKeyFamilies = []struct {
	typ   string
	algos []string
}{
	{ssh.KeyAlgoED25519, []string{ssh.KeyAlgoED25519}},
	{ssh.KeyAlgoECDSA256, []string{ssh.KeyAlgoECDSA256}},
	{ssh.KeyAlgoECDSA384, []string{ssh.KeyAlgoECDSA384}},
	{ssh.KeyAlgoECDSA521, []string{ssh.KeyAlgoECDSA521}},
	{ssh.KeyAlgoRSA, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}},
}

// dialOnce baut eine Verbindung mit den angegebenen Hostschluessel-Algorithmen auf.
func (c *conn) dialOnce(ctx context.Context, algos []string) (cl *ssh.Client, learned string, err error) {
	deadline := time.Now().Add(c.cfg.dialTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	dctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stopLife := context.AfterFunc(c.life, cancel) // Close bricht den Aufbau ab
	defer stopLife()
	d := net.Dialer{KeepAlive: 30 * time.Second}
	nc, err := d.DialContext(dctx, "tcp", c.cfg.addr)
	if err != nil {
		if c.life.Err() != nil {
			return nil, "", ErrClosed
		}
		return nil, "", err
	}
	_ = nc.SetDeadline(deadline)
	stop := context.AfterFunc(dctx, func() { _ = nc.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	want := c.HostKey()
	var seen string
	var hkErr error
	cfg := &ssh.ClientConfig{
		Config: ssh.Config{KeyExchanges: kexAlgos, Ciphers: cipherAlgos, MACs: macAlgos},
		User:   c.cfg.user,
		Auth:   c.cfg.auth,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = Fingerprint(key)
			if want != "" && seen != want {
				hkErr = &HostKeyError{Want: want, Got: seen, GotType: key.Type()}
				return hkErr
			}
			return nil
		},
		HostKeyAlgorithms: algos,
		ClientVersion:     "SSH-2.0-node64-monitor64",
		Timeout:           c.cfg.dialTimeout,
	}
	sc, chans, reqs, err := ssh.NewClientConn(nc, c.cfg.addr, cfg)
	if err != nil {
		_ = nc.Close()
		switch {
		case hkErr != nil:
			return nil, "", hkErr
		case c.life.Err() != nil:
			return nil, "", ErrClosed
		case dctx.Err() != nil && ctx.Err() != nil:
			return nil, "", ctx.Err()
		case dctx.Err() != nil:
			return nil, "", fmt.Errorf("monitor64: connect: no SSH handshake within %s", c.cfg.dialTimeout)
		}
		return nil, "", err
	}
	if !stop() {
		_ = sc.Close()
		if c.life.Err() != nil {
			return nil, "", ErrClosed
		}
		return nil, "", dctx.Err()
	}
	_ = nc.SetDeadline(time.Time{})
	c.mu.Lock()
	if c.fp == "" {
		c.fp = seen
		learned = seen
	}
	c.mu.Unlock()
	return ssh.NewClient(sc, chans, reqs), learned, nil
}

// exec fuehrt cmd in einem neuen Kanal aus, schickt stdin (falls gesetzt) und liest hoechstens limit Byte.
// Bei *RemoteError wird die Ausgabe trotzdem geliefert (Agent: JSON mit Fehlertext). Fehler sind gekuerzt und
// bereinigt; ein abgelaufenes Zeitlimit ergibt *TimeoutError.
func (c *conn) exec(ctx context.Context, cmd string, stdin io.Reader, limit int) ([]byte, error) {
	start := time.Now()
	out, err := c.execRaw(ctx, cmd, stdin, limit)
	if err == nil {
		return out, nil
	}
	return out, finishErr(ctx, start, err)
}

// finishErr macht aus einem Fehler den Fehler fuer den Aufrufer: Hostschluessel bleibt, Zeitlimit wird
// *TimeoutError, alles andere gekuerzt und bereinigt (Texte vom Host).
func finishErr(ctx context.Context, start time.Time, err error) error {
	var hk *HostKeyError
	if errors.As(err, &hk) {
		return err
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		te := &TimeoutError{}
		if d, ok := ctx.Deadline(); ok {
			te.Limit = d.Sub(start)
		}
		return te
	}
	return CleanError(err)
}

func (c *conn) execRaw(ctx context.Context, cmd string, stdin io.Reader, limit int) ([]byte, error) {
	select {
	case c.sess <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.life.Done():
		return nil, ErrClosed
	}
	defer func() { <-c.sess }()

	for attempt := 0; ; attempt++ {
		cl, err := c.get(ctx)
		if err != nil {
			return nil, err
		}
		// Laeuft das Zeitlimit ab, wird die ganze Verbindung geschlossen: ein toter Host bei offener Verbindung
		// beantwortet weder das Oeffnen eines Kanals noch dessen Schliessen (sonst haengt die Anfrage bis zum
		// TCP-Abbruch). Andere Anfragen auf derselben Verbindung scheitern dann mit.
		stopAbort := context.AfterFunc(ctx, func() { _ = cl.Close() })
		sess, err := cl.NewSession()
		if err != nil {
			stopAbort()
			var oce *ssh.OpenChannelError
			if errors.As(err, &oce) {
				c.release(cl, false)
				return nil, fmt.Errorf("monitor64: channel refused: %s", cleanRemote(oce.Message))
			}
			c.release(cl, true)
			if attempt > 0 || ctx.Err() != nil {
				return nil, err
			}
			continue
		}
		out, broken, err := runSession(ctx, sess, cmd, stdin, limit)
		if !stopAbort() {
			broken = true // Verbindung wurde wegen des Zeitlimits geschlossen
		}
		c.release(cl, broken)
		return out, err
	}
}

// runSession: broken=true, wenn die Verbindung danach nicht mehr verlaesslich ist (Zeitlimit, Transportfehler).
// Abbruch per ctx erledigt exec (schliesst die Verbindung, dann kehren alle Lese- und Schreibvorgaenge zurueck).
func runSession(ctx context.Context, sess *ssh.Session, cmd string, stdin io.Reader, limit int) (out []byte, broken bool, err error) {
	defer sess.Close()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return nil, true, err
	}
	errBuf := &capBuf{max: maxStderrBytes}
	sess.Stderr = errBuf
	var in io.WriteCloser
	if stdin != nil {
		if in, err = sess.StdinPipe(); err != nil {
			return nil, true, err
		}
	}
	if err := sess.Start(cmd); err != nil {
		if ctx.Err() != nil {
			return nil, true, ctx.Err()
		}
		return nil, false, fmt.Errorf("monitor64: request refused by host: %w", err)
	}
	var inDone chan struct{}
	if in != nil {
		inDone = make(chan struct{})
		go func() {
			defer close(inDone)
			_, _ = io.Copy(in, stdin) // Fehler zaehlen nicht: die Antwort des Hosts entscheidet
			_ = in.Close()
		}()
	}
	out, rerr := io.ReadAll(io.LimitReader(stdout, int64(limit)+1))
	if rerr == nil && len(out) > limit {
		_ = sess.Close()
		if inDone != nil {
			<-inDone // haengt der Host, schliesst exec beim Zeitlimit die Verbindung
		}
		return nil, false, fmt.Errorf("%w (limit %d bytes)", ErrTooLarge, limit)
	}
	werr := sess.Wait()
	_ = sess.Close()
	if inDone != nil {
		<-inDone
	}
	if ctx.Err() != nil {
		return nil, true, ctx.Err()
	}
	if rerr != nil {
		return nil, true, rerr
	}
	var ee *ssh.ExitError
	switch {
	case werr == nil:
		return out, false, nil
	case errors.As(werr, &ee):
		return out, false, &RemoteError{Status: ee.ExitStatus(), Stderr: cleanRemote(errBuf.String())}
	default:
		return nil, true, werr
	}
}

// capBuf nimmt hoechstens max Byte auf.
type capBuf struct {
	mu  sync.Mutex
	b   bytes.Buffer
	max int
}

func (b *capBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.max - b.b.Len(); room > 0 {
		b.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (b *capBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// cleanRemote kuerzt Texte vom Host (hoechstens maxErrorText Byte) und ersetzt nicht druckbare Zeichen
// (Steuerzeichen, Richtungswechsel, ungueltiges UTF-8) durch Leerzeichen (fuer Fehlermeldungen und Log).
func cleanRemote(s string) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if r != ' ' && !unicode.IsPrint(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > maxErrorText {
		s = strings.ToValidUTF8(s[:maxErrorText], "") + "..."
	}
	return s
}

// cleanedError ist ein gekuerzter, bereinigter Fehlertext; errors.Is/As sehen den urspruenglichen Fehler.
type cleanedError struct {
	msg string
	err error
}

func (e *cleanedError) Error() string { return e.msg }
func (e *cleanedError) Unwrap() error { return e.err }

// CleanError kuerzt und bereinigt den Text eines Fehlers, der Teile vom Host enthalten kann (Disconnect-Grund,
// Algorithmenliste, Banner ...), bevor er in Ereignisse, Meldungen oder die Oberflaeche geht.
func CleanError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if c := cleanRemote(msg); c != msg {
		return &cleanedError{msg: c, err: err}
	}
	return err
}

// withDefaultTimeout setzt ein Zeitlimit, wenn der Aufrufer keines vorgibt.
func withDefaultTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, d)
}

// HostPort ergaenzt den Port, wenn addr keinen enthaelt: "nas" -> "nas:22", "nas:2222" bleibt, "2001:db8::1" und
// "[2001:db8::1]" -> "[2001:db8::1]:22", "[2001:db8::1]:2222" bleibt.
func HostPort(addr string, port int) string {
	addr = strings.TrimSpace(addr)
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]"), strconv.Itoa(port))
}

// SplitHost liefert den Host ohne Port ("nas:2222" -> "nas", "[2001:db8::1]:22" -> "2001:db8::1").
func SplitHost(addr string) string {
	addr = strings.TrimSpace(addr)
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
}
