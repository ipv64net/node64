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
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Standardwerte.
const (
	DefaultDialTimeout = 10 * time.Second
	DefaultIdleTimeout = 5 * time.Minute
	maxSessionsPerConn = 4 // wie der Agent (mehr Kanaele lehnt er ab)
	maxStderrBytes     = 4 << 10
)

var (
	// ErrHostKeyChanged: der Hostschluessel weicht vom gemerkten ab (errors.Is; Details in *HostKeyError).
	ErrHostKeyChanged = errors.New("monitor64: host key changed")
	// ErrTooLarge: die Antwort ist groesser als erlaubt.
	ErrTooLarge = errors.New("monitor64: answer too large")
	// ErrClosed: der Client wurde geschlossen.
	ErrClosed = errors.New("monitor64: client closed")
)

// HostKeyError meldet einen geaenderten Hostschluessel. Es wird nie nachgefragt; die Oberflaeche bietet
// "neuen uebernehmen" mit Got an.
type HostKeyError struct {
	Want string // gemerkter Fingerabdruck
	Got  string // angebotener Fingerabdruck
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

// connConfig beschreibt eine Verbindung (gemeinsam fuer Agent und SSH ohne Agent).
type connConfig struct {
	addr        string
	user        string
	auth        []ssh.AuthMethod
	hostKey     string
	onHostKey   func(fingerprint string)
	dialTimeout time.Duration
	idleTimeout time.Duration
}

// conn haelt eine SSH-Verbindung offen und baut sie bei Bedarf neu auf.
type conn struct {
	cfg  connConfig
	sess chan struct{} // Obergrenze gleichzeitiger Kanaele

	mu      sync.Mutex
	client  *ssh.Client
	fp      string // gemerkter Fingerabdruck (bekannt oder beim ersten Kontakt uebernommen)
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
	return &conn{cfg: cfg, fp: NormalizeFingerprint(cfg.hostKey), sess: make(chan struct{}, maxSessionsPerConn)}
}

// HostKey liefert den gemerkten Fingerabdruck ("" bis zum ersten Kontakt bei TOFU).
func (c *conn) HostKey() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fp
}

// Close schliesst die Verbindung; spaetere Anfragen liefern ErrClosed.
func (c *conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.idle != nil {
		c.idle.Stop()
	}
	if c.client != nil {
		_ = c.client.Close()
		c.client = nil
	}
	return nil
}

// get liefert die offene Verbindung oder baut sie auf.
func (c *conn) get(ctx context.Context) (*ssh.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrClosed
	}
	if c.client == nil {
		cl, err := c.dial(ctx)
		if err != nil {
			return nil, err
		}
		c.client = cl
		go func() {
			_ = cl.Wait()
			c.mu.Lock()
			if c.client == cl {
				c.client = nil
			}
			c.mu.Unlock()
		}()
	}
	c.active++
	if c.idle != nil {
		c.idle.Stop()
	}
	return c.client, nil
}

// release gibt die Verbindung nach einer Anfrage frei; broken schliesst sie (naechste Anfrage baut neu auf).
func (c *conn) release(cl *ssh.Client, broken bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active--
	c.lastUse = time.Now()
	if broken && c.client == cl {
		_ = cl.Close()
		c.client = nil
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

// dial baut die Verbindung auf (unter c.mu) und prueft den Hostschluessel (TOFU).
func (c *conn) dial(ctx context.Context) (*ssh.Client, error) {
	deadline := time.Now().Add(c.cfg.dialTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	dctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	d := net.Dialer{KeepAlive: 30 * time.Second}
	nc, err := d.DialContext(dctx, "tcp", c.cfg.addr)
	if err != nil {
		return nil, err
	}
	_ = nc.SetDeadline(deadline)
	stop := context.AfterFunc(dctx, func() { _ = nc.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	var seen string
	var hkErr error
	cfg := &ssh.ClientConfig{
		User: c.cfg.user,
		Auth: c.cfg.auth,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = Fingerprint(key)
			if c.fp != "" && seen != c.fp {
				hkErr = &HostKeyError{Want: c.fp, Got: seen}
				return hkErr
			}
			return nil
		},
		ClientVersion: "SSH-2.0-node64-monitor64",
		Timeout:       c.cfg.dialTimeout,
	}
	sc, chans, reqs, err := ssh.NewClientConn(nc, c.cfg.addr, cfg)
	if err != nil {
		_ = nc.Close()
		if hkErr != nil {
			return nil, hkErr
		}
		if dctx.Err() != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if !stop() {
		_ = sc.Close()
		return nil, dctx.Err()
	}
	_ = nc.SetDeadline(time.Time{})
	if c.fp == "" {
		c.fp = seen
		if c.cfg.onHostKey != nil {
			c.cfg.onHostKey(seen)
		}
	}
	return ssh.NewClient(sc, chans, reqs), nil
}

// exec fuehrt cmd in einem neuen Kanal aus, schickt stdin (falls gesetzt) und liest hoechstens limit Byte.
// Bei *RemoteError wird die Ausgabe trotzdem geliefert (Agent: JSON mit Fehlertext).
func (c *conn) exec(ctx context.Context, cmd string, stdin io.Reader, limit int) ([]byte, error) {
	select {
	case c.sess <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-c.sess }()

	cl, sess, err := c.open(ctx)
	if err != nil {
		return nil, err
	}
	out, broken, err := runSession(ctx, sess, cmd, stdin, limit)
	c.release(cl, broken)
	return out, err
}

// open baut einen Kanal auf; ist die offene Verbindung tot, wird einmal neu verbunden.
func (c *conn) open(ctx context.Context) (*ssh.Client, *ssh.Session, error) {
	for attempt := 0; ; attempt++ {
		cl, err := c.get(ctx)
		if err != nil {
			return nil, nil, err
		}
		sess, err := cl.NewSession()
		if err == nil {
			return cl, sess, nil
		}
		var oce *ssh.OpenChannelError
		if errors.As(err, &oce) {
			c.release(cl, false)
			return nil, nil, fmt.Errorf("monitor64: channel refused: %s", cleanRemote(oce.Message))
		}
		c.release(cl, true)
		if attempt > 0 || ctx.Err() != nil {
			return nil, nil, err
		}
	}
}

// runSession: broken=true, wenn die Verbindung danach nicht mehr verlaesslich ist (Zeitlimit, Transportfehler).
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
	stopCtx := context.AfterFunc(ctx, func() { _ = sess.Close() })
	defer stopCtx()
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
			<-inDone
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

// cleanRemote kuerzt Texte vom Host und entfernt Steuerzeichen (fuer Fehlermeldungen und Log).
func cleanRemote(s string) string {
	s = strings.ToValidUTF8(strings.TrimSpace(s), "?")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 300 {
		s = s[:300]
		s = strings.ToValidUTF8(s, "") + "..."
	}
	return s
}

// withDefaultTimeout setzt ein Zeitlimit, wenn der Aufrufer keines vorgibt.
func withDefaultTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, d)
}

// hostPort ergaenzt den Standard-Port.
func hostPort(addr string, port int) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(strings.Trim(addr, "[]"), fmt.Sprint(port))
}
