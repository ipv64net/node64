package m64agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ipv64net/node64/internal/m64proto"
)

// testSigner liefert einen Client-Schluessel und seine authorized_keys-Zeile.
func testSigner(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

// startServer startet einen Agent auf 127.0.0.1 (prep darf Felder vor Serve setzen).
func startServer(t *testing.T, cfg Config, prep func(*Server)) (*Server, string) {
	t.Helper()
	hk, _ := testSigner(t)
	cfg.HostKey = hk
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if prep != nil {
		prep(s)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { _ = s.Close() })
	return s, ln.Addr().String()
}

func dialAgent(addr string, signer ssh.Signer, local net.Addr) (*ssh.Client, error) {
	d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: local}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	sc, chans, reqs, err := ssh.NewClientConn(c, addr, &ssh.ClientConfig{
		User:            "node64",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	})
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return ssh.NewClient(sc, chans, reqs), nil
}

func runAgent(c *ssh.Client, cmd string, stdin []byte) (string, error) {
	sess, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}
	out, err := sess.Output(cmd)
	return string(out), err
}

// waitClosed wartet, bis der Agent die Verbindung schliesst.
func waitClosed(t *testing.T, c *ssh.Client, d time.Duration, what string) {
	t.Helper()
	done := make(chan struct{})
	go func() { _ = c.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s: connection still open", what)
	}
}

// F1-K1: ein entfernter Schluessel darf auf offenen Verbindungen nichts mehr tun.
func TestKeyRevokedOnOpenConnections(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	sa, la := testSigner(t)
	sb, lb := testSigner(t)
	if err := WriteKeysFile(keys, []byte(la+"\n"+lb+"\n")); err != nil {
		t.Fatal(err)
	}
	s, addr := startServer(t, Config{KeysFile: keys}, func(s *Server) { s.revokeEvery = time.Hour })

	ca, err := dialAgent(addr, sa, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Close()
	cb, err := dialAgent(addr, sb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Close()
	if out, err := runAgent(cb, "info", nil); err != nil || !strings.Contains(out, `"agent":"monitor64-agent"`) {
		t.Fatalf("info: %q %v", out, err)
	}

	// 1. Jede neue Anfrage prueft den Schluessel erneut (auch ohne Durchlauf von revoke).
	if err := WriteKeysFile(keys, []byte(la+"\n")); err != nil {
		t.Fatal(err)
	}
	s.keys.invalidate()
	if _, err := runAgent(cb, "info", nil); err == nil {
		t.Fatal("removed key could still send a request")
	}
	waitClosed(t, cb, 3*time.Second, "per request check")
	if _, err := runAgent(ca, "info", nil); err != nil {
		t.Fatalf("remaining key refused: %v", err)
	}

	// 2. Anfrage "keys": Verbindungen mit entferntem Schluessel werden danach geschlossen (auch die anfragende).
	sc, lc := testSigner(t)
	if err := WriteKeysFile(keys, []byte(la+"\n"+lb+"\n")); err != nil {
		t.Fatal(err)
	}
	s.keys.invalidate()
	cb2, err := dialAgent(addr, sb, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cb2.Close()
	out, err := runAgent(ca, "keys", []byte(la+"\n"+lc+"\n"))
	if err != nil || !strings.Contains(out, `"ok":true`) {
		t.Fatalf("keys: %q %v", out, err)
	}
	waitClosed(t, cb2, 5*time.Second, "after keys")
	if _, err := dialAgent(addr, sb, nil); err == nil {
		t.Fatal("removed key could log in again")
	}
	cc, err := dialAgent(addr, sc, nil)
	if err != nil {
		t.Fatalf("new key refused: %v", err)
	}
	defer cc.Close()

	// 3. Datei von aussen geaendert: regelmaessige Pruefung schliesst die Verbindung.
	s2, addr2 := startServer(t, Config{KeysFile: keys}, func(s *Server) { s.revokeEvery = 50 * time.Millisecond })
	_ = s2
	cc2, err := dialAgent(addr2, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cc2.Close()
	if err := WriteKeysFile(keys, []byte(la+"\n")); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(3 * time.Second)
	_ = os.Chtimes(keys, future, future)
	waitClosed(t, cc2, 5*time.Second, "file changed")
}

// F1-K4: stille Verbindungen zaehlen als Fehlversuch, belegen nur die Plaetze ohne Anmeldung und sperren eine
// bereits angemeldete Node nicht aus.
func TestSilentConnections(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	sa, la := testSigner(t)
	if err := WriteKeysFile(keys, []byte(la+"\n")); err != nil {
		t.Fatal(err)
	}
	s, addr := startServer(t, Config{KeysFile: keys, HandshakeTimeout: 150 * time.Millisecond, MaxConns: 2}, nil)

	// stille Verbindungen von einer fremden Adresse: Zeitlimit = Fehlversuch, dann gesperrt
	silent := func(addr, local string) net.Conn {
		t.Helper()
		var la net.Addr
		if local != "" {
			la = &net.TCPAddr{IP: net.ParseIP(local)}
		}
		d := net.Dialer{LocalAddr: la, Timeout: 2 * time.Second}
		c, err := d.Dial("tcp", addr)
		if err != nil {
			t.Skipf("dial from %s: %v", local, err)
		}
		return c
	}
	for range failFree {
		c := silent(addr, "127.0.0.2")
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.Copy(io.Discard, c) // Agent schliesst nach dem Handshake-Zeitlimit
		_ = c.Close()
	}
	if !s.lim.blocked("127.0.0.2", time.Now()) {
		t.Fatal("silent connections were not counted as failures")
	}

	// Node meldet sich an (Adresse ist ab dann bekannt)
	_, addr = startServer(t, Config{KeysFile: keys, MaxConns: 2}, nil)
	ca, err := dialAgent(addr, sa, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = ca.Close()

	// Plaetze ohne Anmeldung von vielen Adressen fuellen
	var open []net.Conn
	defer func() {
		for _, c := range open {
			_ = c.Close()
		}
	}()
	for i := range preAuthMax {
		open = append(open, silent(addr, "127.0.1."+string(rune('1'+i))))
	}
	time.Sleep(100 * time.Millisecond)
	// fremde Adresse: kein Platz mehr
	if _, err := dialAgent(addr, sa, &net.TCPAddr{IP: net.ParseIP("127.0.2.1")}); err == nil {
		t.Fatal("unknown address got a slot beyond the pre-auth limit")
	}
	// bekannte Node: kommt trotzdem an
	ca, err = dialAgent(addr, sa, nil)
	if err != nil {
		t.Fatalf("known node locked out: %v", err)
	}
	if _, err := runAgent(ca, "info", nil); err != nil {
		t.Fatalf("info: %v", err)
	}
	_ = ca.Close()
}

func TestPreAuthGate(t *testing.T) {
	var g preAuthGate
	for range preAuthPerIP {
		if !g.acquire("a", false) {
			t.Fatal("per-IP slot refused too early")
		}
	}
	if g.acquire("a", false) || g.acquire("a", true) {
		t.Fatal("per-IP limit not applied")
	}
	for i := preAuthPerIP; i < preAuthMax; i++ {
		if !g.acquire(string(rune('b'+i)), false) {
			t.Fatal("global slot refused too early")
		}
	}
	if g.acquire("z", false) {
		t.Fatal("global limit not applied")
	}
	if !g.acquire("known", true) {
		t.Fatal("known address must bypass the global limit")
	}
	g.release("known")
	g.release("a")
	if !g.acquire("a", false) {
		t.Fatal("release did not free the slot")
	}
}

// F1-K4: volle Merkliste verdraengt alte Eintraege statt neue Fehlversuche zu ignorieren.
func TestLimiterEvicts(t *testing.T) {
	var l limiter
	now := time.Now()
	for i := range failFree {
		l.fail("blocked", now.Add(-time.Duration(failFree-i)*time.Second))
	}
	for i := range failMaxIPs - 1 {
		l.fail("k"+string(rune(i)), now.Add(-time.Minute+time.Duration(i)*time.Millisecond))
	}
	if len(l.m) != failMaxIPs {
		t.Fatalf("setup: %d entries", len(l.m))
	}
	for range failFree {
		l.fail("new", now)
	}
	if !l.blocked("new", now) {
		t.Fatal("failures of a new address not counted with a full list")
	}
	if !l.blocked("blocked", now) {
		t.Fatal("blocked address evicted before older unblocked ones")
	}
	if len(l.m) > failMaxIPs {
		t.Fatalf("list grew to %d", len(l.m))
	}
}

// slowCollector merkt die Frist des Kontexts.
type slowCollector struct{ deadline time.Duration }

func (c *slowCollector) Collect(ctx context.Context, _ []string) *m64proto.Report {
	if d, ok := ctx.Deadline(); ok {
		c.deadline = time.Until(d)
	}
	return &m64proto.Report{}
}

// F1-K3: collect bekommt eine Frist unter dem Zeitlimit der Node, auch wenn mehr eingestellt ist.
func TestCollectDeadline(t *testing.T) {
	hk, _ := testSigner(t)
	col := &slowCollector{}
	s, err := New(Config{HostKey: hk, KeysFile: "x", Collector: col, CollectTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Collect(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if col.deadline <= 0 || col.deadline > maxCollect || maxCollect > 20*time.Second {
		t.Fatalf("collector deadline %v (max %v)", col.deadline, maxCollect)
	}
	s2, _ := New(Config{HostKey: hk, KeysFile: "x"})
	if s2.cfg.CollectTimeout != defaultCollect || defaultCollect > maxCollect {
		t.Fatalf("default collect timeout %v", s2.cfg.CollectTimeout)
	}
}
