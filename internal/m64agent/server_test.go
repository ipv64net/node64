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
	"strconv"
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

// closer merkt, ob die Verbindung geschlossen wurde.
type closer struct{ closed bool }

func (c *closer) Close() error { c.closed = true; return nil }

func testPeer(s string) peer { return peerOf(&net.TCPAddr{IP: net.ParseIP(s), Port: 1}) }

func TestPreAuthGate(t *testing.T) {
	var g preAuthGate
	now := time.Now()
	a := testPeer("192.0.2.1")
	var held []*preAuthSlot
	for range preAuthPerNet {
		sl := g.acquire(a, false, nil, now)
		if sl == nil {
			t.Fatal("per-net slot refused too early")
		}
		held = append(held, sl)
	}
	if g.acquire(a, false, nil, now) != nil {
		t.Fatal("per-net limit not applied")
	}
	for i := preAuthPerNet; i < preAuthMax; i++ {
		if g.acquire(testPeer("198.51.100."+strconv.Itoa(i)), false, nil, now) == nil {
			t.Fatal("global slot refused too early")
		}
	}
	if g.acquire(testPeer("203.0.113.1"), false, nil, now) != nil {
		t.Fatal("global limit not applied")
	}
	k := g.acquire(testPeer("203.0.113.9"), true, nil, now)
	if k == nil {
		t.Fatal("known address must bypass the global limit")
	}
	g.release(k)
	g.release(held[0])
	g.release(held[0]) // doppelt freigeben zaehlt nicht doppelt
	if g.acquire(a, false, nil, now) == nil {
		t.Fatal("release did not free the slot")
	}
	if g.acquire(a, false, nil, now) != nil || g.total != preAuthMax {
		t.Fatalf("double release freed two slots (total %d)", g.total)
	}
}

// S1-K1: bekannte Adresse (NAT, Nachbar im /64) hat einen eigenen, groesseren Topf; ist er voll, wird ein Platz
// geraeumt, dessen Handshake schon zu lange laeuft - frische Plaetze nicht.
func TestPreAuthGateKnown(t *testing.T) {
	g := preAuthGate{evictAge: time.Second}
	now := time.Now()
	node := testPeer("2001:db8:1:2::1")
	// Nachbar im selben /64 fuellt den Topf fuer unbekannte Adressen
	for i := range preAuthPerNet {
		if g.acquire(testPeer("2001:db8:1:2::"+strconv.Itoa(100+i)), false, nil, now) == nil {
			t.Fatal("setup")
		}
	}
	if g.acquire(testPeer("2001:db8:1:2::200"), false, nil, now) != nil {
		t.Fatal("per-/64 limit not applied")
	}
	// die bekannte Adresse kommt trotzdem an, mehr als preAuthPerNet Mal
	var cs []*closer
	for range preAuthPerKnown {
		c := &closer{}
		if g.acquire(node, true, c, now) == nil {
			t.Fatal("known address refused although its pot has room")
		}
		cs = append(cs, c)
	}
	// Topf voll, alle Plaetze frisch: abgewiesen, nichts geschlossen
	if g.acquire(node, true, &closer{}, now.Add(500*time.Millisecond)) != nil || cs[0].closed {
		t.Fatal("fresh slot evicted")
	}
	// aeltester Platz laeuft zu lange: wird geraeumt (Verbindung zu), neuer Platz frei
	sl := g.acquire(node, true, &closer{}, now.Add(1500*time.Millisecond))
	if sl == nil || !cs[0].closed || cs[1].closed {
		t.Fatalf("eviction: slot %v closed %v/%v", sl != nil, cs[0].closed, cs[1].closed)
	}
	if len(g.known[node.ip]) != preAuthPerKnown || g.knownTotal != preAuthPerKnown {
		t.Fatalf("known pot: %d/%d", len(g.known[node.ip]), g.knownTotal)
	}
	g.release(sl)
	if g.knownTotal != preAuthPerKnown-1 {
		t.Fatalf("release: %d", g.knownTotal)
	}
}

// S1-K2: viele /64 aus einem /48 belegen nicht alle Plaetze.
func TestPreAuthGateGroup(t *testing.T) {
	var g preAuthGate
	now := time.Now()
	n := 0
	for i := range 10 {
		if g.acquire(testPeer("2001:db8:1:"+strconv.Itoa(i)+"::1"), false, nil, now) != nil {
			n++
		}
	}
	if n != preAuthPerGroup {
		t.Fatalf("one /48 got %d slots, want %d", n, preAuthPerGroup)
	}
	if g.acquire(testPeer("2001:db8:2::1"), false, nil, now) == nil {
		t.Fatal("other /48 refused")
	}
}

// S1-K1: eine Node hinter derselben Adresse wie stille Verbindungen eines Nachbarn kommt an (deren Plaetze werden
// geraeumt), stille Verbindungen einer bekannten Adresse zaehlen nicht als Fehlversuch.
func TestKnownAddressNotLockedOut(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	sa, la := testSigner(t)
	if err := WriteKeysFile(keys, []byte(la+"\n")); err != nil {
		t.Fatal(err)
	}
	s, addr := startServer(t, Config{KeysFile: keys, HandshakeTimeout: 5 * time.Second},
		func(s *Server) { s.gate.evictAge = 200 * time.Millisecond })
	ca, err := dialAgent(addr, sa, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = ca.Close()
	// Nachbar hinter derselben Adresse belegt alle Plaetze der bekannten Adresse mit stillen Verbindungen
	var open []net.Conn
	defer func() {
		for _, c := range open {
			_ = c.Close()
		}
	}()
	for range preAuthPerKnown {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, c)
	}
	time.Sleep(400 * time.Millisecond)
	ca, err = dialAgent(addr, sa, nil)
	if err != nil {
		t.Fatalf("known node locked out by silent connections from its address: %v", err)
	}
	if _, err := runAgent(ca, "info", nil); err != nil {
		t.Fatalf("info: %v", err)
	}
	_ = ca.Close()
	if s.lim.blocked("127.0.0.1", time.Now()) {
		t.Fatal("known address blocked")
	}
}

// S1-K2: Abweisungen wegen voller Plaetze zaehlen nicht als Fehlversuch - eine neue Node wird nicht gesperrt,
// waehrend Angreifer die Plaetze belegen, und kommt an, sobald einer frei ist.
func TestFullGateNoFailure(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	sa, la := testSigner(t)
	if err := WriteKeysFile(keys, []byte(la+"\n")); err != nil {
		t.Fatal(err)
	}
	s, addr := startServer(t, Config{KeysFile: keys, HandshakeTimeout: 5 * time.Second}, nil)
	var open []net.Conn
	defer func() {
		for _, c := range open {
			_ = c.Close()
		}
	}()
	for i := range preAuthMax {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.3." + strconv.Itoa(i+1))}, Timeout: 2 * time.Second}
		c, err := d.Dial("tcp", addr)
		if err != nil {
			t.Skipf("dial from 127.0.3.%d: %v", i+1, err)
		}
		open = append(open, c)
	}
	time.Sleep(100 * time.Millisecond)
	node := &net.TCPAddr{IP: net.ParseIP("127.0.4.1")}
	for range 2 * failFree {
		if c, err := dialAgent(addr, sa, node); err == nil {
			_ = c.Close()
			t.Fatal("got a slot beyond the pre-auth limit")
		}
	}
	if s.lim.blocked("127.0.4.1", time.Now()) {
		t.Fatal("refusals because of a full gate counted as failures")
	}
	_ = open[0].Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := dialAgent(addr, sa, node)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("new node not admitted after a slot was freed: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
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

// S1-K2: ist die Liste voller Sperren, verdraengen frische Eintraege eines Angreifers nicht seine lange Sperre,
// sondern zuerst Eintraege mit wenigen Fehlversuchen bzw. die kuerzesten Sperren.
func TestLimiterEvictKeepsLongBlocks(t *testing.T) {
	var l limiter
	now := time.Now()
	for i := range failFree + 5 {
		l.fail("long", now.Add(-time.Duration(failFree+5-i)*time.Second)) // laengste Sperre (30 min)
	}
	for i := range failMaxIPs - 1 {
		k := "b" + strconv.Itoa(i)
		for range failFree {
			l.fail(k, now)
		}
	}
	if len(l.m) != failMaxIPs {
		t.Fatalf("setup: %d", len(l.m))
	}
	for i := range failMaxIPs + 10 {
		l.fail("n"+strconv.Itoa(i), now.Add(time.Second))
	}
	if !l.blocked("long", now.Add(time.Second)) {
		t.Fatal("long block evicted by a flood of new addresses")
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
