package transport

import (
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ipv64net/node64/internal/m64proto"
)

// PU1: ein zweiter Client mit demselben Token (frueher "Verbindung testen") meldet beim Schliessen nur sich selbst
// ab; der echte Client behaelt Anmeldung und Verbindungen des Agents.
func TestPushSecondClientKeepsRegistration(t *testing.T) {
	l, addr := startPush(t, PushConfig{}, nil)
	token := NewPushToken()
	e := pushAgent(t, addr, token)
	prod := pushClient(t, l, token, e.node, "", nil)
	if _, err := prod.Info(ctx(t)); err != nil {
		t.Fatal(err)
	}
	other, err := NewAgentClient(AgentConfig{Signer: e.node, Push: l, PushToken: token, PushWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_ = other.Close()
	if !hasOwner(l, token, prod.conn) {
		t.Fatal("registration of the production client lost")
	}
	prod.drop() // naechste Anfrage braucht eine neue Verbindung des Agents
	if _, err := prod.Info(ctx(t)); err != nil {
		t.Fatalf("production client after closing the second client: %v", err)
	}
}

// Karenz: nach dem letzten Client bleibt die Anmeldung samt wartender Verbindung; ein neuer Client in der Karenz
// uebernimmt sie.
func TestPushBoxGrace(t *testing.T) {
	l, addr := startPush(t, PushConfig{}, func(l *PushListener) { l.boxGrace = 300 * time.Millisecond })
	s := newSigner(t)
	token := NewPushToken()
	c1 := pushClient(t, l, token, s, "", nil)
	p, ok := rawPush(t, addr, helloFor(token, s))
	if !ok {
		t.Fatal("refused")
	}
	waitFor(t, "parked", func() bool { return l.Waiting(token) })
	_ = c1.Close()
	pushClient(t, l, token, s, "", nil) // Neubau (ReloadHost)
	time.Sleep(500 * time.Millisecond)
	if !l.Waiting(token) || l.Stats().Tokens != 1 {
		t.Fatalf("registration lost during grace: %+v", l.Stats())
	}
	_ = p.Close()
}

// PU2: der Pool wirft unbenutzte Push-Clients nicht weg (pausierter Host), andere schon.
func TestPoolSweepKeepsPush(t *testing.T) {
	l, _ := startPush(t, PushConfig{}, nil)
	p := NewPool(time.Minute)
	defer p.Close()
	s := newSigner(t)
	token := NewPushToken()
	if _, err := p.Agent("push", AgentConfig{Signer: s, Push: l, PushToken: token}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Agent("pull", AgentConfig{Signer: s, Addr: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	p.sweep(time.Now().Add(time.Hour))
	if p.Existing("push") == nil || p.Existing("pull") != nil {
		t.Fatalf("sweep: push %v pull %v", p.Existing("push") != nil, p.Existing("pull") != nil)
	}
	if l.Stats().Tokens != 1 {
		t.Fatal("registration lost")
	}
}

// SW2: Release haelt den Client fuer die Karenz; wer ihn mit gleicher Konfiguration holt, bekommt ihn samt offener
// Verbindung. Ohne erneutes Holen wird er danach entfernt.
func TestPoolReleaseReuse(t *testing.T) {
	l, addr := startPush(t, PushConfig{}, nil)
	token := NewPushToken()
	e := pushAgent(t, addr, token)
	p := NewPool(0)
	defer p.Close()
	cfg := AgentConfig{Signer: e.node, Push: l, PushToken: token, PushWait: 3 * time.Second}
	a, err := p.Agent("h1", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Info(ctx(t)); err != nil {
		t.Fatal(err)
	}
	cfg.HostKey = a.HostKey()
	a.conn.mu.Lock()
	open := a.conn.client
	a.conn.mu.Unlock()
	p.Release("h1", 200*time.Millisecond)
	b, err := p.Agent("h1", cfg)
	if err != nil || b != a {
		t.Fatal("released client not reused")
	}
	time.Sleep(400 * time.Millisecond)
	b.conn.mu.Lock()
	same := b.conn.client == open && open != nil
	b.conn.mu.Unlock()
	if !same || p.Len() != 1 {
		t.Fatal("connection or client lost after re-use")
	}
	p.Release("h1", 100*time.Millisecond)
	waitFor(t, "removed after grace", func() bool { return p.Len() == 0 })
}

// PU3: aus nicht bestaetigten Netzen hoechstens pushParkedUnverified je Zugang, und sie verdraengen keine
// Verbindung aus einem bestaetigten Netz.
func TestPushUnverifiedCannotEvict(t *testing.T) {
	l, _ := startPush(t, PushConfig{}, nil)
	s := newSigner(t)
	token := NewPushToken()
	pushClient(t, l, token, s, "", nil)
	fp := Fingerprint(s.PublicKey())
	park := func(n string) net.Conn {
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		l.mu.Lock()
		l.conns[a] = struct{}{}
		l.mu.Unlock()
		l.park(a, n, token, fp)
		return b
	}
	l.handshakeOK(token, "198.51.100.1")
	l.handshakeOK(token, "198.51.100.2")
	var legit []net.Conn
	for _, n := range []string{"198.51.100.1", "198.51.100.1", "198.51.100.2", "198.51.100.2"} {
		legit = append(legit, park(n))
	}
	for i := range 6 {
		park(netip4(i))
	}
	if st := l.Stats(); st.Parked != pushParkedPerToken {
		t.Fatalf("parked %d", st.Parked)
	}
	for _, c := range legit {
		_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); !isTimeout(err) {
			t.Fatalf("verified connection evicted: %v", err)
		}
	}
	// ohne bestaetigtes Netz: hoechstens zwei aus nicht bestaetigten
	token2 := NewPushToken()
	pushClient(t, l, token2, s, "", nil)
	before := l.Stats().Parked
	token = token2
	for i := range 4 {
		park(netip4(100 + i))
	}
	if n := l.Stats().Parked - before; n != pushParkedUnverified {
		t.Fatalf("unverified parked %d", n)
	}
}

// PU3: vor dem ersten Kontakt mit zwei verschiedenen angekuendigten Schluesseln wird nichts gemerkt.
func TestPushTOFUAmbiguous(t *testing.T) {
	l, addr := startPush(t, PushConfig{}, nil)
	token := NewPushToken()
	learned := ""
	c := pushClient(t, l, token, newSigner(t), "", func(fp string) { learned = fp })
	k1, k2 := newSigner(t), newSigner(t)
	rogueAgent(t, addr, token, Fingerprint(k1.PublicKey()), k1)
	rogueAgent(t, addr, token, Fingerprint(k2.PublicKey()), k2)
	waitFor(t, "two parked", func() bool { return l.Stats().Parked == 2 })
	if _, err := c.Info(ctx(t)); !errors.Is(err, ErrPushAmbiguous) {
		t.Fatalf("err = %v", err)
	}
	if c.HostKey() != "" || learned != "" {
		t.Fatal("host key learned although ambiguous")
	}
	// bestaetigtes Netz geht vor: nur dessen Verbindungen zaehlen
	now := time.Now()
	b := &pushBox{verified: map[string]time.Time{"n1": now}}
	b.parked = []*parkedConn{{net: "n1", claimed: "A"}, {net: "n2", claimed: "B"}}
	if pc, err := b.pickLocked("", now); err != nil || pc.claimed != "A" {
		t.Fatalf("pick %v %v", pc, err)
	}
	// mit gemerktem Schluessel: angekuendigter gemerkter vor bestaetigtem Netz vor neuester
	b.parked = append(b.parked, &parkedConn{net: "n3", claimed: "C"})
	if pc, _ := b.pickLocked("B", now); pc.claimed != "B" {
		t.Fatalf("pick pinned %v", pc.claimed)
	}
	if pc, _ := b.pickLocked("X", now); pc.claimed != "A" {
		t.Fatalf("pick verified %v", pc.claimed)
	}
}

// PU3: probeStale prueft eine Verbindung mit laufender Anfrage nicht (ausgelastet ist nicht tot).
func TestProbeStaleSkipsBusy(t *testing.T) {
	node, hk := newSigner(t), newSigner(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		cfg := &ssh.ServerConfig{NoClientAuth: true}
		cfg.AddHostKey(hk)
		sc, chans, _, err := ssh.NewServerConn(c, cfg) // globale Anfragen bleiben unbeantwortet
		if err != nil {
			return
		}
		defer sc.Close()
		for nc := range chans {
			_ = nc.Reject(ssh.Prohibited, "no")
		}
	}()
	cn := newConn(connConfig{addr: ln.Addr().String(), user: "x", auth: []ssh.AuthMethod{ssh.PublicKeys(node)}})
	defer cn.Close()
	cl, err := cn.get(ctx(t)) // active = 1 (nicht freigegeben)
	if err != nil {
		t.Fatal(err)
	}
	cn.probeStale(100 * time.Millisecond)
	time.Sleep(400 * time.Millisecond)
	cn.mu.Lock()
	open := cn.client == cl
	cn.mu.Unlock()
	if !open {
		t.Fatal("busy connection closed by probeStale")
	}
	cn.release(cl, false)
}

// PU4: Kennungsphase mit Reserve fuer bekannte Netze und Grenze je IPv6-/48.
func TestPushPendingReserve(t *testing.T) {
	l := NewPushListener(PushConfig{})
	now := time.Now()
	pipe := func() net.Conn {
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		return a
	}
	for i := range pushPendingTotal - pushPendingReserve {
		if !l.admit(pipe(), netip4(i), "", now) {
			t.Fatalf("refused %d", i)
		}
	}
	if l.admit(pipe(), netip4(9999), "", now) {
		t.Fatal("unknown network got a reserved slot")
	}
	l.okLocked("203.0.113.9", now)
	if !l.admit(pipe(), "203.0.113.9", "", now) {
		t.Fatal("known network refused")
	}
	l2 := NewPushListener(PushConfig{})
	for i := range pushPendingPer48 {
		n := "2001:db8:1:" + strconv.Itoa(i) + "::/64"
		if !l2.admit(pipe(), n, "2001:db8:1::/48", now) {
			t.Fatalf("refused /64 %d", i)
		}
	}
	if l2.admit(pipe(), "2001:db8:1:ffff::/64", "2001:db8:1::/48", now) || !l2.admit(pipe(), "2001:db8:2::/64", "2001:db8:2::/48", now) {
		t.Fatal("/48 limit wrong")
	}
	if n, n48 := pushNets(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:3::4"), Port: 1}); n != "2001:db8:1:2::/64" || n48 != "2001:db8:1::/48" {
		t.Fatalf("nets %q %q", n, n48)
	}
}

// PU5: Rebind oeffnet erst den neuen Port und schliesst dann den alten; scheitert das Oeffnen, bleibt der alte.
func TestPushRebind(t *testing.T) {
	l, old := startPush(t, PushConfig{}, nil)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if _, err := l.Rebind(busy.Addr().String()); err == nil {
		t.Fatal("rebind to a used port succeeded")
	}
	if c, err := net.DialTimeout("tcp", old, time.Second); err != nil {
		t.Fatalf("old port closed after failed rebind: %v", err)
	} else {
		_ = c.Close()
	}
	a, err := l.Rebind("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if got := l.Listening(); len(got) != 1 || got[0].String() != a.String() {
		t.Fatalf("listening %v", got)
	}
	if c, err := net.DialTimeout("tcp", old, time.Second); err == nil {
		_ = c.Close()
		t.Fatal("old port still open")
	}
	// gleicher Port, andere Adresse: kurz schliessen, dann neu
	port := a.(*net.TCPAddr).Port
	if _, err := l.Rebind(net.JoinHostPort("", strconv.Itoa(port))); err != nil {
		t.Fatalf("rebind same port: %v", err)
	}
	if got := l.Listening(); len(got) != 1 || got[0].(*net.TCPAddr).Port != port {
		t.Fatalf("listening %v", got)
	}
}

// fakeLn liefert erst errs Fehler, dann blockiert Accept bis Close bzw. liefert final.
type fakeLn struct {
	errs   atomic.Int32
	calls  atomic.Int32
	closed atomic.Bool
	final  chan error
}

func (f *fakeLn) Accept() (net.Conn, error) {
	f.calls.Add(1)
	if f.errs.Add(-1) >= 0 {
		return nil, errors.New("accept: too many open files")
	}
	return nil, <-f.final
}
func (f *fakeLn) Close() error   { f.closed.Store(true); return nil }
func (f *fakeLn) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }

// PU6: voruebergehende Fehler (EMFILE) beenden die Annahme nicht; endet sie doch, wird der Port geschlossen.
func TestPushServeTemporaryErrors(t *testing.T) {
	l := NewPushListener(PushConfig{})
	defer l.Close()
	f := &fakeLn{final: make(chan error, 1)}
	f.errs.Store(3)
	done := make(chan error, 1)
	go func() { done <- l.Serve(f) }()
	waitFor(t, "accept after errors", func() bool { return f.calls.Load() >= 4 })
	select {
	case err := <-done:
		t.Fatalf("serve ended after temporary errors: %v", err)
	default:
	}
	f.final <- net.ErrClosed // Port von aussen weg
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not end")
	}
	if !f.closed.Load() || len(l.Listening()) != 0 {
		t.Fatal("listener not closed at the end of serve")
	}
}

// CL4: Kennung mit den Werten aus m64proto.
func TestPushHelloProto(t *testing.T) {
	fp := Fingerprint(newSigner(t).PublicKey())
	tok := NewPushToken()
	line := m64proto.PushMagic + " " + tok + " " + fp
	if _, _, ok := parseHello(line); !ok || len(line)+1 > m64proto.PushHelloMax {
		t.Fatal("hello")
	}
}
