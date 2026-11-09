package transport

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ipv64net/node64/internal/m64agent"
)

func TestPushProtocol(t *testing.T) {
	if PushMagic != m64agent.PushMagic || DefaultPushPort != m64agent.DefaultPushPort || pushAck != 'W' || pushStart != 'S' {
		t.Fatal("protocol constants differ between node and agent")
	}
	seen := map[string]bool{}
	for range 50 {
		tok := NewPushToken()
		if len(tok) != 26 || !ValidPushToken(tok) || !m64agent.ValidPushToken(tok) || seen[tok] {
			t.Fatalf("token %q", tok)
		}
		seen[tok] = true
	}
	fp := Fingerprint(newSigner(t).PublicKey())
	tok := NewPushToken()
	for _, tc := range []struct {
		line string
		ok   bool
	}{
		{PushMagic + " " + tok + " " + fp, true},
		{PushMagic + " " + tok + " " + fp + " ", false},
		{PushMagic + "  " + tok + " " + fp, false},
		{"M64PUSH2 " + tok + " " + fp, false},
		{PushMagic + " " + strings.ToUpper(tok) + " " + fp, false},
		{PushMagic + " short " + fp, false},
		{PushMagic + " " + tok + " " + fp[:49], false},
		{PushMagic + " " + tok + " MD5:" + fp[4:], false},
		{PushMagic + " " + tok + " " + fp[:49] + "=", false},
		{PushMagic + " " + tok, false},
		{"", false},
	} {
		gt, gf, ok := parseHello(tc.line)
		if ok != tc.ok || (ok && (gt != tok || gf != fp)) {
			t.Errorf("parseHello(%q) = %q %q %v", tc.line, gt, gf, ok)
		}
	}
}

// startPush startet einen Lauscher auf 127.0.0.1.
func startPush(t *testing.T, cfg PushConfig, prep func(*PushListener)) (*PushListener, string) {
	t.Helper()
	l := NewPushListener(cfg)
	if prep != nil {
		prep(l)
	}
	a, err := l.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, a.String()
}

// pushAgent startet einen Agent (m64agent) im Push-Betrieb zum Lauscher addr.
func pushAgent(t *testing.T, addr, token string) *agentEnv {
	t.Helper()
	e := startAgent(t, func(c *m64agent.Config) {
		c.PushRetryMin, c.PushRetryMax = 20*time.Millisecond, 200*time.Millisecond
	})
	go func() { _ = e.srv.Push(m64agent.PushTarget{Token: token, Addr: addr}) }()
	return e
}

func pushClient(t *testing.T, l *PushListener, token string, signer ssh.Signer, hostKey string, onKey func(string)) *AgentClient {
	t.Helper()
	c, err := NewAgentClient(AgentConfig{Signer: signer, HostKey: hostKey, OnHostKey: onKey, Push: l, PushToken: token,
		PushWait: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// rawPush meldet sich mit einer Kennung und liefert die Verbindung (ok: Node hat mit "W" bestaetigt).
func rawPush(t *testing.T, addr, hello string) (net.Conn, bool) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := io.WriteString(c, hello); err != nil {
		return c, false
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var b [1]byte
	_, err = io.ReadFull(c, b[:])
	_ = c.SetReadDeadline(time.Time{})
	return c, err == nil && b[0] == pushAck
}

func helloFor(token string, s ssh.Signer) string {
	return PushMagic + " " + token + " " + Fingerprint(s.PublicKey()) + "\n"
}

// rogueAgent meldet sich mit token und dem angekuendigten Fingerabdruck claim, zeigt beim Handshake aber den
// eigenen Schluessel hk (z. B. kopierter Fingerabdruck eines fremden Agents).
func rogueAgent(t *testing.T, addr, token, claim string, hk ssh.Signer) {
	t.Helper()
	c, ok := rawPush(t, addr, PushMagic+" "+token+" "+claim+"\n")
	if !ok {
		t.Fatal("rogue connection not accepted")
	}
	go func() {
		var b [1]byte
		if _, err := io.ReadFull(c, b[:]); err != nil || b[0] != pushStart {
			return
		}
		cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil // nimmt jeden Schluessel
		}}
		cfg.AddHostKey(hk)
		if sc, chans, reqs, err := ssh.NewServerConn(c, cfg); err == nil {
			go ssh.DiscardRequests(reqs)
			for nc := range chans {
				_ = nc.Reject(ssh.Prohibited, "rogue")
			}
			_ = sc.Close()
		}
	}()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Ende zu Ende: Agent im Push-Betrieb, Node merkt den Hostschluessel beim ersten Kontakt, info/collect ueber die
// Push-Verbindung, nach Abbruch neu verbunden.
func TestPushEndToEnd(t *testing.T) {
	l, addr := startPush(t, PushConfig{}, nil)
	token := NewPushToken()
	var learned string
	var mu sync.Mutex
	e := pushAgent(t, addr, token)
	c := pushClient(t, l, token, e.node, "", func(fp string) { mu.Lock(); learned = fp; mu.Unlock() })

	info, err := c.Info(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if info.Agent != m64agent.Name {
		t.Fatalf("info = %+v", info)
	}
	want := Fingerprint(e.hostKey.PublicKey())
	mu.Lock()
	got := learned
	mu.Unlock()
	if got != want || c.HostKey() != want {
		t.Fatalf("learned %q, HostKey %q, want %q", got, c.HostKey(), want)
	}
	rep, err := c.Collect(ctx(t), "cpu")
	if err != nil || rep.CPU == nil || rep.CPU.Cores != 4 {
		t.Fatalf("collect: %+v %v", rep, err)
	}
	// Verbindung weg (Leerlauf, Abbruch): naechste Anfrage nimmt die neue Verbindung des Agents
	c.drop()
	if _, err := c.Info(ctx(t)); err != nil {
		t.Fatalf("after reconnect: %v", err)
	}
	if st := l.Stats(); st.Tokens != 1 {
		t.Fatalf("stats %+v", st)
	}
}

// Ohne Agent: kurze Wartezeit, dann ErrNotConnected.
func TestPushNotConnected(t *testing.T) {
	l, _ := startPush(t, PushConfig{}, nil)
	c, err := NewAgentClient(AgentConfig{Signer: newSigner(t), Push: l, PushToken: NewPushToken(), PushWait: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	_, err = c.Info(ctx(t))
	if !errors.Is(err, ErrNotConnected) || time.Since(start) > 2*time.Second {
		t.Fatalf("err %v after %v", err, time.Since(start))
	}
	if _, err := NewAgentClient(AgentConfig{Signer: newSigner(t), Push: l, PushToken: "kurz"}); err == nil {
		t.Fatal("invalid token accepted")
	}
}

// Gemerkter Hostschluessel passt nicht: *HostKeyError mit dem nachweislich angebotenen Schluessel, nichts gemerkt.
func TestPushWrongHostKey(t *testing.T) {
	l, addr := startPush(t, PushConfig{}, nil)
	token := NewPushToken()
	e := pushAgent(t, addr, token)
	pinned := Fingerprint(newSigner(t).PublicKey())
	c := pushClient(t, l, token, e.node, pinned, nil)
	_, err := c.Info(ctx(t))
	var hk *HostKeyError
	if !errors.As(err, &hk) || hk.Got != Fingerprint(e.hostKey.PublicKey()) || hk.Want != pinned {
		t.Fatalf("err = %v", err)
	}
	if c.HostKey() != pinned {
		t.Fatalf("host key changed to %q", c.HostKey())
	}
}

// Fremder Agent mit kopiertem Fingerabdruck (und Token): scheitert am Handshake. Ist der echte Agent auch da, wird
// dessen Verbindung genommen; allein ergibt der fremde einen *HostKeyError mit seinem echten Schluessel.
func TestPushCopiedFingerprint(t *testing.T) {
	l, addr := startPush(t, PushConfig{}, nil)
	token := NewPushToken()
	e := pushAgent(t, addr, token)
	legit := Fingerprint(e.hostKey.PublicKey())
	c := pushClient(t, l, token, e.node, legit, nil)
	waitFor(t, "legit agent parked", func() bool { return l.Waiting(token) })
	rogue := newSigner(t)
	rogueAgent(t, addr, token, legit, rogue) // neuer als die echte Verbindung, gleicher angekuendigter Fingerabdruck
	waitFor(t, "two parked", func() bool { return l.Stats().Parked == 2 })
	if _, err := c.Info(ctx(t)); err != nil {
		t.Fatalf("legit connection not used: %v", err)
	}

	// allein: fremder Agent
	l2, addr2 := startPush(t, PushConfig{}, nil)
	token2 := NewPushToken()
	c2, err := NewAgentClient(AgentConfig{Signer: e.node, HostKey: legit, Push: l2, PushToken: token2, PushWait: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	rogueAgent(t, addr2, token2, legit, rogue)
	_, err = c2.Info(ctx(t))
	var hk *HostKeyError
	if !errors.As(err, &hk) || hk.Got != Fingerprint(rogue.PublicKey()) {
		t.Fatalf("err = %v", err)
	}
	if c2.HostKey() != legit {
		t.Fatalf("host key changed to %q", c2.HostKey())
	}
}

// Erster Kontakt: angebotener Schluessel muss zum angekuendigten Fingerabdruck passen, sonst wird nichts gemerkt.
func TestPushTOFUClaimMismatch(t *testing.T) {
	l, addr := startPush(t, PushConfig{}, nil)
	token := NewPushToken()
	learned := ""
	c := pushClient(t, l, token, newSigner(t), "", func(fp string) { learned = fp })
	rogueAgent(t, addr, token, Fingerprint(newSigner(t).PublicKey()), newSigner(t))
	_, err := c.Info(ctx(t))
	var hk *HostKeyError
	if err == nil || errors.As(err, &hk) || !strings.Contains(err.Error(), "announced fingerprint") {
		t.Fatalf("err = %v", err)
	}
	if c.HostKey() != "" || learned != "" {
		t.Fatalf("host key learned: %q %q", c.HostKey(), learned)
	}
}

// Kennung: unbekannter Token, kaputte oder zu lange Kennung, Zeitlimit - Verbindung zu, ohne "W".
func TestPushHelloRefused(t *testing.T) {
	l, addr := startPush(t, PushConfig{}, func(l *PushListener) { l.helloTimeout = 200 * time.Millisecond })
	token := NewPushToken()
	s := newSigner(t)
	pushClient(t, l, token, s, "", nil)
	for _, hello := range []string{
		helloFor(NewPushToken(), s), // unbekannt
		"GET / HTTP/1.1\r\n\r\n",
		strings.Repeat("A", 400),
		PushMagic + " " + token + " " + Fingerprint(s.PublicKey()) + "\r\n",
		"", // nichts: Zeitlimit
	} {
		c, ok := rawPush(t, addr, hello)
		if ok {
			t.Errorf("accepted %q", hello)
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
			t.Errorf("connection for %q not closed: %v", hello, err)
		}
	}
	if _, ok := rawPush(t, addr, helloFor(token, s)); !ok {
		t.Fatal("valid hello refused")
	}
	waitFor(t, "parked", func() bool { st := l.Stats(); return st.Parked == 1 && st.Pending == 0 })
}

// Fehlversuche sperren ein Netz - nie aber eines, aus dem schon ein gueltiger Token kam.
func TestPushFailBlock(t *testing.T) {
	s := newSigner(t)
	l, addr := startPush(t, PushConfig{}, nil)
	token := NewPushToken()
	pushClient(t, l, token, s, "", nil)
	for range pushFailFree {
		rawPush(t, addr, helloFor(NewPushToken(), s))
	}
	waitFor(t, "block", func() bool { l.mu.Lock(); defer l.mu.Unlock(); return l.refusedLocked("127.0.0.1", time.Now()) })
	if _, ok := rawPush(t, addr, helloFor(token, s)); ok {
		t.Fatal("blocked network accepted")
	}

	l2, addr2 := startPush(t, PushConfig{}, nil)
	pushClient(t, l2, token, s, "", nil)
	if _, ok := rawPush(t, addr2, helloFor(token, s)); !ok {
		t.Fatal("valid hello refused")
	}
	for range pushFailFree + 5 {
		rawPush(t, addr2, helloFor(NewPushToken(), s))
	}
	if _, ok := rawPush(t, addr2, helloFor(token, s)); !ok {
		t.Fatal("known network blocked")
	}

	// Limiter direkt: Verfall, Sperre, Eintraege begrenzt
	l3 := NewPushListener(PushConfig{})
	now := time.Now()
	for i := range pushFailFree - 1 {
		l3.failLocked("192.0.2.1", now.Add(time.Duration(i)*time.Second))
	}
	if l3.refusedLocked("192.0.2.1", now.Add(time.Minute)) {
		t.Fatal("blocked too early")
	}
	l3.failLocked("192.0.2.1", now.Add(time.Minute))
	if !l3.refusedLocked("192.0.2.1", now.Add(time.Minute)) || l3.refusedLocked("192.0.2.1", now.Add(time.Minute+pushFailBlock+time.Second)) {
		t.Fatal("block wrong")
	}
	for i := range pushMaxNets + 100 {
		l3.failLocked(netip4(i), now)
		l3.okLocked(netip4(i+1<<20), now)
	}
	if len(l3.fails) > pushMaxNets || len(l3.good) > pushMaxNets {
		t.Fatalf("maps grow: %d %d", len(l3.fails), len(l3.good))
	}
}

func netip4(i int) string {
	return net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)).String()
}

// Grenzen: Kennungsphase je Netz, wartende Verbindungen je Netz und Token (aelteste verdraengt), je Token.
func TestPushLimits(t *testing.T) {
	l, addr := startPush(t, PushConfig{}, func(l *PushListener) { l.helloTimeout = 3 * time.Second })
	s := newSigner(t)
	token := NewPushToken()
	pushClient(t, l, token, s, "", nil)

	// Kennungsphase: hoechstens pushPendingPerNet stille Verbindungen je Netz
	var silent []net.Conn
	for range pushPendingPerNet {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		silent = append(silent, c)
	}
	waitFor(t, "pending", func() bool { return l.Stats().Pending == pushPendingPerNet })
	extra, _ := net.Dial("tcp", addr)
	_ = extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("connection over the pending limit not closed: %v", err)
	}
	_ = extra.Close()
	for _, c := range silent {
		_ = c.Close()
	}
	waitFor(t, "pending released", func() bool { return l.Stats().Pending == 0 })

	// je Netz und Token zwei: die dritte verdraengt die aelteste
	c1, ok1 := rawPush(t, addr, helloFor(token, s))
	_, ok2 := rawPush(t, addr, helloFor(token, s))
	_, ok3 := rawPush(t, addr, helloFor(token, s))
	if !ok1 || !ok2 || !ok3 {
		t.Fatal("parking refused")
	}
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c1.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("oldest connection not replaced: %v", err)
	}
	waitFor(t, "two parked", func() bool { return l.Stats().Parked == pushParkedPerNetToken })

	// je Token hoechstens pushParkedPerToken (verschiedene Netze direkt ueber park)
	for i := range pushParkedPerToken + 2 {
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		l.mu.Lock()
		l.conns[a] = struct{}{}
		l.mu.Unlock()
		l.park(a, netip4(i), token, Fingerprint(s.PublicKey()))
	}
	if st := l.Stats(); st.Parked != pushParkedPerToken {
		t.Fatalf("parked per token %d", st.Parked)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Wartende Verbindungen: Agent weg -> verworfen; zu alt -> geschlossen; Zugang abgemeldet -> geschlossen.
func TestPushParkedLifecycle(t *testing.T) {
	l, addr := startPush(t, PushConfig{ParkMax: 300 * time.Millisecond}, nil)
	s := newSigner(t)
	token := NewPushToken()
	c := pushClient(t, l, token, s, "", nil)

	a, ok := rawPush(t, addr, helloFor(token, s))
	if !ok {
		t.Fatal("refused")
	}
	_ = a.Close()
	waitFor(t, "closed parked connection dropped", func() bool { return l.Stats().Parked == 0 })

	b, _ := rawPush(t, addr, helloFor(token, s))
	_ = b.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := b.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("expired connection not closed: %v", err)
	}
	waitFor(t, "expired", func() bool { return l.Stats().Parked == 0 })

	// Daten entgegen dem Protokoll -> verworfen
	d, _ := rawPush(t, addr, helloFor(token, s))
	_, _ = d.Write([]byte("x"))
	_ = d.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := d.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("connection with data not closed: %v", err)
	}

	e, _ := rawPush(t, addr, helloFor(token, s))
	waitFor(t, "parked", func() bool { return l.Waiting(token) })
	_ = c.Close()
	_ = e.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := e.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("connection of a removed access not closed: %v", err)
	}
	if st := l.Stats(); st.Tokens != 0 || st.Parked != 0 {
		t.Fatalf("stats %+v", st)
	}
	// unbekannt nach dem Abmelden
	if _, ok := rawPush(t, addr, helloFor(token, s)); ok {
		t.Fatal("hello for a removed access accepted")
	}
}

// Lauscher schliessen: wartende Verbindungen zu, Anfragen ErrNotConnected, Serve endet.
func TestPushListenerClose(t *testing.T) {
	l, addr := startPush(t, PushConfig{}, nil)
	s := newSigner(t)
	token := NewPushToken()
	c := pushClient(t, l, token, s, "", nil)
	p, _ := rawPush(t, addr, helloFor(token, s))
	waitFor(t, "parked", func() bool { return l.Waiting(token) })
	_ = l.Close()
	_ = p.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := p.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("parked connection open after Close: %v", err)
	}
	if _, err := c.Info(ctx(t)); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("err = %v", err)
	}
	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Fatal("listener still open")
	}
	if _, err := l.Listen("127.0.0.1:0"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Listen after Close: %v", err)
	}
}

// Port schliessen und wieder oeffnen: Anmeldungen bleiben.
func TestPushStopListening(t *testing.T) {
	l, addr := startPush(t, PushConfig{}, nil)
	s := newSigner(t)
	token := NewPushToken()
	pushClient(t, l, token, s, "", nil)
	if len(l.Listening()) != 1 {
		t.Fatal("not listening")
	}
	l.StopListening()
	if len(l.Listening()) != 0 {
		t.Fatal("still listening")
	}
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_ = c.Close()
		t.Fatal("port still open")
	}
	a, err := l.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rawPush(t, a.String(), helloFor(token, s)); !ok {
		t.Fatal("registration lost after StopListening")
	}
}

// Pool: gleiche Push-Einstellung = gleicher Client; neuer Token = neuer Client, der alte meldet den neuen nicht ab.
func TestPushPool(t *testing.T) {
	l, _ := startPush(t, PushConfig{}, nil)
	p := NewPool(0)
	defer p.Close()
	s := newSigner(t)
	t1, t2 := NewPushToken(), NewPushToken()
	cfg := AgentConfig{Signer: s, Push: l, PushToken: t1}
	a, err := p.Agent("h1", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := p.Agent("h1", cfg); b != a {
		t.Fatal("client replaced without change")
	}
	cfg.PushToken = t2
	b, err := p.Agent("h1", cfg)
	if err != nil || b == a {
		t.Fatal("client not replaced for a new token")
	}
	l.mu.Lock()
	_, old := l.boxes[t1]
	nb := l.boxes[t2]
	l.mu.Unlock()
	if old || nb == nil || nb.owner != b.conn {
		t.Fatal("registration wrong after replacement")
	}
	// gleicher Token, neuer Client (z. B. anderer Schluessel): Anmeldung bleibt beim neuen
	cfg.Signer = newSigner(t)
	c, _ := p.Agent("h1", cfg)
	l.mu.Lock()
	nb = l.boxes[t2]
	l.mu.Unlock()
	if nb == nil || nb.owner != c.conn {
		t.Fatal("old client removed the registration of the new one")
	}
}

// probeStale: antwortet die alte Verbindung nicht auf ein Keepalive, wird sie geschlossen; antwortet sie, bleibt sie.
func TestProbeStale(t *testing.T) {
	node := newSigner(t)
	for _, tc := range []struct {
		name  string
		reply bool
	}{{"alive", true}, {"dead", false}} {
		t.Run(tc.name, func(t *testing.T) {
			hk := newSigner(t)
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
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				if tc.reply {
					go ssh.DiscardRequests(reqs)
				} // sonst: globale Anfragen bleiben unbeantwortet
				for nc := range chans {
					_ = nc.Reject(ssh.Prohibited, "no")
				}
			}()
			cn := newConn(connConfig{addr: ln.Addr().String(), user: "x", auth: []ssh.AuthMethod{ssh.PublicKeys(node)}})
			defer cn.Close()
			cl, err := cn.get(ctx(t))
			if err != nil {
				t.Fatal(err)
			}
			cn.release(cl, false)
			cn.probeStale(200 * time.Millisecond)
			time.Sleep(600 * time.Millisecond)
			cn.mu.Lock()
			open := cn.client != nil
			probing := cn.probing
			cn.mu.Unlock()
			if open != tc.reply || probing {
				t.Fatalf("open %v probing %v", open, probing)
			}
		})
	}
}

// Neue Push-Verbindung (z. B. eines Fremden mit dem Token) bei offener, gesunder Verbindung: die alte wird nur
// geprueft und bleibt (eine tote schliesst probeStale, siehe TestProbeStale).
func TestPushKeepsHealthyConnection(t *testing.T) {
	l, addr := startPush(t, PushConfig{}, nil)
	token := NewPushToken()
	e := pushAgent(t, addr, token)
	c := pushClient(t, l, token, e.node, "", nil)
	if _, err := c.Info(ctx(t)); err != nil {
		t.Fatal(err)
	}
	c.conn.mu.Lock()
	old := c.conn.client
	c.conn.mu.Unlock()
	if old == nil {
		t.Fatal("no open connection")
	}
	hk := newSigner(t)
	rogueAgent(t, addr, token, Fingerprint(e.hostKey.PublicKey()), hk) // irgendeine neue Verbindung mit dem Token
	// Der echte Agent antwortet auf Keepalives: die Verbindung bleibt.
	time.Sleep(pushProbeWait / 10)
	c.conn.mu.Lock()
	still := c.conn.client == old
	c.conn.mu.Unlock()
	if !still {
		t.Fatal("healthy connection closed by a new push connection")
	}
}
