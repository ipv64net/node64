package m64agent

import (
	"bufio"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const testToken = "abcdefghijklmnopqrstuvwxyz"

func TestParsePushTarget(t *testing.T) {
	for _, tc := range []struct {
		in, addr string
		ok       bool
	}{
		{testToken + "@node.example", "node.example:6466", true},
		{testToken + "@node.example:7000", "node.example:7000", true},
		{"  " + testToken + "@192.0.2.1:6466 ", "192.0.2.1:6466", true},
		{testToken + "@[2001:db8::1]:6466", "[2001:db8::1]:6466", true},
		{testToken + "@[2001:db8::1]", "[2001:db8::1]:6466", true},
		{testToken + "@2001:db8::1", "[2001:db8::1]:6466", true},
		{"node.example:6466", "", false},               // ohne Token
		{"short@node", "", false},                      // Token zu kurz
		{"ABCDEFGHIJKLMNOPQRST@node", "", false},       // Grossbuchstaben
		{testToken + "@", "", false},                   // ohne Host
		{testToken + "@:6466", "", false},              // ohne Host
		{testToken + "@node:0", "", false},             // Port
		{testToken + "@node:70000", "", false},         // Port
		{testToken + "@node:abc", "", false},           // Port
		{testToken + "@no de", "", false},              // Leerzeichen
		{testToken + "@node/x", "", false},             // Pfad
		{testToken + "@a@b", "", false},                // zweites @
		{testToken + "@node\x00", "", false},           // Steuerzeichen
		{testToken + "@[node", "", false},              // Klammer
		{testToken + "@nöde", "", false},               // kein ASCII
		{strings.Repeat("a", 65) + "@node", "", false}, // Token zu lang
		{testToken + "@" + strings.Repeat("a", 300), "", false},
	} {
		got, err := ParsePushTarget(tc.in)
		if tc.ok != (err == nil) || (tc.ok && (got.Addr != tc.addr || got.Token != testToken)) {
			t.Errorf("ParsePushTarget(%q) = %+v, %v", tc.in, got, err)
		}
	}
	if s := (PushTarget{Token: testToken, Addr: "n:1"}).String(); strings.Contains(s, testToken) {
		t.Errorf("String() contains the token: %q", s)
	}
}

func TestParsePushTargets(t *testing.T) {
	data := "# Kommentar\r\n\r\n" + testToken + "@a.example\r\n" + testToken + "@a.example:6466\n" + testToken + "@b.example:7000\n"
	got, err := ParsePushTargets([]byte(data))
	if err != nil || len(got) != 2 || got[0].Addr != "a.example:6466" || got[1].Addr != "b.example:7000" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := ParsePushTargets([]byte(testToken + "@a\nkaputt\n")); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("broken line: %v", err)
	}
	var many strings.Builder
	for i := range 9 {
		many.WriteString(testToken + "@n" + string(rune('a'+i)) + "\n")
	}
	if _, err := ParsePushTargets([]byte(many.String())); err == nil {
		t.Fatal("9 nodes accepted")
	}
}

func TestPushFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, PushFile)
	if got, err := ReadPushFile(p); got != nil || err != nil {
		t.Fatalf("missing file: %v %v", got, err)
	}
	a := PushTarget{Token: testToken, Addr: "a.example:6466"}
	b := PushTarget{Token: "zyxwvutsrqponmlkjihgfedcba", Addr: "b.example:6466"}
	all, err := AddPushTargets(nil, []PushTarget{a, b})
	if err != nil {
		t.Fatal(err)
	}
	// gleiche Adresse: neuer Token ersetzt den alten
	a2 := PushTarget{Token: "aaaaaaaaaaaaaaaaaaaaaaaaaa", Addr: a.Addr}
	if all, err = AddPushTargets(all, []PushTarget{a2}); err != nil || len(all) != 2 || all[0] != a2 {
		t.Fatalf("replace: %+v %v", all, err)
	}
	if err := WritePushFile(p, all); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPushFile(p)
	if err != nil || len(got) != 2 || got[0] != a2 || got[1] != b {
		t.Fatalf("read back: %+v %v", got, err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", fi.Mode().Perm())
		}
		_ = os.Chmod(p, 0o644)
		if _, err := ReadPushFile(p); err != nil {
			t.Fatal(err)
		}
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode not fixed: %v", fi.Mode().Perm())
		}
	}
	if err := os.WriteFile(p, []byte(strings.Repeat("#", maxPushFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPushFile(p); err == nil {
		t.Fatal("large file accepted")
	}
	if _, err := ReadPushFile(dir); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := AddPushTargets(nil, []PushTarget{{Token: "x", Addr: "a:1"}}); err == nil {
		t.Fatal("invalid target accepted")
	}
}

// fakeNode nimmt Push-Verbindungen an und gibt sie dem Test.
type fakeNode struct {
	ln    net.Listener
	conns chan net.Conn
}

func newFakeNode(t *testing.T) *fakeNode {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	n := &fakeNode{ln: ln, conns: make(chan net.Conn, 16)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.conns <- c
		}
	}()
	return n
}

func (n *fakeNode) target() PushTarget {
	return PushTarget{Token: testToken, Addr: n.ln.Addr().String()}
}

// next wartet auf die naechste Verbindung und liest die Kennung.
func (n *fakeNode) next(t *testing.T, d time.Duration) (net.Conn, string) {
	t.Helper()
	select {
	case c := <-n.conns:
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := bufio.NewReaderSize(c, 16).ReadString('\n') // Agent schickt nach der Kennung nichts
		if err != nil {
			t.Fatalf("hello: %v", err)
		}
		_ = c.SetReadDeadline(time.Time{})
		return c, line
	case <-time.After(d):
		t.Fatal("no push connection")
	}
	return nil, ""
}

// startPushAgent startet einen Agent ohne Lauscher mit kurzer Wartezeit.
func startPushAgent(t *testing.T, keysLine string, target PushTarget, prep func(*Server)) *Server {
	t.Helper()
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	if err := WriteKeysFile(keys, []byte(keysLine+"\n")); err != nil {
		t.Fatal(err)
	}
	hk, _ := testSigner(t)
	s, err := New(Config{HostKey: hk, KeysFile: keys, PushRetryMin: 30 * time.Millisecond, PushRetryMax: 240 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if prep != nil {
		prep(s)
	}
	done := make(chan error, 1)
	go func() { done <- s.Push(target) }()
	t.Cleanup(func() {
		_ = s.Close()
		select {
		case err := <-done:
			if !errors.Is(err, ErrServerClosed) {
				t.Errorf("Push returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Push did not end after Close")
		}
	})
	return s
}

// nodeSSH baut als Node SSH auf einer Push-Verbindung auf (nach "W" und "S").
func nodeSSH(t *testing.T, c net.Conn, signer ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	if _, err := c.Write([]byte{pushAck, pushStart}); err != nil {
		return nil, err
	}
	sc, chans, reqs, err := ssh.NewClientConn(c, "node", &ssh.ClientConfig{User: "monitor64",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(sc, chans, reqs), nil
}

// Kennung, Ablehnung mit Wiederholung, Anmeldung, Anfrage, Neuverbinden nach dem Ende.
func TestPushConnectAndReconnect(t *testing.T) {
	node := newFakeNode(t)
	signer, line := testSigner(t)
	s := startPushAgent(t, line, node.target(), nil)
	fp := Fingerprint(s.cfg.HostKey.PublicKey())

	// 1. Verbindung: Token "unbekannt" (ohne Bestaetigung geschlossen) -> neuer Versuch
	c, hello := node.next(t, 5*time.Second)
	if hello != PushMagic+" "+testToken+" "+fp+"\n" || len(hello) > maxPushHello {
		t.Fatalf("hello = %q", hello)
	}
	_ = c.Close()

	// 2. Verbindung: angenommen, SSH, info
	c, _ = node.next(t, 5*time.Second)
	cl, err := nodeSSH(t, c, signer)
	if err != nil {
		t.Fatal(err)
	}
	out, err := runAgent(cl, "info", nil)
	if err != nil || !strings.Contains(out, `"agent":"monitor64-agent"`) {
		t.Fatalf("info: %q %v", out, err)
	}
	// Node beendet die Verbindung -> Agent verbindet zuegig neu
	_ = cl.Close()
	c, _ = node.next(t, 2*time.Second)
	_ = c.Close()
}

// Falscher Schluessel der Node: Anmeldung scheitert, die Wartezeit waechst (bis PushRetryMax).
func TestPushBackoffOnRefusedLogin(t *testing.T) {
	node := newFakeNode(t)
	_, line := testSigner(t)
	stranger, _ := testSigner(t)
	startPushAgent(t, line, node.target(), nil)
	var at []time.Time
	for range 5 {
		c, _ := node.next(t, 5*time.Second)
		at = append(at, time.Now())
		if cl, err := nodeSSH(t, c, stranger); err == nil {
			_ = cl.Close()
			t.Fatal("stranger logged in")
		}
		_ = c.Close()
	}
	// Abstaende 30, 60, 120, 240 ms (+-20 %): der letzte deutlich groesser als der erste
	if first, last := at[1].Sub(at[0]), at[4].Sub(at[3]); last < 2*first || last < 150*time.Millisecond {
		t.Fatalf("no backoff: first %v, last %v", first, last)
	}
}

// Die Node antwortet nicht mit "W"/"S", sondern mit etwas anderem: Fehler, neuer Versuch, keine Panik.
func TestPushUnexpectedAnswer(t *testing.T) {
	node := newFakeNode(t)
	_, line := testSigner(t)
	startPushAgent(t, line, node.target(), nil)
	for _, junk := range []string{"X", "WX", "SSH-2.0-evil\r\n"} {
		c, _ := node.next(t, 5*time.Second)
		_, _ = c.Write([]byte(junk))
		buf := make([]byte, 64)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, err := c.Read(buf); err == nil {
			t.Fatalf("agent answered %q to %q", buf[:n], junk)
		}
		_ = c.Close()
	}
	c, _ := node.next(t, 5*time.Second)
	_ = c.Close()
}

// Wartende Verbindung, die die Node ohne SSH beendet, zaehlt nicht als Fehler (sofort neu, ohne wachsende Wartezeit).
func TestPushRoutedResetsBackoff(t *testing.T) {
	node := newFakeNode(t)
	_, line := testSigner(t)
	startPushAgent(t, line, node.target(), nil)
	for range 4 { // erst Fehlschlaege: Wartezeit waechst
		c, _ := node.next(t, 5*time.Second)
		_ = c.Close()
	}
	c, _ := node.next(t, 5*time.Second)
	_, _ = c.Write([]byte{pushAck})
	time.Sleep(20 * time.Millisecond)
	_ = c.Close()
	start := time.Now()
	c, _ = node.next(t, 5*time.Second)
	_ = c.Close()
	if d := time.Since(start); d > 150*time.Millisecond {
		t.Fatalf("waited %v after a routed connection", d)
	}
}

// Keepalive: antwortet die Node nicht mehr, schliesst der Agent die Verbindung und verbindet neu.
func TestPushKeepalive(t *testing.T) {
	node := newFakeNode(t)
	signer, line := testSigner(t)
	startPushAgent(t, line, node.target(), func(s *Server) { s.pushKeepaliveEvery = 50 * time.Millisecond })

	// Node antwortet auf Keepalives (ssh.Client): Verbindung bleibt
	c, _ := node.next(t, 5*time.Second)
	cl, err := nodeSSH(t, c, signer)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := runAgent(cl, "info", nil); err != nil {
		t.Fatalf("connection with keepalive answers closed: %v", err)
	}
	_ = cl.Close()

	// Node liest globale Anfragen nicht (haengt): Agent schliesst und verbindet neu
	c, _ = node.next(t, 5*time.Second)
	_, _ = c.Write([]byte{pushAck, pushStart})
	sc, chans, _, err := ssh.NewClientConn(c, "node", &ssh.ClientConfig{User: "monitor64",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	go func() {
		for nc := range chans {
			_ = nc.Reject(ssh.Prohibited, "no")
		}
	}()
	// reqs wird nicht gelesen: keine Antwort auf Keepalives
	waitDone := make(chan struct{})
	go func() { _ = sc.Wait(); close(waitDone) }()
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		t.Fatal("dead connection not closed by the agent")
	}
	c, _ = node.next(t, 5*time.Second)
	_ = c.Close()
}

// Close beendet Push auch waehrend des Wartens auf "S" und waehrend der Wartezeit.
func TestPushClose(t *testing.T) {
	node := newFakeNode(t)
	_, line := testSigner(t)
	s := startPushAgent(t, line, node.target(), nil)
	c, _ := node.next(t, 5*time.Second)
	_, _ = c.Write([]byte{pushAck})
	done := make(chan struct{})
	go func() { _ = s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hangs while waiting for the node")
	}
	if err := s.Push(node.target()); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("Push after Close: %v", err)
	}
	if err := (&Server{}).Push(PushTarget{Token: "x", Addr: "a:1"}); err == nil {
		t.Fatal("invalid target accepted")
	}
}

// Mehrere Ziele gleichzeitig (Cluster): je Ziel eine Verbindung.
func TestPushTwoNodes(t *testing.T) {
	n1, n2 := newFakeNode(t), newFakeNode(t)
	signer, line := testSigner(t)
	s := startPushAgent(t, line, n1.target(), nil)
	go func() { _ = s.Push(n2.target()) }()
	var wg sync.WaitGroup
	for _, n := range []*fakeNode{n1, n2} {
		c, _ := n.next(t, 5*time.Second)
		cl, err := nodeSSH(t, c, signer)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cl.Close()
			if _, err := runAgent(cl, "info", nil); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
