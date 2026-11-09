package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// Regressionstests zum Review (Pool, Zeitlimits, Fehlertexte, Verfahren, Adressen).

// freezeProxy leitet weiter, bis frozen gesetzt ist; danach haengt sie (Verbindung bleibt offen, nichts kommt an).
type freezeProxy struct {
	ln     net.Listener
	mu     sync.Mutex
	frozen bool
	gate   chan struct{}
}

func newFreezeProxy(t *testing.T, target string) *freezeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &freezeProxy{ln: ln, gate: make(chan struct{})}
	t.Cleanup(func() { _ = ln.Close(); close(p.gate) })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u, err := net.Dial("tcp", target)
			if err != nil {
				_ = c.Close()
				continue
			}
			go p.pipe(u, c)
			go p.pipe(c, u)
		}
	}()
	return p
}

func (p *freezeProxy) freeze() {
	p.mu.Lock()
	p.frozen = true
	p.mu.Unlock()
}

func (p *freezeProxy) pipe(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			p.mu.Lock()
			fr := p.frozen
			p.mu.Unlock()
			if fr {
				<-p.gate
				_ = dst.Close()
				return
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			_ = dst.Close()
			return
		}
	}
}

// F2-K2: toter Host bei offener Verbindung - weder Kanal oeffnen noch laufende Anfrage duerfen das Zeitlimit
// ueberdauern.
func TestTimeoutUnresponsivePeer(t *testing.T) {
	node := newSigner(t)
	fs := startFakeSSH(t, node.PublicKey(), "", func(cmd string, in io.Reader, out, _ io.Writer) uint32 {
		if strings.Contains(cmd, "slow") {
			time.Sleep(300 * time.Millisecond)
		}
		_, _ = io.Copy(io.Discard, in)
		_, _ = io.WriteString(out, "ok")
		return 0
	})
	for _, mid := range []bool{false, true} {
		p := newFreezeProxy(t, fs.addr)
		c, err := NewSSHClient(SSHConfig{Addr: p.ln.Addr().String(), User: "u", Signer: node})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Run(ctx(t), "x"); err != nil {
			t.Fatal(err)
		}
		cx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		done := make(chan error, 1)
		start := time.Now()
		if !mid {
			p.freeze() // Kanal oeffnen haengt
		}
		go func() {
			args := []string{}
			if mid {
				args = append(args, "smart") // der Befehl laeuft, dann friert die Verbindung ein
			}
			_, err := c.conn.exec(cx, "sh -s slow "+strings.Join(args, " "), strings.NewReader("x"), 1<<10)
			done <- err
		}()
		if mid {
			time.Sleep(100 * time.Millisecond)
			p.freeze()
		}
		select {
		case err := <-done:
			if !errors.Is(err, ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "timeout") {
				t.Errorf("mid=%v: err = %v, want timeout", mid, err)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("mid=%v: returned after %v", mid, d)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("mid=%v: request with 500ms deadline still blocked after 5s", mid)
		}
		cancel()
		_ = c.Close()
	}
}

// F2-K1/F7-K1: ein Client, der laufend direkt benutzt wird, darf nicht vom Aufraeumen geschlossen werden - auch
// nicht waehrend einer Anfrage, die laenger als forget dauert.
func TestPoolKeepsClientInUse(t *testing.T) {
	node := newSigner(t)
	fs := startFakeSSH(t, node.PublicKey(), "", func(cmd string, in io.Reader, out, errw io.Writer) uint32 {
		_, _ = io.Copy(io.Discard, in)
		if strings.Contains(cmd, "long") {
			time.Sleep(600 * time.Millisecond)
		}
		_, _ = io.WriteString(out, "ok")
		return 0
	})
	p := NewPool(200 * time.Millisecond)
	defer p.Close()
	c, _ := p.SSH("acc", SSHConfig{Addr: fs.addr, User: "u", Signer: node}) // einmal holen, dann direkt nutzen
	deadline := time.Now().Add(time.Second)
	for i := 0; time.Now().Before(deadline); i++ {
		if _, err := c.Run(ctx(t), "x"); err != nil {
			t.Fatalf("round %d: client in continuous use closed by pool: %v", i, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := c.conn.exec(ctx(t), "sh -s long", strings.NewReader("x"), 1<<10); err != nil {
		t.Fatalf("long request: %v", err)
	}
	if p.Len() != 1 {
		t.Fatalf("len = %d", p.Len())
	}
	// danach ungenutzt: wird verworfen
	deadline = time.Now().Add(3 * time.Second)
	for p.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if p.Len() != 0 {
		t.Fatal("unused client not removed")
	}
}

// F2-K3: nach TOFU und Schluesselwechsel muss "neuen uebernehmen" (leerer Schluessel) einen neuen Client bauen.
func TestPoolResetAfterTOFU(t *testing.T) {
	node := newSigner(t)
	fs1 := startFakeSSH(t, node.PublicKey(), "", echoScript)
	fs2 := startFakeSSH(t, node.PublicKey(), "", echoScript)
	px := newProxy(t, fs1.addr)
	p := NewPool(time.Hour)
	defer p.Close()
	cfg := SSHConfig{Addr: px.addr(), User: "u", Signer: node}
	s1, _ := p.SSH("acc", cfg) // ohne Hostschluessel angelegt -> TOFU
	if _, err := s1.Run(ctx(t), "x"); err != nil {
		t.Fatal(err)
	}
	learned := s1.HostKey()
	px.target.Store(fs2.addr) // Host neu installiert
	px.dropAll()
	cfg.HostKey = learned
	s2, _ := p.SSH("acc", cfg)
	if s2 != s1 {
		t.Fatal("learned key must keep the client")
	}
	if _, err := s2.Run(ctx(t), "x"); !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("want host key changed: %v", err)
	}
	cfg.HostKey = "" // "neuen uebernehmen"
	s3, _ := p.SSH("acc", cfg)
	if s3 == s1 {
		t.Fatal("reset must build a new client")
	}
	if _, err := s3.Run(ctx(t), "x"); err != nil {
		t.Fatalf("after reset: %v", err)
	}
	if s3.HostKey() != Fingerprint(fs2.hk.PublicKey()) {
		t.Fatal("new key not learned")
	}
	if _, err := s1.Run(ctx(t), "x"); !errors.Is(err, ErrClosed) {
		t.Fatalf("old client must be closed: %v", err)
	}
	// Zweiter Abruf mit dem neu gelernten Schluessel behaelt den Client.
	cfg.HostKey = s3.HostKey()
	if s4, _ := p.SSH("acc", cfg); s4 != s3 {
		t.Fatal("learned key must keep the new client")
	}
}

// F2-K7: ein haengender Verbindungsaufbau (bzw. das Ersetzen eines solchen Clients) blockiert andere Schluessel
// nicht; Close wartet nicht auf den Aufbau.
func TestPoolNotBlockedByDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0") // nimmt an, schweigt
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var held []net.Conn
	var hmu sync.Mutex
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hmu.Lock()
			held = append(held, c)
			hmu.Unlock()
		}
	}()
	t.Cleanup(func() {
		hmu.Lock()
		defer hmu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})
	node := newSigner(t)
	p := NewPool(time.Hour)
	defer p.Close()
	a, _ := p.SSH("a", SSHConfig{Addr: ln.Addr().String(), User: "u", Signer: node, DialTimeout: 3 * time.Second})
	runErr := make(chan error, 1)
	go func() { _, err := a.Run(context.Background(), "x"); runErr <- err }()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	if _, err := p.SSH("a", SSHConfig{Addr: "127.0.0.1:1", User: "u", Signer: node}); err != nil { // ersetzt a
		t.Fatal(err)
	}
	if _, err := p.SSH("b", SSHConfig{Addr: "127.0.0.1:2", User: "u", Signer: node}); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("pool blocked %v behind another host's dial", d)
	}
	select {
	case err := <-runErr:
		if !errors.Is(err, ErrClosed) {
			t.Errorf("replaced client during dial: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("closing the client did not abort the dial")
	}
}

// F2-K6: Fehlertexte vom Host (Disconnect-Grund) werden gekuerzt und bereinigt.
func TestHostErrorTextCleaned(t *testing.T) {
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
		defer c.Close()
		_, _ = c.Write([]byte("SSH-2.0-evil\r\n"))
		msg := make([]byte, 100<<10)
		for i := range msg {
			msg[i] = 'A' + byte(i%26)
		}
		copy(msg, "\x1b[31mred‮\n")
		var payload []byte
		payload = append(payload, 1, 0, 0, 0, 2) // SSH_MSG_DISCONNECT, Grund 2
		payload = append(payload, byte(len(msg)>>24), byte(len(msg)>>16), byte(len(msg)>>8), byte(len(msg)))
		payload = append(payload, msg...)
		payload = append(payload, 0, 0, 0, 0)
		pad := 8 - (5+len(payload))%8
		if pad < 4 {
			pad += 8
		}
		plen := 1 + len(payload) + pad
		pkt := []byte{byte(plen >> 24), byte(plen >> 16), byte(plen >> 8), byte(plen), byte(pad)}
		pkt = append(pkt, payload...)
		pkt = append(pkt, make([]byte, pad)...)
		_, _ = c.Write(pkt)
		time.Sleep(time.Second)
	}()
	c, _ := NewAgentClient(AgentConfig{Addr: ln.Addr().String(), Signer: newSigner(t)})
	defer c.Close()
	_, err = c.Info(ctx(t))
	if err == nil {
		t.Fatal("no error")
	}
	checkClean(t, err.Error())
}

func checkClean(t *testing.T, s string) {
	t.Helper()
	if len(s) > maxErrorText+10 {
		t.Errorf("error text not shortened: %d bytes", len(s))
	}
	for _, r := range s {
		if r != ' ' && !unicode.IsPrint(r) {
			t.Errorf("non-printable %U in %q", r, s)
		}
	}
}

func TestCleanError(t *testing.T) {
	base := errors.New("ssh: disconnect, reason 2: \x1b[2J" + strings.Repeat("‮x", 400))
	err := CleanError(base)
	checkClean(t, err.Error())
	if !errors.Is(err, base) {
		t.Fatal("original error must stay reachable for errors.Is")
	}
	short := errors.New("monitor64: client closed")
	if CleanError(short) != short || CleanError(nil) != nil {
		t.Fatal("clean errors must stay unchanged")
	}
	if got := cleanRemote("a\tb\x00c\xffd"); got != "a b c?d" {
		t.Fatalf("cleanRemote = %q", got)
	}
}

// startHostKeySSH: SSH-Server mit vorgegebenen Hostschluesseln.
func startHostKeySSH(t *testing.T, allowed ssh.PublicKey, hostKeys ...ssh.Signer) string {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if string(k.Marshal()) == string(allowed.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("no")
		},
	}
	for _, hk := range hostKeys {
		cfg.AddHostKey(hk)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFake(c, cfg, echoScript)
		}
	}()
	return ln.Addr().String()
}

// F2-K8: Zertifikat-Hostschluessel werden nicht genommen (Fingerabdruck bleibt der des Schluessels), ssh-rsa
// mit SHA-1 wird abgelehnt, RSA mit SHA-2 geht.
func TestHostKeyAlgorithms(t *testing.T) {
	node := newSigner(t)

	hk := newSigner(t)
	ca := newSigner(t)
	cert := &ssh.Certificate{Key: hk.PublicKey(), CertType: ssh.HostCert, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	certSigner, err := ssh.NewCertSigner(cert, hk)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := NewSSHClient(SSHConfig{Addr: startHostKeySSH(t, node.PublicKey(), certSigner, hk), User: "u", Signer: node})
	defer c.Close()
	if _, err := c.Run(ctx(t), "x"); err != nil {
		t.Fatal(err)
	}
	if c.HostKey() != Fingerprint(hk.PublicKey()) {
		t.Fatalf("host key %s, want plain key %s (certificate chosen?)", c.HostKey(), Fingerprint(hk.PublicKey()))
	}

	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := ssh.NewSignerFromKey(rk)
	if err != nil {
		t.Fatal(err)
	}
	sha1Only, err := ssh.NewSignerWithAlgorithms(rs.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSA})
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := NewSSHClient(SSHConfig{Addr: startHostKeySSH(t, node.PublicKey(), sha1Only), User: "u", Signer: node})
	defer c2.Close()
	if _, err := c2.Run(ctx(t), "x"); err == nil {
		t.Fatal("ssh-rsa (SHA-1) host key must be refused")
	} else {
		checkClean(t, err.Error())
	}

	c3, _ := NewSSHClient(SSHConfig{Addr: startHostKeySSH(t, node.PublicKey(), rs), User: "u", Signer: node})
	defer c3.Close()
	if _, err := c3.Run(ctx(t), "x"); err != nil {
		t.Fatalf("rsa-sha2: %v", err)
	}
}

// F11-K7: ein Helfer fuer Adressen mit und ohne Port.
func TestHostPort(t *testing.T) {
	for _, tc := range []struct {
		in   string
		port int
		want string
		host string
	}{
		{"nas", 22, "nas:22", "nas"},
		{"nas:2222", 22, "nas:2222", "nas"},
		{" nas ", 22, "nas:22", "nas"},
		{"192.0.2.1", 7964, "192.0.2.1:7964", "192.0.2.1"},
		{"192.0.2.1:2222", 22, "192.0.2.1:2222", "192.0.2.1"},
		{"2001:db8::1", 22, "[2001:db8::1]:22", "2001:db8::1"},
		{"[2001:db8::1]", 22, "[2001:db8::1]:22", "2001:db8::1"},
		{"[2001:db8::1]:2222", 22, "[2001:db8::1]:2222", "2001:db8::1"},
		{"fe80::1%eth0", 22, "[fe80::1%eth0]:22", "fe80::1%eth0"},
	} {
		if got := HostPort(tc.in, tc.port); got != tc.want {
			t.Errorf("HostPort(%q, %d) = %q, want %q", tc.in, tc.port, got, tc.want)
		}
		if got := SplitHost(tc.in); got != tc.host {
			t.Errorf("SplitHost(%q) = %q, want %q", tc.in, got, tc.host)
		}
	}
}

// Der Host hat mehrere Hostschluessel; gemerkt ist einer, den die bevorzugte Reihenfolge nicht zuerst waehlt:
// kein falsches "Schluessel geaendert" (Fund beim Ausrollen nach dem Review).
func TestPinnedKeyOtherAlgorithm(t *testing.T) {
	node := newSigner(t)
	ed := newSigner(t) // ed25519 (bevorzugt)
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ssh.NewSignerFromKey(ek)
	if err != nil {
		t.Fatal(err)
	}
	addr := startHostKeySSH(t, node.PublicKey(), ed, ec)
	// gemerkt ist der ecdsa-Schluessel (z. B. von einem frueheren Client mit anderer Reihenfolge)
	c, _ := NewSSHClient(SSHConfig{Addr: addr, User: "u", Signer: node, HostKey: Fingerprint(ec.PublicKey())})
	defer c.Close()
	if _, err := c.Run(ctx(t), "x"); err != nil {
		t.Fatalf("pinned ecdsa key must be accepted: %v", err)
	}
	// wirklich fremder Schluessel bleibt "geaendert"
	other := newSigner(t)
	c2, _ := NewSSHClient(SSHConfig{Addr: addr, User: "u", Signer: node, HostKey: Fingerprint(other.PublicKey())})
	defer c2.Close()
	if _, err := c2.Run(ctx(t), "x"); !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("want host key changed, got %v", err)
	}
}
