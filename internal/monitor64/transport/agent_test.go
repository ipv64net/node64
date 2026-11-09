package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ipv64net/node64/internal/m64agent"
	"github.com/ipv64net/node64/internal/m64proto"
)

// fakeCollector liefert feste Werte und merkt sich die angefragten Abschnitte.
type fakeCollector struct {
	mu   sync.Mutex
	secs [][]string
	big  bool
}

func (f *fakeCollector) Collect(_ context.Context, secs []string) *m64proto.Report {
	f.mu.Lock()
	f.secs = append(f.secs, secs)
	big := f.big
	f.mu.Unlock()
	r := &m64proto.Report{CPU: &m64proto.CPU{Cores: 4, User: 100, Idle: 900}, Mem: &m64proto.Mem{Total: 8 << 30, Available: 4 << 30}}
	if big {
		for i := 0; i < 60000; i++ {
			r.FS = append(r.FS, m64proto.FS{Mount: "/mnt/" + strings.Repeat("x", 60), Total: uint64(i)})
		}
	}
	return r
}

func (f *fakeCollector) Caps() []string { return []string{m64proto.SecCPU, m64proto.SecMem} }

type agentEnv struct {
	srv      *m64agent.Server
	addr     string
	dir      string
	keysFile string
	exe      string
	hostKey  ssh.Signer
	node     ssh.Signer
	relPriv  ed25519.PrivateKey
	coll     *fakeCollector
	updated  chan string
}

func startAgent(t *testing.T, mod func(*m64agent.Config)) *agentEnv {
	t.Helper()
	dir := t.TempDir()
	e := &agentEnv{dir: dir, keysFile: filepath.Join(dir, "keys"), exe: filepath.Join(dir, "bin", "monitor64-agent"),
		node: newSigner(t), coll: &fakeCollector{}, updated: make(chan string, 4)}
	writeFile(t, e.keysFile, []byte(keyLine(e.node)+" node\n"), 0o600)
	writeFile(t, e.exe, []byte("old binary"), 0o755)
	hk, err := m64agent.LoadOrCreateHostKey(filepath.Join(dir, "hostkey"))
	if err != nil {
		t.Fatal(err)
	}
	e.hostKey = hk
	relPub, relPriv, _ := ed25519.GenerateKey(rand.Reader)
	e.relPriv = relPriv
	cfg := m64agent.Config{
		HostKey:     hk,
		KeysFile:    e.keysFile,
		Collector:   e.coll,
		Version:     "1.0.0",
		ReleaseKeys: []ed25519.PublicKey{relPub},
		ExePath:     e.exe,
		OnUpdated:   func(v string) { e.updated <- v },
	}
	if mod != nil {
		mod(&cfg)
	}
	srv, err := m64agent.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	e.srv, e.addr = srv, ln.Addr().String()
	return e
}

func (e *agentEnv) client(t *testing.T, addr string, signer ssh.Signer, hostKey string) *AgentClient {
	t.Helper()
	c, err := NewAgentClient(AgentConfig{Addr: addr, Signer: signer, HostKey: hostKey})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestAgentInfoCollect(t *testing.T) {
	e := startAgent(t, nil)
	p := newProxy(t, e.addr)
	var learned []string
	c, err := NewAgentClient(AgentConfig{Addr: p.addr(), Signer: e.node, OnHostKey: func(fp string) { learned = append(learned, fp) }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	info, err := c.Info(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if info.Agent != m64agent.Name || info.Version != "1.0.0" || info.OS != runtime.GOOS || !slices.Contains(info.Caps, "cpu") {
		t.Fatalf("info = %+v", info)
	}
	want := Fingerprint(e.hostKey.PublicKey())
	if c.HostKey() != want || len(learned) != 1 || learned[0] != want {
		t.Fatalf("TOFU: HostKey %q learned %v want %q", c.HostKey(), learned, want)
	}
	rep, err := c.Collect(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if rep.V != m64proto.Version || rep.CPU == nil || rep.CPU.Cores != 4 || rep.Time == 0 {
		t.Fatalf("report = %+v", rep)
	}
	if _, err := c.Collect(ctx(t), "cpu", "mem"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Collect(ctx(t), "cpu;id"); err == nil {
		t.Fatal("invalid section accepted by client")
	}
	e.coll.mu.Lock()
	got := e.coll.secs
	e.coll.mu.Unlock()
	if len(got) != 2 || len(got[0]) != 0 || !slices.Equal(got[1], []string{"cpu", "mem"}) {
		t.Fatalf("sections = %v", got)
	}
	// nur "local" ohne local.d: Collector wird nicht gefragt
	if _, err := c.Collect(ctx(t), "local"); err != nil {
		t.Fatal(err)
	}
	// gleichzeitige Anfragen ueber dieselbe Verbindung
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.Collect(ctx(t))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := p.accepts.Load(); n != 1 {
		t.Fatalf("connection not reused: %d connections", n)
	}
}

func TestAgentWrongKey(t *testing.T) {
	e := startAgent(t, nil)
	c := e.client(t, e.addr, newSigner(t), "")
	_, err := c.Info(ctx(t))
	if err == nil || errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("wrong key: err = %v", err)
	}
}

func TestAgentRateLimit(t *testing.T) {
	e := startAgent(t, nil)
	for range 5 {
		c := e.client(t, e.addr, newSigner(t), "")
		if _, err := c.Info(ctx(t)); err == nil {
			t.Fatal("wrong key accepted")
		}
	}
	// Der Agent zaehlt den Fehlversuch erst, nachdem der Client die Ablehnung schon gesehen hat: warten, bis er
	// beim Annehmen sperrt (sonst kaeme der richtige Schluessel noch durch, und die Adresse gaelte danach als bekannt).
	waitRefused(t, e.addr)
	// jetzt ist 127.0.0.1 gesperrt - auch der richtige Schluessel
	c := e.client(t, e.addr, e.node, "")
	if _, err := c.Info(ctx(t)); err == nil {
		t.Fatal("blocked address accepted")
	}
}

// waitRefused wartet, bis der Agent Verbindungen von 127.0.0.1 gleich beim Annehmen schliesst (ohne SSH-Kennung).
func waitRefused(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			var b [4]byte
			n, rerr := io.ReadFull(c, b[:])
			_ = c.Close()
			if n == 0 && rerr != nil && !errors.Is(rerr, os.ErrDeadlineExceeded) {
				return // geschlossen ohne Kennung: gesperrt
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("address not refused after failed logins")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// rawClient verbindet ohne transport (fuer verbotene Anfragen).
func rawClient(t *testing.T, e *agentEnv) *ssh.Client {
	t.Helper()
	cl, err := ssh.Dial("tcp", e.addr, &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.PublicKeys(e.node)},
		HostKeyCallback: ssh.FixedHostKey(e.hostKey.PublicKey()), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	return cl
}

func TestAgentForbidden(t *testing.T) {
	e := startAgent(t, nil)
	cl := rawClient(t, e)
	var last *ssh.Session
	session := func() *ssh.Session {
		if last != nil {
			_ = last.Close() // der Agent erlaubt nur wenige offene Kanaele je Verbindung
			time.Sleep(20 * time.Millisecond)
		}
		s, err := cl.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		last = s
		return s
	}
	defer func() {
		if last != nil {
			_ = last.Close()
		}
	}()
	if err := session().Shell(); err == nil {
		t.Error("shell accepted")
	}
	if err := session().RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err == nil {
		t.Error("pty accepted")
	}
	if err := session().RequestSubsystem("sftp"); err == nil {
		t.Error("subsystem accepted")
	}
	if err := session().Setenv("LD_PRELOAD", "/tmp/x.so"); err == nil {
		t.Error("env accepted")
	}
	for _, cmd := range []string{"ls", "id", "collect;id", "collect cpu id", "info\n", "keys --force", "/bin/sh -c info"} {
		if err := session().Run(cmd); err == nil {
			t.Errorf("exec %q accepted", cmd)
		}
	}
	s := session()
	if ok, _ := s.SendRequest("x11-req", true, nil); ok {
		t.Error("x11 accepted")
	}
	if ok, _ := s.SendRequest("auth-agent-req@openssh.com", true, nil); ok {
		t.Error("agent forwarding accepted")
	}
	if c, err := cl.Dial("tcp", "127.0.0.1:22"); err == nil {
		_ = c.Close()
		t.Error("direct-tcpip accepted")
	}
	if l, err := cl.Listen("tcp", "127.0.0.1:0"); err == nil {
		_ = l.Close()
		t.Error("tcpip-forward accepted")
	}
	if _, _, err := cl.OpenChannel("direct-streamlocal@openssh.com", nil); err == nil {
		t.Error("streamlocal accepted")
	}
	// erlaubte Anfrage funktioniert auf derselben Verbindung weiter
	out, err := session().Output("info")
	if err != nil || !bytes.Contains(out, []byte(`"agent":"monitor64-agent"`)) {
		t.Fatalf("info after refusals: %v %s", err, out)
	}
}

func TestAgentHostKeyChanged(t *testing.T) {
	e1 := startAgent(t, nil)
	e2 := startAgent(t, func(c *m64agent.Config) {})
	// gleicher Node-Schluessel auf beiden Agents
	writeFile(t, e2.keysFile, []byte(keyLine(e1.node)+"\n"), 0o600)

	// falscher Fingerabdruck vorgegeben
	c := e1.client(t, e1.addr, e1.node, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	_, err := c.Info(ctx(t))
	var hke *HostKeyError
	if !errors.Is(err, ErrHostKeyChanged) || !errors.As(err, &hke) || hke.Got != Fingerprint(e1.hostKey.PublicKey()) {
		t.Fatalf("err = %v", err)
	}
	// bekannter Fingerabdruck (auch ohne Praefix/Padding eingegeben) passt
	fp := strings.TrimPrefix(Fingerprint(e1.hostKey.PublicKey()), "SHA256:") + "="
	if _, err := e1.client(t, e1.addr, e1.node, fp).Info(ctx(t)); err != nil {
		t.Fatalf("known key: %v", err)
	}

	// TOFU, danach anderer Agent hinter derselben Adresse
	p := newProxy(t, e1.addr)
	c = e1.client(t, p.addr(), e1.node, "")
	if _, err := c.Info(ctx(t)); err != nil {
		t.Fatal(err)
	}
	p.target.Store(e2.addr)
	p.dropAll()
	_, err = c.Info(ctx(t))
	if !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("changed host key not detected: %v", err)
	}
	if c.HostKey() != Fingerprint(e1.hostKey.PublicKey()) {
		t.Fatal("learned key must stay")
	}
}

func TestAgentReconnectAndIdle(t *testing.T) {
	e := startAgent(t, nil)
	p := newProxy(t, e.addr)
	c, err := NewAgentClient(AgentConfig{Addr: p.addr(), Signer: e.node, IdleTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Info(ctx(t)); err != nil {
		t.Fatal(err)
	}
	p.dropAll() // Verbindung bricht weg
	time.Sleep(50 * time.Millisecond)
	if _, err := c.Info(ctx(t)); err != nil {
		t.Fatalf("no reconnect: %v", err)
	}
	if n := p.accepts.Load(); n != 2 {
		t.Fatalf("accepts = %d, want 2", n)
	}
	time.Sleep(time.Second) // Leerlauf schliesst
	if _, err := c.Info(ctx(t)); err != nil {
		t.Fatal(err)
	}
	if n := p.accepts.Load(); n != 3 {
		t.Fatalf("accepts after idle = %d, want 3", n)
	}
	_ = c.Close()
	if _, err := c.Info(ctx(t)); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed client: %v", err)
	}
}

func signed(priv ed25519.PrivateKey, version, goos, goarch string, body []byte) m64proto.UpdateHeader {
	sum := sha256.Sum256(body)
	h := m64proto.UpdateHeader{Version: version, OS: goos, Arch: goarch, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}
	h.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, m64proto.SignedMessage(h.Version, h.OS, h.Arch, h.SHA256)))
	return h
}

func TestAgentUpdate(t *testing.T) {
	e := startAgent(t, nil)
	c := e.client(t, e.addr, e.node, "")
	body := bytes.Repeat([]byte("new agent "), 100000) // ~1 MB
	_, badPriv, _ := ed25519.GenerateKey(rand.Reader)
	readExe := func() string { b, _ := os.ReadFile(e.exe); return string(b) }

	for name, tc := range map[string]struct {
		h    m64proto.UpdateHeader
		body []byte
		want string
	}{
		"bad signature": {signed(badPriv, "1.1.0", runtime.GOOS, runtime.GOARCH, body), body, "signature"},
		"downgrade":     {signed(e.relPriv, "0.9.0", runtime.GOOS, runtime.GOARCH, body), body, "not newer"},
		"same version":  {signed(e.relPriv, "1.0.0", runtime.GOOS, runtime.GOARCH, body), body, "not newer"},
		"wrong arch":    {signed(e.relPriv, "1.1.0", runtime.GOOS, "mips", body), body, "platform"},
		"wrong content": {signed(e.relPriv, "1.1.0", runtime.GOOS, runtime.GOARCH, body), append([]byte("X"), body[1:]...), "sha256"},
		"short body":    {signed(e.relPriv, "1.1.0", runtime.GOOS, runtime.GOARCH, body), body[:1000], "incomplete"},
	} {
		res, err := c.Update(ctx(t), tc.h, bytes.NewReader(tc.body))
		if err == nil || res == nil || res.OK || !strings.Contains(res.Error, tc.want) {
			t.Errorf("%s: res %+v err %v", name, res, err)
		}
		if readExe() != "old binary" {
			t.Fatalf("%s: old file changed", name)
		}
	}
	res, err := c.Update(ctx(t), signed(e.relPriv, "1.1.0", runtime.GOOS, runtime.GOARCH, body), bytes.NewReader(body))
	if err != nil || !res.OK || res.Version != "1.1.0" {
		t.Fatalf("valid update: %+v %v", res, err)
	}
	if readExe() != string(body) {
		t.Fatal("file not replaced")
	}
	select {
	case v := <-e.updated:
		if v != "1.1.0" {
			t.Fatalf("OnUpdated %q", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnUpdated not called")
	}
	// Erlaubt: neue Datei, vorherige Version fuer den Rueckfall (.old) und der Merker der unbestaetigten neuen
	// Version (.update); sonst nichts (keine Reste von Zwischendateien).
	ents, _ := os.ReadDir(filepath.Dir(e.exe))
	base := filepath.Base(e.exe)
	for _, ent := range ents {
		switch ent.Name() {
		case base, base + ".update":
		case base + ".old":
			if b, _ := os.ReadFile(e.exe + ".old"); string(b) != "old binary" {
				t.Fatalf(".old has wrong content")
			}
		default:
			t.Fatalf("leftover files: %v", ents)
		}
	}
}

func TestAgentUpdateDisabled(t *testing.T) {
	e := startAgent(t, func(c *m64agent.Config) { c.ReleaseKeys = nil })
	c := e.client(t, e.addr, e.node, "")
	body := []byte("x")
	res, err := c.Update(ctx(t), signed(e.relPriv, "2.0.0", runtime.GOOS, runtime.GOARCH, body), bytes.NewReader(body))
	if err == nil || res == nil || !strings.Contains(res.Error, "no release key") {
		t.Fatalf("res %+v err %v", res, err)
	}
}

func TestAgentSetKeys(t *testing.T) {
	e := startAgent(t, nil)
	c := e.client(t, e.addr, e.node, "")
	k2 := newSigner(t)
	if _, err := c.SetKeys(ctx(t), nil); err == nil {
		t.Fatal("empty list accepted by client")
	}
	if _, err := c.SetKeys(ctx(t), []string{"ssh-ed25519 AAAA\nssh-rsa B"}); err == nil {
		t.Fatal("line break accepted")
	}
	res, err := c.SetKeys(ctx(t), []string{keyLine(e.node) + " node", keyLine(k2) + " cluster"})
	if err != nil || !res.OK || res.Count != 2 {
		t.Fatalf("set 2 keys: %+v %v", res, err)
	}
	// nur noch k2 (die anfragende Node muss nicht enthalten sein)
	if res, err = c.SetKeys(ctx(t), []string{keyLine(k2)}); err != nil || res.Count != 1 {
		t.Fatalf("set k2: %+v %v", res, err)
	}
	if b, _ := os.ReadFile(e.keysFile); strings.TrimSpace(string(b)) != keyLine(k2) {
		t.Fatalf("keys file = %q", b)
	}
	if fi, _ := os.Stat(e.keysFile); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("keys file mode %v", fi.Mode().Perm())
	}
	if _, err := e.client(t, e.addr, e.node, "").Info(ctx(t)); err == nil {
		t.Fatal("removed key still accepted on a new connection")
	}
	if _, err := e.client(t, e.addr, k2, "").Info(ctx(t)); err != nil {
		t.Fatalf("new key refused: %v", err)
	}

	// Server lehnt leere und kaputte Listen ab (direkt, ohne Pruefung im Client)
	cl, err := ssh.Dial("tcp", e.addr, &ssh.ClientConfig{User: "x", Auth: []ssh.AuthMethod{ssh.PublicKeys(k2)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	for name, in := range map[string]string{
		"empty":    "# nur Kommentar\n\n",
		"garbage":  keyLine(k2) + "\nkein schluessel\n",
		"too big":  strings.Repeat("#", m64proto.MaxKeysBytes+10),
		"dsa type": "ssh-dss AAAAB3NzaC1kc3MAAACBAP",
	} {
		s, err := cl.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		s.Stdin = strings.NewReader(in)
		out, err := s.Output("keys")
		if err == nil || !bytes.Contains(out, []byte(`"ok":false`)) {
			t.Errorf("%s: accepted (%s, %v)", name, out, err)
		}
		_ = s.Close()
	}
	if b, _ := os.ReadFile(e.keysFile); strings.TrimSpace(string(b)) != keyLine(k2) {
		t.Fatal("keys file changed by refused request")
	}
}

func TestAgentSizeLimits(t *testing.T) {
	// Agent: zu grosser Report wird nicht geschickt
	e := startAgent(t, nil)
	e.coll.big = true
	c := e.client(t, e.addr, e.node, "")
	_, err := c.Collect(ctx(t))
	var re *RemoteError
	if !errors.As(err, &re) || !strings.Contains(re.Stderr, "too large") {
		t.Fatalf("big report: %v", err)
	}

	// Client: Host schickt mehr als erlaubt
	node := newSigner(t)
	fs := startFakeSSH(t, node.PublicKey(), "", func(cmd string, _ io.Reader, out, _ io.Writer) uint32 {
		n := m64proto.MaxInfoBytes + 1
		if cmd == "collect" {
			n = m64proto.MaxReportBytes + 1
		}
		_, _ = out.Write(bytes.Repeat([]byte("a"), n))
		return 0
	})
	fc := e.client(t, fs.addr, node, "")
	if _, err := fc.Info(ctx(t)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("info limit: %v", err)
	}
	if _, err := fc.Collect(ctx(t)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("collect limit: %v", err)
	}
	// Verbindung bleibt nutzbar
	if _, err := fc.Info(ctx(t)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("after limit: %v", err)
	}
}

func TestAgentTimeout(t *testing.T) {
	node := newSigner(t)
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	fs := startFakeSSH(t, node.PublicKey(), "", func(string, io.Reader, io.Writer, io.Writer) uint32 {
		<-block
		return 0
	})
	c, _ := NewAgentClient(AgentConfig{Addr: fs.addr, Signer: node})
	defer c.Close()
	cx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Info(cx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout not honoured")
	}
}
