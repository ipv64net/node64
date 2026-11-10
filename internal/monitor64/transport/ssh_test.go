package transport

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ipv64net/node64/internal/m64proto"
)

// echoScript antwortet mit Befehl und Skript; "exit 3" im Skript liefert Status 3, "BIG" zu viel Ausgabe.
func echoScript(cmd string, in io.Reader, out, errw io.Writer) uint32 {
	script, _ := io.ReadAll(in)
	if bytes.Contains(script, []byte("BIG")) {
		_, _ = out.Write(bytes.Repeat([]byte("x"), m64proto.MaxReportBytes+1))
		return 0
	}
	fmt.Fprintf(out, "cmd=%s\n%s", cmd, script)
	if bytes.Contains(script, []byte("exit 3")) {
		fmt.Fprint(errw, "boom\x1b[31m")
		return 3
	}
	return 0
}

func TestSSHClientRun(t *testing.T) {
	node := newSigner(t)
	fs := startFakeSSH(t, node.PublicKey(), "", echoScript)
	c, err := NewSSHClient(SSHConfig{Addr: fs.addr, User: "monitor64", Signer: node})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	out, err := c.Run(ctx(t), "echo hello\n", "smart", "updates")
	if err != nil || string(out) != "cmd=sh -s -- smart updates\necho hello\n" {
		t.Fatalf("out %q err %v", out, err)
	}
	if c.HostKey() != Fingerprint(fs.hk.PublicKey()) {
		t.Fatal("TOFU fingerprint missing")
	}
	out, err = c.Run(ctx(t), "x")
	if err != nil || !strings.HasPrefix(string(out), "cmd=sh -s\n") {
		t.Fatalf("no args: %q %v", out, err)
	}
	for _, bad := range []string{"; rm -rf /", "smart;id", "$(id)", "--", "-c"} {
		if _, err := c.Run(ctx(t), "x", bad); err == nil {
			t.Errorf("arg %q accepted", bad)
		}
	}
	out, err = c.Run(ctx(t), "exit 3")
	var re *RemoteError
	if !errors.As(err, &re) || re.Status != 3 || re.Stderr != "boom [31m" || !strings.Contains(string(out), "exit 3") {
		t.Fatalf("exit status: %q %v", out, err)
	}
	if _, err := c.Run(ctx(t), "BIG"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("limit: %v", err)
	}
}

func TestSSHClientPassword(t *testing.T) {
	fs := startFakeSSH(t, nil, "geheim", echoScript)
	fp := Fingerprint(fs.hk.PublicKey())
	// ohne bestaetigten Hostschluessel: Abbruch vor der Anmeldung, das Passwort kommt nie beim Server an, nichts
	// wird gemerkt
	before := fakePwTries.Load()
	learned := ""
	un, err := NewSSHClient(SSHConfig{Addr: fs.addr, User: "root", Password: "geheim", OnHostKey: func(s string) { learned = s }})
	if err != nil {
		t.Fatal(err)
	}
	defer un.Close()
	_, err = un.Run(ctx(t), "x")
	var uk *UnconfirmedKeyError
	if !errors.As(err, &uk) || !errors.Is(err, ErrHostKeyUnconfirmed) || uk.Got != fp {
		t.Fatalf("unconfirmed key: %v", err)
	}
	if n := fakePwTries.Load() - before; n != 0 || learned != "" || un.HostKey() != "" {
		t.Fatalf("password sent to unconfirmed host: tries=%d learned=%q", n, learned)
	}
	// bestaetigt: Anmeldung mit Passwort
	c, err := NewSSHClient(SSHConfig{Addr: fs.addr, User: "root", Password: "geheim", HostKey: fp})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Run(ctx(t), "x"); err != nil {
		t.Fatal(err)
	}
	if fakePwTries.Load() == before {
		t.Fatal("no password login after confirmation")
	}
	bad, _ := NewSSHClient(SSHConfig{Addr: fs.addr, User: "root", Password: "falsch", HostKey: fp})
	defer bad.Close()
	if _, err := bad.Run(ctx(t), "x"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err := NewSSHClient(SSHConfig{Addr: fs.addr, User: "root"}); err == nil {
		t.Fatal("client without key and password")
	}
}

func TestSSHClientHostKeyChanged(t *testing.T) {
	node := newSigner(t)
	fs1 := startFakeSSH(t, node.PublicKey(), "", echoScript)
	fs2 := startFakeSSH(t, node.PublicKey(), "", echoScript)
	c, _ := NewSSHClient(SSHConfig{Addr: fs2.addr, User: "u", Signer: node, HostKey: Fingerprint(fs1.hk.PublicKey())})
	defer c.Close()
	if _, err := c.Run(ctx(t), "x"); !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("err = %v", err)
	}
}

func TestPool(t *testing.T) {
	node := newSigner(t)
	fs := startFakeSSH(t, node.PublicKey(), "", echoScript)
	p := NewPool(time.Hour)
	defer p.Close()
	a1, err := p.Agent("h1", AgentConfig{Addr: "127.0.0.1:1", Signer: node})
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := p.Agent("h1", AgentConfig{Addr: "127.0.0.1:1", Signer: node})
	if a1 != a2 {
		t.Fatal("same config must give the same client")
	}
	a3, _ := p.Agent("h1", AgentConfig{Addr: "127.0.0.1:2", Signer: node})
	if a3 == a1 {
		t.Fatal("changed address must replace the client")
	}
	if _, err := a1.Info(ctx(t)); !errors.Is(err, ErrClosed) {
		t.Fatalf("replaced client must be closed: %v", err)
	}

	// TOFU: gelernter Fingerabdruck haelt den Client
	s1, _ := p.SSH("h2", SSHConfig{Addr: fs.addr, User: "u", Signer: node})
	if _, err := s1.Run(ctx(t), "x"); err != nil {
		t.Fatal(err)
	}
	s2, _ := p.SSH("h2", SSHConfig{Addr: fs.addr, User: "u", Signer: node, HostKey: s1.HostKey()})
	if s1 != s2 {
		t.Fatal("learned host key must keep the client")
	}
	s3, _ := p.SSH("h2", SSHConfig{Addr: fs.addr, User: "u", Signer: node, HostKey: "SHA256:other"})
	if s3 == s1 {
		t.Fatal("new host key must replace the client")
	}
	if p.Len() != 2 {
		t.Fatalf("len = %d", p.Len())
	}
	p.Remove("h1")
	if p.Len() != 1 {
		t.Fatal("remove failed")
	}
	p.Close()
	if _, err := p.Agent("h3", AgentConfig{Addr: "x", Signer: node}); !errors.Is(err, ErrClosed) {
		t.Fatal("closed pool must refuse")
	}
}

func TestPoolForget(t *testing.T) {
	p := NewPool(100 * time.Millisecond)
	defer p.Close()
	node := newSigner(t)
	if _, err := p.Agent("h", AgentConfig{Addr: "127.0.0.1:1", Signer: node}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for p.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if p.Len() != 0 {
		t.Fatal("unused client not removed")
	}
}

func TestKeyHelpers(t *testing.T) {
	priv, signer, err := GenerateKey(`node64@"nas" $(id)`)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := ParseKey(priv)
	if err != nil || Fingerprint(s2.PublicKey()) != Fingerprint(signer.PublicKey()) {
		t.Fatalf("parse back: %v", err)
	}
	if !bytes.Contains(priv, []byte("OPENSSH PRIVATE KEY")) {
		t.Fatal("not OpenSSH format")
	}
	line := AuthorizedKeyLine(signer.PublicKey(), `node64@"nas" $(id)`)
	pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || Fingerprint(pub) != Fingerprint(signer.PublicKey()) || comment != "node64@nas_(id)" {
		t.Fatalf("line %q comment %q err %v", line, comment, err)
	}
	if !strings.HasPrefix(line, "ssh-ed25519 ") {
		t.Fatalf("line = %q", line)
	}
	fp := Fingerprint(signer.PublicKey())
	for _, in := range []string{fp, strings.TrimPrefix(fp, "SHA256:"), " sha256:" + strings.TrimPrefix(fp, "SHA256:") + "= "} {
		if NormalizeFingerprint(in) != fp {
			t.Errorf("normalize %q = %q", in, NormalizeFingerprint(in))
		}
	}
	if NormalizeFingerprint("") != "" {
		t.Error("empty must stay empty")
	}
}
