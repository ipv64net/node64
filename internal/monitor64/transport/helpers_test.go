package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func keyLine(s ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

// proxy leitet TCP an ein austauschbares Ziel weiter (Wechsel des Agents, Abbruch aller Verbindungen).
type proxy struct {
	ln      net.Listener
	target  atomic.Value // string
	accepts atomic.Int32
	mu      sync.Mutex
	conns   []net.Conn
}

func newProxy(t *testing.T, target string) *proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{ln: ln}
	p.target.Store(target)
	t.Cleanup(func() { _ = ln.Close(); p.dropAll() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.accepts.Add(1)
			u, err := net.Dial("tcp", p.target.Load().(string))
			if err != nil {
				_ = c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, u)
			p.mu.Unlock()
			go func() { _, _ = io.Copy(u, c); _ = u.Close() }()
			go func() { _, _ = io.Copy(c, u); _ = c.Close() }()
		}
	}()
	return p
}

func (p *proxy) addr() string { return p.ln.Addr().String() }

func (p *proxy) dropAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
}

// fakePwTries zaehlt die Passwort-Anmeldungen, die bei einem fakeSSH ankamen.
var fakePwTries atomic.Int32

// fakeSSH ist ein kleiner SSH-Server fuer Tests des SSHClient und der Groessengrenzen.
type fakeSSH struct {
	addr string
	ln   net.Listener
	hk   ssh.Signer
}

type fakeHandler func(cmd string, stdin io.Reader, stdout, stderr io.Writer) uint32

func startFakeSSH(t *testing.T, allowed ssh.PublicKey, password string, h fakeHandler) *fakeSSH {
	t.Helper()
	hk := newSigner(t)
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if allowed != nil && string(k.Marshal()) == string(allowed.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("no")
		},
	}
	if password != "" {
		cfg.PasswordCallback = func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			fakePwTries.Add(1)
			if string(pw) == password {
				return nil, nil
			}
			return nil, errors.New("no")
		}
	}
	cfg.AddHostKey(hk)
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
			go serveFake(c, cfg, h)
		}
	}()
	return &fakeSSH{addr: ln.Addr().String(), ln: ln, hk: hk}
}

func serveFake(c net.Conn, cfg *ssh.ServerConfig, h fakeHandler) {
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		_ = c.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, rq, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range rq {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				var p struct{ Cmd string }
				_ = ssh.Unmarshal(req.Payload, &p)
				_ = req.Reply(true, nil)
				code := h(p.Cmd, ch, ch, ch.Stderr())
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{code}))
				return
			}
		}()
	}
}

func writeFile(t *testing.T, p string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
}
