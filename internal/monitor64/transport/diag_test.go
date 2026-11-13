package transport

import (
	"errors"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Diagnose fuer "Verbindung testen": nach dem Aufbau stehen die tatsaechlich verbundene Adresse und die Art des
// Hostschluessels bereit.
func TestPeerAfterConnect(t *testing.T) {
	node := newSigner(t)
	fs := startFakeSSH(t, node.PublicKey(), "", echoScript)
	c, err := NewSSHClient(SSHConfig{Addr: fs.addr, User: "monitor64", Signer: node})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if a, k := c.Peer(); a != "" || k != "" {
		t.Fatalf("vor dem Aufbau: %q %q", a, k)
	}
	if _, err := c.Run(ctx(t), "x"); err != nil {
		t.Fatal(err)
	}
	if a, k := c.Peer(); a != fs.addr || k != "ssh-ed25519" {
		t.Fatalf("Gegenstelle %q, Schluesselart %q (erwartet %q, ssh-ed25519)", a, k, fs.addr)
	}
}

// Ein Server, der gar keine Anmeldung per Schluessel anbietet (z. B. ein anderer Dienst unter dem Namen): der
// Fehler ist als ErrNoKeyAuth erkennbar, Gegenstelle und Schluesselart stehen trotzdem bereit.
func TestNoKeyAuthOffered(t *testing.T) {
	hk := newSigner(t)
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, errors.New("no") }}
	cfg.AddHostKey(hk)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if sc, _, _, err := ssh.NewServerConn(nc, cfg); err == nil {
					_ = sc.Close()
				}
				_ = nc.Close()
			}()
		}
	}()
	c, err := NewSSHClient(SSHConfig{Addr: ln.Addr().String(), User: "monitor64", Signer: newSigner(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Run(ctx(t), "x")
	if !errors.Is(err, ErrNoKeyAuth) || !strings.Contains(err.Error(), "attempted methods [none]") {
		t.Fatalf("erwartet ErrNoKeyAuth: %v", err)
	}
	if a, k := c.Peer(); a != ln.Addr().String() || k != "ssh-ed25519" {
		t.Fatalf("Gegenstelle %q, Schluesselart %q", a, k)
	}
	// Zugang mit Passwort an einem Server, der nur Schluessel annimmt: auch "[none]", aber nicht dieser Hinweis
	ko := startFakeSSH(t, newSigner(t).PublicKey(), "", echoScript)
	c3, _ := NewSSHClient(SSHConfig{Addr: ko.addr, User: "monitor64", Password: "geheim", HostKey: Fingerprint(ko.hk.PublicKey())})
	defer c3.Close()
	if _, err := c3.Run(ctx(t), "x"); err == nil || errors.Is(err, ErrNoKeyAuth) || !strings.Contains(err.Error(), "attempted methods [none]") {
		t.Fatalf("Passwort an Server nur mit Schluessel: %v", err)
	}
	// falscher Schluessel an einem Server MIT Schluessel-Anmeldung ist etwas anderes
	fs := startFakeSSH(t, newSigner(t).PublicKey(), "", echoScript)
	c2, _ := NewSSHClient(SSHConfig{Addr: fs.addr, User: "monitor64", Signer: newSigner(t)})
	defer c2.Close()
	if _, err := c2.Run(ctx(t), "x"); err == nil || errors.Is(err, ErrNoKeyAuth) {
		t.Fatalf("falscher Schluessel: %v", err)
	}
}
