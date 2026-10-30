package proxmox

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshDocker ist ein SSH-Server, der direct-streamlocal zum Socket /var/run/docker.sock an eine Docker-API weiterreicht.
func sshDocker(t *testing.T, api http.Handler, user string, allowed ssh.PublicKey) (addr string, hostKey ssh.PublicKey) {
	on := new(atomic.Bool)
	on.Store(true)
	return sshDockerMode(t, api, user, allowed, on, false)
}

// sshDockerMode: stream = Socket-Weiterleitung erlaubt (sonst „open failed“ wie bei AllowTcpForwarding no), stdio =
// docker-CLI vorhanden (exec „docker system dial-stdio“, sonst „not found“ mit Exit 127).
// Der Server hat wie OpenSSH auch einen ECDSA-Host-Key; hostKey ist der Ed25519-Key (den der Client nehmen soll).
func sshDockerMode(t *testing.T, api http.Handler, user string, allowed ssh.PublicKey, stream *atomic.Bool, stdio bool) (addr string, hostKey ssh.PublicKey) {
	t.Helper()
	backend := httptest.NewServer(api)
	t.Cleanup(backend.Close)
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(hk)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if c.User() == user && bytes.Equal(k.Marshal(), allowed.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(signer)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if es, err := ssh.NewSignerFromKey(ek); err == nil {
		cfg.AddHostKey(es)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					conn.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					if nc.ChannelType() == "session" {
						go sshDockerSession(nc, backend.Listener.Addr().String(), stdio)
						continue
					}
					var p struct {
						Path string
						R0   string
						R1   uint32
					}
					if nc.ChannelType() != "direct-streamlocal@openssh.com" || ssh.Unmarshal(nc.ExtraData(), &p) != nil {
						_ = nc.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					if !stream.Load() {
						_ = nc.Reject(ssh.ConnectionFailed, "open failed")
						continue
					}
					if p.Path != "/var/run/docker.sock" {
						_ = nc.Reject(ssh.ConnectionFailed, "connect failed")
						continue
					}
					ch, creqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go ssh.DiscardRequests(creqs)
					be, err := net.Dial("tcp", backend.Listener.Addr().String())
					if err != nil {
						ch.Close()
						continue
					}
					go func() { _, _ = io.Copy(ch, be); ch.Close() }()
					go func() { _, _ = io.Copy(be, ch); be.Close() }()
				}
			}()
		}
	}()
	return ln.Addr().String(), signer.PublicKey()
}

// sshDockerSession fuehrt exec „docker system dial-stdio“ aus: Ein- und Ausgabe gehen an die Docker-API.
func sshDockerSession(nc ssh.NewChannel, backend string, stdio bool) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	exit := func(code uint32) {
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{code}))
		ch.Close()
	}
	for req := range reqs {
		var ex struct{ Command string }
		if req.Type != "exec" || ssh.Unmarshal(req.Payload, &ex) != nil {
			_ = req.Reply(false, nil)
			continue
		}
		_ = req.Reply(true, nil)
		if !stdio || !strings.HasSuffix(ex.Command, "system dial-stdio") {
			_, _ = ch.Stderr().Write([]byte("sh: docker: not found\n"))
			exit(127)
			return
		}
		be, err := net.Dial("tcp", backend)
		if err != nil {
			exit(1)
			return
		}
		go func() { _, _ = io.Copy(be, ch); be.Close() }()
		_, _ = io.Copy(ch, be)
		exit(0)
		return
	}
}

// Ohne Socket-Weiterleitung (AllowTcpForwarding no, restrict): ueber docker system dial-stdio wie der Docker-Client.
func TestDockerSSHStdio(t *testing.T) {
	f, _, _ := newFakeDocker(t)
	f.list = []map[string]any{dkEntry("a1", "web", "running", "Up 1 hour", nil)}
	key, _ := GenerateDockerSSHKey()
	signer, _ := ssh.ParsePrivateKey([]byte(key))
	ctx := context.Background()
	off := new(atomic.Bool)
	addr, hostKey := sshDockerMode(t, f, "node64", signer.PublicKey(), off, true)
	sys := System{Kind: KindDocker, Name: "stdio", Addresses: []string{"ssh://node64@" + addr}, Secret: DockerCreds{Key: key}.Encode(),
		PinSHA256: SSHFingerprint(hostKey), Interval: 30}
	if res := DockerProbe(ctx, sys); !res.OK || res.Containers != 1 || res.Info == nil || res.Info.Name != "dockerhost" {
		t.Fatalf("dial-stdio: %+v", res)
	}
	p := NewDockerPoller(nil, sys, nil)
	for i := 0; i < 3; i++ { // mehrere Abfragen ueber dieselbe SSH-Verbindung
		if s := p.Poll(ctx); !s.OK || len(s.Resources) != 1 {
			t.Fatalf("poll %d: %+v", i, s)
		}
	}
	p.close()
	// weder Weiterleitung noch docker-CLI: verstaendlicher Fehler
	streamOK := new(atomic.Bool)
	addr, hostKey = sshDockerMode(t, f, "node64", signer.PublicKey(), streamOK, false)
	sys.Addresses, sys.PinSHA256 = []string{"ssh://node64@" + addr}, SSHFingerprint(hostKey)
	if res := DockerProbe(ctx, sys); res.OK || !strings.Contains(res.Error, "not found") || !strings.Contains(res.Error, "docker CLI is missing") {
		t.Fatalf("ohne docker-cli: %+v", res)
	}
	// dial-stdio gescheitert (keine CLI): sobald die Weiterleitung wieder geht (Socket war kurz weg), laeuft es wieder
	p = NewDockerPoller(nil, sys, nil)
	if s := p.Poll(ctx); s.OK {
		t.Fatal("ohne weiterleitung und cli ok")
	}
	streamOK.Store(true)
	if s := p.Poll(ctx); !s.OK || len(s.Resources) != 1 {
		t.Fatalf("weiterleitung wieder da: %+v", s)
	}
	p.close()
	if _, _, _, err := dockerSSHTarget("ssh://a@h/var/run/x';rm -rf /"); err == nil {
		t.Fatal("socket-pfad mit Sonderzeichen")
	}
}

func TestDockerSSH(t *testing.T) {
	f, _, _ := newFakeDocker(t)
	f.list = []map[string]any{dkEntry("a1", "web", "running", "Up 1 hour", nil), dkEntry("b1", "db", "exited", "Exited (0) 1 hour ago", nil)}
	key, err := GenerateDockerSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.ParsePrivateKey([]byte(key))
	addr, hostKey := sshDocker(t, f, "node64", signer.PublicKey())
	if pub := DockerSSHPublicKey(key); !strings.HasPrefix(pub, "ssh-ed25519 ") || !strings.HasSuffix(pub, " node64") {
		t.Fatalf("public key: %q", pub)
	}
	sys := System{Kind: KindDocker, Name: "remote", Addresses: []string{"ssh://node64@" + addr}, Secret: DockerCreds{Key: key}.Encode(), Interval: 30}
	ctx := context.Background()

	// ohne Pin: nur der Fingerabdruck, der Schluessel wird nicht benutzt
	res := DockerProbe(ctx, sys)
	if res.OK || !res.NeedConfirm || res.Fingerprint != SSHFingerprint(hostKey) || res.Error != "" {
		t.Fatalf("probe ohne pin: %+v", res)
	}
	if ValidateSystem(&System{Kind: KindDocker, Addresses: sys.Addresses, Secret: sys.Secret}, true) == nil {
		t.Fatal("ssh ohne Pin gespeichert")
	}
	// mit Pin (auch im Format von ssh-keygen)
	sys.PinSHA256 = PinBase64(res.Fingerprint)
	res = DockerProbe(ctx, sys)
	if !res.OK || res.Containers != 2 || res.Running != 1 || res.Info == nil || res.Info.Name != "dockerhost" || res.Info.Version != "27.3.1" {
		t.Fatalf("probe mit pin: %+v", res)
	}
	// Abfrage ueber SSH, eine Verbindung fuer alle Anfragen
	p := NewDockerPoller(nil, sys, nil)
	s := p.Poll(ctx)
	if !s.OK || len(s.Resources) != 2 || s.Docker == nil || s.Docker.NCPU != 4 {
		t.Fatalf("poll: %+v", s)
	}
	if hc, base := p.Client(); hc == nil || base != "http://docker" || p.Host() != sys.Addresses[0] {
		t.Fatalf("client: %v %q %q", hc, base, p.Host())
	}
	p.close()
	// falscher Pin, fremder Schluessel, falscher Socket
	bad := sys
	bad.PinSHA256 = strings.Repeat("ab", 32)
	if res := DockerProbe(ctx, bad); res.OK || !strings.Contains(res.Error, "does not match") {
		t.Fatalf("falscher pin: %+v", res)
	}
	other, _ := GenerateDockerSSHKey()
	bad = sys
	bad.Secret = DockerCreds{Key: other}.Encode()
	if res := DockerProbe(ctx, bad); res.OK || !strings.Contains(res.Error, "authorized_keys") {
		t.Fatalf("fremder schluessel: %+v", res)
	}
	bad = sys
	bad.Addresses = []string{"ssh://node64@" + addr + "/run/other.sock"}
	if res := DockerProbe(ctx, bad); res.OK || !strings.Contains(res.Error, "dial-stdio") { // Weiterleitung abgelehnt: docker-CLI versucht
		t.Fatalf("falscher socket: %+v", res)
	}
}

// dkCert erzeugt ein selbst signiertes Client-Zertifikat (PEM).
func dkCert(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "node64"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}))
}

func TestDockerTLS(t *testing.T) {
	f, _, _ := newFakeDocker(t)
	f.list = []map[string]any{dkEntry("a1", "web", "running", "Up 1 hour", nil)}
	srv := httptest.NewUnstartedServer(f)
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	cert, key := dkCert(t)
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	sys := System{Kind: KindDocker, Name: "tls", Addresses: []string{srv.URL}, Secret: DockerCreds{Cert: cert, Key: key}.Encode(), Interval: 30}
	ctx := context.Background()
	res := DockerProbe(ctx, sys)
	if res.OK || !res.NeedConfirm || res.Fingerprint != CertFingerprint(srv.Certificate().Raw) || res.Trusted {
		t.Fatalf("probe ohne ca/pin: %+v", res)
	}
	pinned := sys
	pinned.PinSHA256 = res.Fingerprint
	if res := DockerProbe(ctx, pinned); !res.OK || res.Containers != 1 {
		t.Fatalf("probe mit pin: %+v", res)
	}
	withCA := sys
	withCA.Secret = DockerCreds{Cert: cert, Key: key, CA: ca}.Encode()
	if res := DockerProbe(ctx, withCA); !res.OK || !res.Trusted {
		t.Fatalf("probe mit ca: %+v", res)
	}
	noCert := pinned
	noCert.Secret = ""
	if res := DockerProbe(ctx, noCert); res.OK {
		t.Fatalf("ohne client-zertifikat: %+v", res)
	}
	if err := ValidateSystem(&System{Kind: KindDocker, Addresses: sys.Addresses, Secret: DockerCreds{Cert: cert}.Encode()}, true); err == nil {
		t.Fatal("zertifikat ohne schluessel")
	}
}

func TestDockerRemoteValidate(t *testing.T) {
	user, addr, sock, err := dockerSSHTarget("ssh://admin@10.0.0.5")
	if err != nil || user != "admin" || addr != "10.0.0.5:22" || sock != "/var/run/docker.sock" {
		t.Fatalf("ssh target: %q %q %q %v", user, addr, sock, err)
	}
	if _, addr, sock, _ := dockerSSHTarget("ssh://a@[fd00::1]:2222/run/user/1000/docker.sock"); addr != "[fd00::1]:2222" || sock != "/run/user/1000/docker.sock" {
		t.Fatalf("ssh target v6: %q %q", addr, sock)
	}
	for _, h := range []string{"ssh://10.0.0.5", "ssh://a:pw@10.0.0.5", "ssh://a@", "tcp://a@host:2375", "tcp://fd00::1", "https://fd00::1:2376"} {
		if ValidDockerHost(h) {
			t.Errorf("%s gilt als gueltig", h)
		}
	}
	for _, h := range []string{"tcp://[fd00::1]:2375", "https://[fd00::1]:2376", "tcp://10.0.0.5:2375", "http://docker-proxy:2375"} {
		if !ValidDockerHost(h) {
			t.Errorf("%s gilt als ungueltig", h)
		}
	}
	hex := strings.Repeat("0a", 32)
	if p, ok := NormalizeDockerPin(PinBase64(hex)); !ok || p != hex {
		t.Fatalf("pin base64: %q %v", p, ok)
	}
	if _, ok := NormalizeDockerPin("SHA256:kaputt"); ok {
		t.Fatal("kaputter pin")
	}
	key, _ := GenerateDockerSSHKey()
	sys := &System{Kind: KindDocker, Addresses: []string{"ssh://a@h"}, PinSHA256: PinBase64(hex)}
	if err := ValidateSystem(sys, true); err == nil {
		t.Fatal("ssh ohne schluessel")
	}
	sys.Secret = DockerCreds{Key: key}.Encode()
	if err := ValidateSystem(sys, true); err != nil || sys.PinSHA256 != hex {
		t.Fatalf("ssh: %v %q", err, sys.PinSHA256)
	}
	sys = &System{Kind: KindDocker, Addresses: []string{"tcp://h:2375"}, Secret: "x", PinSHA256: hex}
	if err := ValidateSystem(sys, true); err != nil || sys.Secret != "" || sys.PinSHA256 != "" {
		t.Fatalf("tcp: %v %+v", err, sys)
	}
}

func TestStoreDockerSecret(t *testing.T) {
	ctx := context.Background()
	s, core := pveTestStore(t)
	key, _ := GenerateDockerSSHKey()
	pin := strings.Repeat("0b", 32)
	sys := &System{Kind: KindDocker, Name: "r", Addresses: []string{"ssh://a@h"}, PinSHA256: pin, Secret: DockerCreds{Key: key}.Encode(), Enabled: true}
	if err := NewStore(core, nil).SaveSystem(ctx, sys); !errors.Is(err, ErrNoBox) {
		t.Fatalf("ohne box: %v", err)
	}
	if err := s.SaveSystem(ctx, sys); err != nil {
		t.Fatal(err)
	}
	got, _ := s.System(ctx, sys.ID)
	if ParseDockerCreds(got.Secret).Key != key || got.PinSHA256 != pin {
		t.Fatalf("gespeichert: %+v", got)
	}
	var raw string
	_ = core.Reader().QueryRowContext(ctx, `SELECT secret FROM pve_systems WHERE id = ?`, sys.ID).Scan(&raw)
	if strings.Contains(raw, "PRIVATE KEY") {
		t.Fatal("schluessel unverschluesselt")
	}
	got.Secret, got.Name = "", "r2" // leer = behalten
	if err := s.SaveSystem(ctx, got); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.System(ctx, sys.ID); ParseDockerCreds(got.Secret).Key != key || got.Name != "r2" {
		t.Fatalf("behalten: %+v", got)
	}
	if err := s.SaveSystem(ctx, &System{ID: got.ID, Kind: KindDocker, Name: "r2", Addresses: []string{"ssh://a@h"}, PinSHA256: pin, Secret: DockerNoCreds}); err == nil {
		t.Fatal("ssh ohne schluessel per DockerNoCreds gespeichert")
	}
	tlsSys := &System{ID: got.ID, Kind: KindDocker, Name: "r2", Addresses: []string{"https://h:2376"}, Secret: DockerNoCreds}
	if err := s.SaveSystem(ctx, tlsSys); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.System(ctx, sys.ID); got.Secret != "" {
		t.Fatal("DockerNoCreds hat das Secret nicht geloescht")
	}
	got.Addresses, got.Secret = []string{"tcp://h:2375"}, ""
	if err := s.SaveSystem(ctx, got); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.System(ctx, sys.ID); got.Secret != "" || got.PinSHA256 != "" {
		t.Fatalf("tcp loescht zugangsdaten: %+v", got)
	}
}
