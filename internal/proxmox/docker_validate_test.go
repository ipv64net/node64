package proxmox

import (
	"context"
	"strings"
	"testing"
)

// Review: Mit ValidateSystem (b1663645) gingen die einzigen Tests der weiter genutzten Pruefungen verloren
// (PROXY64-Docker-Labels, DNS64-Docker, Monitor64-Zugang Docker). Hier wieder ohne ValidateSystem.
func TestDockerRemoteValidate(t *testing.T) {
	user, addr, sock, err := dockerSSHTarget("ssh://admin@10.0.0.5")
	if err != nil || user != "admin" || addr != "10.0.0.5:22" || sock != "/var/run/docker.sock" {
		t.Fatalf("ssh target: %q %q %q %v", user, addr, sock, err)
	}
	if _, addr, sock, _ := dockerSSHTarget("ssh://a@[fd00::1]:2222/run/user/1000/docker.sock"); addr != "[fd00::1]:2222" || sock != "/run/user/1000/docker.sock" {
		t.Fatalf("ssh target v6: %q %q", addr, sock)
	}
	for _, h := range []string{"ssh://10.0.0.5", "ssh://a:pw@10.0.0.5", "ssh://a@", "tcp://a@host:2375", "tcp://fd00::1", "https://fd00::1:2376", "ftp://x", "unix://relative", "tcp://"} {
		if ValidDockerHost(h) {
			t.Errorf("%s gilt als gueltig", h)
		}
	}
	for _, h := range []string{"tcp://[fd00::1]:2375", "https://[fd00::1]:2376", "tcp://10.0.0.5:2375", "http://docker-proxy:2375", "ssh://a@h", "unix:///var/run/docker.sock"} {
		if !ValidDockerHost(h) {
			t.Errorf("%s gilt als ungueltig", h)
		}
	}
	hex := strings.Repeat("0a", 32)
	if p, ok := NormalizeDockerPin(PinBase64(hex)); !ok || p != hex {
		t.Fatalf("pin base64: %q %v", p, ok)
	}
	if p, ok := NormalizeDockerPin(hex); !ok || p != hex {
		t.Fatalf("pin hex: %q %v", p, ok)
	}
	if _, ok := NormalizeDockerPin("SHA256:kaputt"); ok {
		t.Fatal("kaputter pin")
	}
}

func TestDockerPollerError(t *testing.T) {
	f, p, _ := newFakeDocker(t)
	f.set(func(f *fakeDocker) { f.fail = true })
	if s := p.Poll(context.Background()); s.OK || !strings.Contains(s.Error, "boom") || len(s.Resources) != 0 {
		t.Fatalf("fehler: %+v", s)
	}
	bad := NewDockerPoller(nil, System{Kind: KindDocker, Addresses: []string{"ftp://x"}}, nil)
	if s := bad.Poll(context.Background()); s.OK || s.Error == "" {
		t.Fatalf("ungueltiger Host: %+v", s)
	}
}
