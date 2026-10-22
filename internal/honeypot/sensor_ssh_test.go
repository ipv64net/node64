package honeypot

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSensorSSHPassword(t *testing.T) {
	p := sensorFreePort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcSSH, p, ""}}})

	// Banner wie OpenSSH
	c, err := net.Dial("tcp", sensorAddrOf(p))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	line, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if b := strings.TrimSpace(line); !strings.HasPrefix(b, "SSH-2.0-OpenSSH_9.") || (!strings.Contains(b, " Debian-") && !strings.Contains(b, " Ubuntu-")) {
		t.Fatalf("Banner %q", line)
	}

	_, err = ssh.Dial("tcp", sensorAddrOf(p), &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("hunter2")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		ClientVersion:   "SSH-2.0-TestClient_1.0",
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("Login angenommen")
	}
	e := rec.wait(t, sensorKind(KindSSHBrute))
	if e.Username != "root" || e.Password != "hunter2" || e.Client != "SSH-2.0-TestClient_1.0" || e.Service != SvcSSH || e.Port != p {
		t.Fatalf("Ereignis: %+v", e)
	}
	if e.Src.String() != "127.0.0.1" || e.SrcPort == 0 {
		t.Fatalf("Quelle: %v:%d", e.Src, e.SrcPort)
	}
	if s.counters.Logins.Load() < 1 || s.counters.Connections.Load() < 2 {
		t.Fatalf("Zaehler: logins=%d conns=%d", s.counters.Logins.Load(), s.counters.Connections.Load())
	}
	// Banner-Abfrage ohne Anmeldung = Probe
	rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Service == SvcSSH })

	// Host-Schluessel liegt im Datenverzeichnis und wird wiederverwendet
	path := filepath.Join(s.dir, sensorHostKeyFile)
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	s2 := NewSensor(sensorTestLog(), s.dir)
	k1, _ := s.sshSigner()
	k2, err := s2.sshSigner()
	if err != nil || !bytes.Equal(k1.PublicKey().Marshal(), k2.PublicKey().Marshal()) {
		t.Fatalf("Host-Schluessel nicht wiederverwendet: %v", err)
	}
}

func TestSensorSSHPublicKeyAndTries(t *testing.T) {
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcSSH, p, ""}}})
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	_, err := ssh.Dial("tcp", sensorAddrOf(p), &ssh.ClientConfig{
		User:            "admin",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("Login angenommen")
	}
	e := rec.wait(t, sensorKind(KindSSHBrute))
	if e.Username != "admin" || e.Detail != ssh.FingerprintSHA256(signer.PublicKey()) || e.Password != "" {
		t.Fatalf("Ereignis: %+v", e)
	}

	// viele Passwoerter auf einer Verbindung: nach sensorSSHTries getrennt
	n := 0
	_, err = ssh.Dial("tcp", sensorAddrOf(p), &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
			n++
			return "pw", nil
		}), 20)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("Login angenommen")
	}
	isPW := func(e Event) bool { return e.Kind == KindSSHBrute && e.Password == "pw" }
	rec.wait(t, isPW)
	time.Sleep(200 * time.Millisecond)
	if got := rec.count(isPW); got != sensorSSHTries || n > sensorSSHTries {
		t.Fatalf("Versuche: %d Ereignisse, %d gesendet", got, n)
	}

	// Keyboard-Interactive
	_, _ = ssh.Dial("tcp", sensorAddrOf(p), &ssh.ClientConfig{
		User: "pi",
		Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(name, instr string, q []string, echo []bool) ([]string, error) {
			return []string{"raspberry"}, nil
		})},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	rec.wait(t, func(e Event) bool { return e.Kind == KindSSHBrute && e.Username == "pi" && e.Password == "raspberry" })
}
