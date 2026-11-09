//go:build windows

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows/svc/mgr"
)

// testKey liefert einen gueltigen oeffentlichen Schluessel im authorized_keys-Format.
func testKey(t *testing.T, comment string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " " + comment
}

// Nur reine Hilfsfunktionen: install/uninstall, Dienst und Firewall laufen in Tests nie.

func TestCheckInstallArgsWindows(t *testing.T) {
	k := testKey(t, "node64@nas")
	if got, err := checkInstallArgs("  "+k+"\r\n", 6465); err != nil || got != k {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []struct {
		key  string
		port int
	}{{"", 6465}, {"kein schluessel", 6465}, {k + "\n" + k, 6465}, {k, 0}, {k, 70000}} {
		if _, err := checkInstallArgs(bad.key, bad.port); err == nil {
			t.Errorf("%q %d angenommen", bad.key, bad.port)
		}
	}
}

func TestFirewallCmdLines(t *testing.T) {
	del, add := firewallCmdLines(`C:\Windows\System32\netsh.exe`, `C:\Program Files\monitor64-agent\monitor64-agent.exe`, 6465)
	if del != `"C:\Windows\System32\netsh.exe" advfirewall firewall delete rule name="Monitor64-Agent"` {
		t.Errorf("del = %s", del)
	}
	for _, want := range []string{` add rule name="Monitor64-Agent" `, ` dir=in action=allow protocol=TCP localport=6465 `,
		` program="C:\Program Files\monitor64-agent\monitor64-agent.exe" `, ` enable=yes profile=any`} {
		if !strings.Contains(add, want) {
			t.Errorf("add ohne %q: %s", want, add)
		}
	}
}

func TestBinaryPath(t *testing.T) {
	got := binaryPath(`C:\Program Files\monitor64-agent\monitor64-agent.exe`, []string{"run", "--port", "6465"})
	if got != `"C:\Program Files\monitor64-agent\monitor64-agent.exe" run --port 6465` {
		t.Fatal(got)
	}
	ra := recoveryActions()
	if len(ra) != 3 || ra[0].Type != mgr.ServiceRestart || ra[0].Delay != 2*time.Second || ra[2].Delay != 30*time.Second {
		t.Fatalf("%+v", ra)
	}
}

func TestAddKeyWindows(t *testing.T) {
	p := filepath.Join(t.TempDir(), "keys")
	k1, k2 := testKey(t, "node64@nas"), testKey(t, "node64@b")
	if added, err := addKey(p, k1); err != nil || !added {
		t.Fatalf("%v %v", added, err)
	}
	// gleicher Schluessel mit anderem Kommentar bzw. CRLF in der Datei: nicht doppelt
	if err := os.WriteFile(p, []byte(k1+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if added, err := addKey(p, strings.TrimSuffix(k1, " node64@nas")+" anders"); err != nil || added {
		t.Fatalf("doppelt: %v %v", added, err)
	}
	if added, err := addKey(p, k2); err != nil || !added {
		t.Fatalf("%v %v", added, err)
	}
	b, _ := os.ReadFile(p)
	if strings.Count(string(b), "ssh-ed25519") != 2 || strings.Contains(string(b), "\r") {
		t.Fatalf("%q", b)
	}
}

func TestRotLog(t *testing.T) {
	dir := t.TempDir()
	l := &rotLog{path: filepath.Join(dir, "agent.log"), max: 100}
	line := []byte(strings.Repeat("x", 39) + "\n")
	for i := 0; i < 7; i++ {
		if n, err := l.Write(line); n != len(line) || err != nil {
			t.Fatal(n, err)
		}
	}
	l.close()
	cur, _ := os.ReadFile(l.path)
	old, _ := os.ReadFile(l.path + ".1")
	if len(cur) > 100 || len(old) > 100 || len(cur)+len(old) < 80 {
		t.Fatalf("cur %d old %d", len(cur), len(old))
	}
	// neuer Lauf mit voller Datei dreht sofort
	if err := os.WriteFile(l.path, make([]byte, 99), 0o600); err != nil {
		t.Fatal(err)
	}
	l2 := &rotLog{path: l.path, max: 100}
	_, _ = l2.Write(line)
	l2.close()
	if b, _ := os.ReadFile(l.path); len(b) != len(line) {
		t.Fatalf("nach Neustart %d Byte", len(b))
	}
}

func TestKeepRunLinkAndRestart(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "monitor64-agent.exe")
	if err := os.WriteFile(exe, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	keepRunLink(exe)
	keepRunLink(exe) // zweiter Start: alter Verweis wird ersetzt
	fi1, _ := os.Stat(exe)
	fi2, err := os.Stat(exe + ".run")
	if err != nil || !os.SameFile(fi1, fi2) {
		t.Fatalf("run-Verweis: %v", err)
	}
	// als Dienst: Neustart = Ende mit exitRestart (Dienst-Manager startet neu)
	oldExit, oldSvc := exitFn, asService.Load()
	defer func() { exitFn = oldExit; asService.Store(oldSvc) }()
	code := -1
	exitFn = func(c int) { code = c }
	asService.Store(true)
	if err := restartSelf(exe); err != nil || code != exitRestart {
		t.Fatalf("restartSelf: %v code %d", err, code)
	}
}
