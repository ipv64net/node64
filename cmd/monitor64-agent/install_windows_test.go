//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc/mgr"
)

// Nur reine Hilfsfunktionen: install/uninstall, Dienst und Firewall laufen in Tests nie.

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
