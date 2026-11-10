//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64agent"
)

// Anzeige des Symbols: Zustand des Dienstes, letzte Abfrage, Update verfuegbar - deutsch und englisch.
func TestTrayLines(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	v := trayView{Version: "0.3.0", Installed: true, Running: true, Started: now.Add(-2 * time.Hour).Unix(), LastReq: now.Add(-42 * time.Second).Unix()}
	tip, lines := trayLines(v, true, now)
	if tip != "Monitor64-Agent 0.3.0 – läuft" || len(lines) != 4 || lines[0] != "Monitor64-Agent 0.3.0" ||
		!strings.HasPrefix(lines[1], "Dienst läuft seit ") || lines[2] != "Letzte Abfrage durch die Node: vor 42 s" ||
		lines[3] != "Update: noch keine Angabe der Node" {
		t.Fatalf("laeuft: %q %q", tip, lines)
	}
	v.Latest = "0.4.0"
	tip, lines = trayLines(v, true, now)
	if tip != "Monitor64-Agent 0.3.0 – läuft – Update verfügbar: 0.4.0" || lines[3] != "Update verfügbar: 0.4.0 – Einspielen über Node64" {
		t.Fatalf("update: %q %q", tip, lines)
	}
	tip, lines = trayLines(v, false, now)
	if tip != "Monitor64-Agent 0.3.0 – running – update available: 0.4.0" || lines[2] != "Last poll by the node: 42 s ago" ||
		lines[3] != "Update available: 0.4.0 – installed via Node64" {
		t.Fatalf("englisch: %q %q", tip, lines)
	}
	v.Latest = "0.3.0"
	if _, lines = trayLines(v, true, now); lines[3] != "Update: aktuell" {
		t.Fatalf("aktuell: %q", lines)
	}
	v.Latest, v.LastReq = "v0.2.9", 0 // aeltere Angabe der Node ist kein Update
	if tip, lines = trayLines(v, true, now); lines[2] != "Noch keine Abfrage durch die Node" || lines[3] != "Update: aktuell" || strings.Contains(tip, "Update") {
		t.Fatalf("aelter: %q %q", tip, lines)
	}
	// Dienst steht bzw. fehlt: keine Zeile zur letzten Abfrage
	if tip, lines = trayLines(trayView{Version: "0.3.0", Installed: true}, true, now); tip != "Monitor64-Agent 0.3.0 – läuft nicht" || lines[1] != "Dienst läuft nicht" || len(lines) != 3 {
		t.Fatalf("gestoppt: %q %q", tip, lines)
	}
	if tip, lines = trayLines(trayView{Version: "dev"}, false, now); tip != "Monitor64-Agent dev – not installed" || lines[1] != "Service is not installed" {
		t.Fatalf("fehlt: %q %q", tip, lines)
	}
	for d, want := range map[time.Duration]string{5 * time.Second: "vor 5 s", 3 * time.Minute: "vor 3 min", 5 * time.Hour: "vor 5 h", -time.Second: "vor 0 s"} {
		if got := trayAgo(d, true); got != want {
			t.Errorf("trayAgo(%v) = %q", d, got)
		}
	}
}

func TestNewerVersion(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"0.4.0", "0.3.0", true}, {"0.3.0", "0.3.0", false}, {"0.3.0", "0.4.0", false}, {"v1.0.0", "0.9.9", true},
		{"0.10.0", "0.9.0", true}, {"1.0", "1.0.0", false}, {"1.0.1", "1.0", true}, {"0.4.0-rc1", "0.3.0", true},
		{"0.4.0", "dev", false}, {"dev", "0.4.0", false}, {"", "0.1.0", false},
	} {
		if got := newerVersion(c.a, c.b); got != c.want {
			t.Errorf("newerVersion(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

// Stand des Dienstes: nie halb geschrieben, unlesbare Datei gilt als "kein Stand".
func TestStatusFile(t *testing.T) {
	dir := t.TempDir()
	p := statusPath(filepath.Join(dir, "monitor64-agent.exe"))
	if _, ok := readStatus(p); ok {
		t.Fatal("status without file")
	}
	st := m64agent.Status{Version: "0.3.0", PID: 4711, Started: 100, LastRequest: 200, Latest: "0.4.0", LatestAt: 150}
	if err := writeStatus(p, st); err != nil {
		t.Fatal(err)
	}
	if got, ok := readStatus(p); !ok || got != st {
		t.Fatalf("read back: %+v %v", got, ok)
	}
	if _, err := os.Stat(p + ".tmp"); err == nil {
		t.Fatal("temporary file left behind")
	}
	if err := os.WriteFile(p, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := readStatus(p); ok {
		t.Fatal("broken file accepted")
	}
}
