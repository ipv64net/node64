//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64agent"
)

// Rueckfall unter Windows mit echten Dateien: die neue Version laeuft und holt beim zweiten Start ohne Bestaetigung
// die alte Datei zurueck - das Ersetzen der laufenden Datei klappt nur ueber den zweiten Namen (keepRunLink).
// Danach startet sie die alte Version (hier im Vordergrund; die scheitert absichtlich an einer unbekannten Option,
// bevor sie einen Port oeffnet).
func TestRollbackWhileRunningWindows(t *testing.T) {
	if testing.Short() {
		t.Skip("baut zwei Programmdateien")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "monitor64-agent.exe")
	build := func(out, version string) {
		cmd := exec.Command("go", "build", "-o", out, "-ldflags", "-X main.Version="+version, ".")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", version, err, b)
		}
	}
	build(exe, "1.3.0")
	build(exe+".old", "1.2.0")
	if err := m64agent.WriteUpdateMarker(exe, "1.2.0", "1.3.0"); err != nil {
		t.Fatal(err)
	}
	// erster Start der neuen Version: zaehlt (und scheitert an der Option, wie ein Absturz vor der Bestaetigung)
	run := func() string {
		cmd := exec.Command(exe, "run", "--unknown-flag")
		b, _ := cmd.CombinedOutput()
		return string(b)
	}
	run()
	if b, err := os.ReadFile(exe + ".update"); err != nil || !strings.Contains(string(b), `"starts":1`) {
		t.Fatalf("Start nicht gezaehlt: %q %v", b, err)
	}
	out := run()
	if !strings.Contains(out, "previous version restored") {
		t.Fatalf("kein Rueckfall:\n%s", out)
	}
	time.Sleep(time.Second) // die alte Version wurde im Vordergrund neu gestartet
	v, err := exec.Command(exe, "version").Output()
	if err != nil || !strings.Contains(string(v), " 1.2.0 ") {
		t.Fatalf("nach dem Rueckfall: %q %v", v, err)
	}
	if b, _ := os.ReadFile(exe + ".failed"); strings.TrimSpace(string(b)) != "1.3.0" {
		t.Fatalf(".failed = %q", b)
	}
}
