//go:build linux

package m64linux

import (
	"os"
	"testing"
)

// Gegen die echte Mount-Tabelle dieses Rechners (wie der Agent: /proc/mounts und statfs). Nur mit M64_REALFS=1,
// z. B. in einem Container mit eingehaengten Testdateisystemen; gibt die gemeldeten Dateisysteme aus.
func TestRealFS(t *testing.T) {
	if os.Getenv("M64_REALFS") == "" {
		t.Skip("M64_REALFS nicht gesetzt")
	}
	b, err := os.ReadFile("/proc/mounts")
	if err != nil {
		t.Fatal(err)
	}
	fsl, errs := FSFromStatfs(ParseMounts(b), statfsPath)
	for _, e := range errs {
		t.Logf("Fehler: %v", e)
	}
	for _, f := range fsl {
		t.Logf("%-32s %-18s %-14s %d MiB", f.Mount, f.Device, f.Type, f.Total>>20)
	}
}
