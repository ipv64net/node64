package m64linux

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Wertet eine echte Ausgabe des SSH-Skripts aus (M64_SCRIPT_OUT=<Datei>), z. B. aus einem Container mit
// installierten Kernel-Paketen, und gibt "Neustart noetig" aus.
func TestRealScriptReboot(t *testing.T) {
	p := os.Getenv("M64_SCRIPT_OUT")
	if p == "" {
		t.Skip("M64_SCRIPT_OUT nicht gesetzt")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseScriptOutput(b, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(r.Reboot)
	t.Logf("Neustart: %s", j)
}
