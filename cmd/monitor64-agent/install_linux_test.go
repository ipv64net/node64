//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F1-K7: Haertung erlaubt HOME fuer eigene Skripte, /root lesbar, /run nur mit zypper.
func TestUnitText(t *testing.T) {
	u := unitText(6465, false)
	for _, want := range []string{"run --port 6465", "ProtectHome=read-only", "StateDirectory=monitor64-agent",
		"ProtectSystem=strict", "Restart=always", "ReadWritePaths=" + defaultDir + " " + libDir} {
		if !strings.Contains(u, want) {
			t.Errorf("unit misses %q", want)
		}
	}
	if strings.Contains(u, "ProtectHome=yes") || strings.Contains(u, "/run") || strings.Contains(u, "%!") {
		t.Errorf("unit without zypper:\n%s", u)
	}
	if z := unitText(6465, true); !strings.Contains(z, "\nReadWritePaths=/run -/var/log/zypper.log\n") {
		t.Errorf("unit with zypper:\n%s", z)
	}
}

// F1-K5: Probestart der neuen Datei.
func TestProbe(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "agent")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\necho 'monitor64-agent 1.2.3 linux/amd64'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := probe(exe, "1.2.3"); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if err := probe(exe, "v1.2.3"); err != nil {
		t.Fatalf("probe with v: %v", err)
	}
	if err := probe(exe, "1.2.4"); err == nil {
		t.Fatal("wrong version accepted")
	}
	broken := filepath.Join(t.TempDir(), "broken")
	if err := os.WriteFile(broken, []byte("\x7fELFgarbage"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := probe(broken, "1.2.3"); err == nil {
		t.Fatal("broken file accepted")
	}
}
