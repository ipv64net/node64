//go:build linux

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// F1-K7: Haertung erlaubt HOME fuer eigene Skripte, /root lesbar, /run nur mit zypper.
func TestUnitText(t *testing.T) {
	u := unitText(6465, false)
	// Issue #96: ein systemweit gesetztes GODEBUG (UGOS) darf den Agent nicht am Start hindern
	if !strings.Contains(u, "\nUnsetEnvironment=GODEBUG\n") {
		t.Error("Unit ohne UnsetEnvironment=GODEBUG")
	}
	for _, want := range []string{"run --port 6465", "ProtectHome=read-only", "StateDirectory=monitor64-agent",
		"ProtectSystem=strict", "Restart=always", "ReadWritePaths=" + defaultDir + " " + libDir} {
		if !strings.Contains(u, want) {
			t.Errorf("unit misses %q", want)
		}
	}
	if strings.Contains(u, "ProtectHome=yes") || strings.Contains(u, "/run") || strings.Contains(u, "%!") {
		t.Errorf("unit without zypper:\n%s", u)
	}
	// #158: ProtectKernelModules=yes versteckt /lib/modules ("Neustart noetig"); Module laden bleibt gesperrt
	if strings.Contains(u, "ProtectKernelModules") || !strings.Contains(u, "\nCapabilityBoundingSet=~CAP_SYS_MODULE\n") ||
		!strings.Contains(u, "\nSystemCallFilter=~@module\n") {
		t.Errorf("Kernel-Module:\n%s", u)
	}
	if z := unitText(6465, true); !strings.Contains(z, "\nReadWritePaths=/run -/var/log/zypper.log\n") {
		t.Errorf("unit with zypper:\n%s", z)
	}
}

// Forum 5205: Raspberry Pi OS 32 Bit mit 64-Bit-Kernel - systemd (armhf) beendete die arm64-Datei bei
// SystemCallArchitectures=native sofort (status=31/SYS). Die Architektur der Datei ist zusaetzlich erlaubt.
func TestUnitSyscallArch5205(t *testing.T) {
	u := unitText(6465, false)
	if !strings.Contains(u, "\nSystemCallArchitectures=native"+sysArch(runtime.GOARCH)+"\n") {
		t.Errorf("SystemCallArchitectures:\n%s", u)
	}
	for goarch, want := range map[string]string{"arm64": " arm64", "arm": " arm", "amd64": " x86-64", "386": " x86", "mips": ""} {
		if got := sysArch(goarch); got != want {
			t.Errorf("%s: %q, erwartet %q", goarch, got, want)
		}
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

// #169: dnf schreibt Logs unter /var/log - die vorhandenen Dateien sind freigegeben (mit "-": fehlen sie, startet der
// Dienst trotzdem); der Agent laesst dnf ausserdem in den eigenen Ordner loggen (wirkt ohne neue Unit).
func TestUnitTextDnfLogs169(t *testing.T) {
	u := unitText(6465, false)
	for _, f := range []string{"dnf.log", "dnf.librepo.log", "dnf.rpm.log", "hawkey.log", "dnf5.log"} {
		if !strings.Contains(u, " -/var/log/"+f) && !strings.Contains(u, "=-/var/log/"+f) {
			t.Errorf("unit ohne -/var/log/%s", f)
		}
	}
	if strings.Contains(u, "ReadWritePaths=/var/log") || strings.Contains(u, " /var/log ") {
		t.Error("ganz /var/log freigegeben")
	}
}
