//go:build windows

package m64agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestCheckSDWindows(t *testing.T) {
	ti := trustedInstallerSID
	for _, tc := range []struct {
		name string
		sddl string
		mask uint32
		err  string // "" = ok
	}{
		{"Standard", "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)", leafWriteMask, ""},
		{"TrustedInstaller", "O:" + ti + "D:P(A;;FA;;;" + ti + ")(A;;0x1200a9;;;BU)", leafWriteMask, ""},
		{"Eigentuemer Benutzer", "O:BUD:P(A;;FA;;;SY)", leafWriteMask, "owned by"},
		{"Benutzer aendern", "O:BAD:P(A;;FA;;;SY)(A;;0x1301bf;;;BU)", leafWriteMask, "writable by"},
		{"Jeder Vollzugriff", "O:SYD:(A;;GA;;;WD)", leafWriteMask, "writable by"},
		{"Benutzer GENERIC_WRITE", "O:SYD:(A;;GW;;;BU)", leafWriteMask, "writable by"},
		{"Benutzer Rechte aendern", "O:SYD:(A;;WD;;;AU)", leafWriteMask, "writable by"},
		{"nur vererbbar", "O:BAD:P(A;OICIIO;FA;;;BU)(A;;FA;;;SY)", leafWriteMask, ""},
		{"CREATOR OWNER", "O:BAD:(A;;FA;;;CO)", leafWriteMask, ""},
		{"verweigert", "O:BAD:(D;;FA;;;BU)(A;;FA;;;SY)", leafWriteMask, ""},
		{"OWNER RIGHTS", "O:BAD:(A;;FA;;;OW)", leafWriteMask, ""},
		{"keine Zugriffsliste", "O:BAD:NO_ACCESS_CONTROL", leafWriteMask, "no access list"},
		// Ordner darueber: Anlegen erlaubt (C:\, C:\ProgramData), Loeschen/Umbenennen nicht
		{"Vorfahr anlegen", "O:SYD:(A;;0x6;;;BU)(A;;FA;;;SY)", ancestorWriteMask, ""},
		{"Vorfahr anlegen (Skript)", "O:SYD:(A;;0x6;;;BU)(A;;FA;;;SY)", leafWriteMask, "writable by"},
		{"Vorfahr loeschen", "O:SYD:(A;;0x40;;;BU)", ancestorWriteMask, "writable by"},
		{"Vorfahr DELETE", "O:SYD:(A;;SD;;;BU)", ancestorWriteMask, "writable by"},
	} {
		sd, err := windows.SecurityDescriptorFromString(tc.sddl)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		err = checkSD(sd, tc.mask)
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%s: %v (erwartet %q)", tc.name, err, tc.err)
		}
	}
}

// Systemdateien (TrustedInstaller, Benutzer nur lesen) gehen durch, Dateien im Benutzer-Temp nicht.
func TestCheckScriptWindows(t *testing.T) {
	sys := systemDir()
	if err := checkDir(filepath.Join(sys, "System32")); err != nil {
		t.Fatalf("System32: %v", err)
	}
	// C:\ProgramData: Benutzer duerfen dort Ordner anlegen, aber keine fremden ersetzen - als Vorfahr erlaubt
	if pd := os.Getenv("ProgramData"); pd != "" {
		if err := checkAncestors(filepath.Join(pd, "x")); err != nil {
			t.Fatalf("ProgramData als Vorfahr: %v", err)
		}
	}
	real, err := checkScript(filepath.Join(sys, `System32\whoami.exe`))
	if err != nil || !strings.EqualFold(filepath.Base(real), "whoami.exe") {
		t.Fatalf("whoami.exe: %q %v", real, err)
	}
	dir := t.TempDir()
	if err := checkDir(dir); err == nil {
		t.Fatal("Benutzer-Temp angenommen")
	}
	for name, want := range map[string]string{"x.ps1": "owned by", "x.txt": "unsupported file type", "a&b.bat": "cmd.exe"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("echo 0 x -\r\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := checkScript(p); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v (erwartet %q)", name, err, want)
		}
	}
}

// Die Aufrufe je Endung laufen (auch mit Leerzeichen im Pfad) und sehen nur die schlanke Umgebung.
func TestScriptCmdWindows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mit leer")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("M64_GEHEIM", "x")
	scripts := map[string]string{
		"a.ps1": "Write-Output \"0 ps1 - ok $env:M64_GEHEIM\"\r\n",
		"b.bat": "@echo off\r\necho 0 bat - ok %M64_GEHEIM%\r\n",
		"c.cmd": "@echo 1 cmd - warn\r\n",
	}
	for name, body := range scripts {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := scriptCmd(ctx, nil, p)
		cmd.Env = localEnv()
		prepareCmd(cmd)
		out, err := cmd.Output()
		cancel()
		if err != nil {
			t.Fatalf("%s: %v (%s)", name, err, out)
		}
		checks, bad := ParseLocal(out, name)
		if bad != 0 || len(checks) != 1 || strings.Contains(string(out), "%M64_GEHEIM%") && name != "b.bat" {
			t.Errorf("%s: %q -> %+v (%d)", name, out, checks, bad)
		}
		if strings.Contains(string(out), " x") {
			t.Errorf("%s: Variable des Agents sichtbar: %q", name, out)
		}
	}
	env := strings.Join(localEnv(), "\n")
	if !strings.Contains(env, "PATH=") || !strings.Contains(strings.ToLower(env), "systemroot=") || strings.Contains(env, "M64_GEHEIM") {
		t.Fatalf("env = %s", env)
	}
}

// Beim Zeitlimit enden auch die Kindprozesse (sonst haelt z. B. ping die Ausgabe offen).
func TestKillTreeWindows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(systemDir(), `System32\cmd.exe`), "/d", "/c", "ping -n 30 127.0.0.1 >nul")
	prepareCmd(cmd)
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var child uint32
	for i := 0; i < 50 && child == 0; i++ {
		time.Sleep(20 * time.Millisecond)
		child = childOf(uint32(cmd.Process.Pid))
	}
	start := time.Now()
	_ = cmd.Wait()
	if child == 0 {
		t.Skip("Kindprozess nicht gefunden")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Wait dauerte %s", d)
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, child)
	if err != nil {
		return // schon weg
	}
	defer windows.CloseHandle(h)
	if ev, _ := windows.WaitForSingleObject(h, 2000); ev != windows.WAIT_OBJECT_0 {
		t.Fatalf("Kindprozess %d laeuft noch", child)
	}
}

func childOf(pid uint32) uint32 {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if pe.ParentProcessID == pid {
			return pe.ProcessID
		}
	}
	return 0
}
