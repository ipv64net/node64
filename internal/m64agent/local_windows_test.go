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

	"github.com/ipv64net/node64/internal/m64proto"
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

// WI2: der Ordner des aufgeloesten Skripts zaehlt wie local.d - in C:\ProgramData duerfen Benutzer Dateien anlegen
// (als Vorfahr erlaubt, als Ordner eines Skripts nicht: DLL bzw. Befehl daneben liefe als SYSTEM).
func TestOpenScriptParentDirWindows(t *testing.T) {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		t.Skip("ProgramData fehlt")
	}
	if err := checkAncestors(filepath.Join(pd, "x")); err != nil {
		t.Skipf("ProgramData als Vorfahr: %v", err)
	}
	_, err := openScript(filepath.Join(pd, "m64-gibt-es-nicht.exe"))
	if err == nil || !strings.Contains(err.Error(), "writable by") {
		t.Fatalf("Skript direkt in ProgramData: %v", err)
	}
	// Systemordner bleiben erlaubt
	if f, err := openScript(filepath.Join(systemDir(), `System32\whoami.exe`)); err != nil {
		t.Fatalf("whoami.exe: %v", err)
	} else {
		_ = f.Close()
	}
}

// WI3: Ausgabe in der OEM-Codepage (cmd.exe schreibt so in die Pipe) wird zu UTF-8; gueltiges UTF-8 bleibt.
func TestDecodeOutputWindows(t *testing.T) {
	if cp := oemCP(); cp != 437 && cp != 850 && cp != 858 {
		t.Skipf("OEM-Codepage %d (Test erwartet 437/850/858)", cp)
	}
	oem := []byte("0 m64oem - Gr\x94\xe1e ok\n") // "Groesse" in 437/850
	if got := string(decodeOutput(oem, false)); got != "0 m64oem - Größe ok\n" {
		t.Fatalf("OEM: %q", got)
	}
	utf := []byte("0 m64 - Größe ok\n")
	if got := decodeOutput(utf, false); string(got) != string(utf) {
		t.Fatalf("UTF-8 veraendert: %q", got)
	}
	// abgeschnitten mitten im UTF-8-Zeichen: bleibt UTF-8
	cut := append([]byte("0 a - ok\n0 b - Gr"), "ö"[0])
	if got := decodeOutput(cut, true); string(got) != string(cut) {
		t.Fatalf("abgeschnitten: %q", got)
	}

	// echter Lauf: .bat mit OEM-Text
	dir := t.TempDir()
	p := filepath.Join(dir, "oem.bat")
	if err := os.WriteFile(p, append([]byte("@echo off\r\necho "), append(oem[:len(oem)-1], '\r', '\n')...), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := scriptCmd(ctx, nil, p)
	cmd.Env = localEnv()
	out := &limitBuf{max: m64proto.LocalMaxBytes}
	cmd.Stdout = out
	prepareCmd(cmd)
	if err := runCmd(cmd); err != nil {
		t.Fatal(err)
	}
	checks, bad := ParseLocal(out.buf.Bytes(), "oem.bat")
	if bad != 0 || len(checks) != 1 || !strings.Contains(checks[0].Text, "Größe") {
		t.Fatalf("%q -> %+v", out.buf.Bytes(), checks)
	}
}

// WI4: beim Zeitlimit endet auch ein Enkel, dessen Elternprozess schon beendet ist (killTree findet ihn nicht).
func TestRunCmdJobWindows(t *testing.T) {
	dir := t.TempDir()
	waitfor := filepath.Join(systemDir(), `System32\waitfor.exe`)
	if _, err := os.Stat(waitfor); err != nil {
		t.Skip("waitfor.exe fehlt")
	}
	b := filepath.Join(dir, "b.bat")
	a := filepath.Join(dir, "a.bat")
	if err := os.WriteFile(b, []byte("@echo off\r\nstart \"\" /b \""+waitfor+"\" /t 60 m64jobtest\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a, []byte("@echo off\r\ncmd /d /c \""+b+"\"\r\necho 0 a - ok\r\nping -n 30 127.0.0.1 >nul\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := pidsOf("waitfor.exe")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := scriptCmd(ctx, nil, a)
	cmd.Env = localEnv()
	out := &limitBuf{max: m64proto.LocalMaxBytes}
	cmd.Stdout = out
	prepareCmd(cmd)
	cmd.WaitDelay = 2 * time.Second
	found := make(chan []uint32, 1)
	go func() {
		var pids []uint32
		for i := 0; i < 150 && len(pids) == 0; i++ {
			time.Sleep(20 * time.Millisecond)
			for p := range pidsOf("waitfor.exe") {
				if !before[p] {
					pids = append(pids, p)
				}
			}
		}
		found <- pids
	}()
	start := time.Now()
	_ = runCmd(cmd)
	pids := <-found
	t.Cleanup(func() {
		for _, p := range pids {
			if h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, p); err == nil {
				_ = windows.TerminateProcess(h, 1)
				windows.CloseHandle(h)
			}
		}
	})
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("Lauf dauerte %s", d)
	}
	if !strings.Contains(out.buf.String(), "0 a - ok") {
		t.Errorf("Ausgabe %q", out.buf.String())
	}
	if len(pids) == 0 {
		t.Skip("Enkel nicht gefunden")
	}
	for _, p := range pids {
		h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, p)
		if err != nil {
			continue // schon weg
		}
		ev, _ := windows.WaitForSingleObject(h, 2000)
		windows.CloseHandle(h)
		if ev != windows.WAIT_OBJECT_0 {
			t.Fatalf("Enkel %d laeuft noch", p)
		}
	}
}

// pidsOf liefert die Prozessnummern zu einem Programmnamen.
func pidsOf(exe string) map[uint32]bool {
	out := map[uint32]bool{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if strings.EqualFold(windows.UTF16ToString(pe.ExeFile[:]), exe) {
			out[pe.ProcessID] = true
		}
	}
	return out
}
