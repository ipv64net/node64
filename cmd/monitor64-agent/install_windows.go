//go:build windows

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/ipv64net/node64/internal/m64agent"
	"github.com/ipv64net/node64/internal/m64proto"
)

// Ablage unter Windows: Programm in %ProgramFiles%\monitor64-agent (nur der Ordner ist fuer update schreibbar, durch
// SYSTEM), Einstellungen in %ProgramData%\monitor64-agent (defaultDir, Rechte siehe paths_windows.go). Der Dienst
// laeuft als LocalSystem (Storage- und Update-Abfragen brauchen das).
const (
	exeName        = "monitor64-agent.exe"
	serviceDisplay = "Monitor64-Agent (Node64)"
	serviceDesc    = "Answers Node64 monitoring queries over SSH (port 6465/tcp) - https://node64.de/"
	firewallRule   = "Monitor64-Agent"
)

// programDir liefert %ProgramFiles%\monitor64-agent.
func programDir() string {
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil || pf == "" {
		pf = os.Getenv("ProgramFiles")
	}
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "monitor64-agent")
}

func install(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	key := fs.String("key", "", `public key of the node ("ssh-ed25519 AAAA... comment")`)
	port := fs.Int("port", m64proto.DefaultPort, "TCP port")
	var pf pushFlags
	pf.register(fs)
	noTray := fs.Bool("no-tray", false, "no icon in the notification area")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := doInstall(*key, *port, pf, *noTray); err != nil {
		fmt.Fprintln(os.Stderr, "monitor64-agent: ERROR:", err)
		return 1
	}
	return 0
}

func doInstall(key string, port int, pf pushFlags, noTray bool) error {
	key, err := checkInstallArgs(key, port)
	if err != nil {
		return err
	}
	connectPath := filepath.Join(defaultDir, m64agent.PushFile)
	if pf.noListen && len(pf.connect) == 0 {
		if t, _ := m64agent.ReadPushFile(connectPath); len(t) == 0 {
			return errors.New("--no-listen needs --connect token@node[:port]")
		}
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("please run as Administrator")
	}
	pdir := programDir()
	exePath := filepath.Join(pdir, exeName)

	// Ordner mit festen Rechten (vor dem Schreiben von Schluesseln, die erben sie); vorhandene nur, wenn sie
	// SYSTEM/Administratoren gehoeren und keine Verweise sind (samt keys, hostkey, connect und local.d darin)
	for _, d := range []struct {
		path, sddl string
		entries    []string
	}{{defaultDir, sddlData, dataEntries}, {pdir, sddlProgram, nil}} {
		if err := prepareDir(d.path, d.sddl, d.entries, trustedOwner); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(defaultDir, "local.d"), 0o700); err != nil {
		return err
	}
	keysPath := filepath.Join(defaultDir, "keys")
	added, err := addKey(keysPath, key)
	if err != nil {
		return err
	}
	if added {
		say("key added to %s", keysPath)
	} else {
		say("key already in %s", keysPath)
	}
	if err := writePushTargets(connectPath, pf.connect); err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err == nil {
		if err := stopService(s); err != nil {
			s.Close()
			return fmt.Errorf("stop running service: %w", err)
		}
	} else {
		s = nil
	}

	// Programmdatei
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if fi1, e1 := os.Stat(self); e1 == nil {
		if fi2, e2 := os.Stat(exePath); e2 != nil || !os.SameFile(fi1, fi2) {
			if err := copyFile(self, exePath, 0o755); err != nil {
				return fmt.Errorf("copy program: %w", err)
			}
		}
	}
	say("program installed: %s", exePath)

	// Hostschluessel (vor dem Start, damit der Fingerabdruck sicher feststeht)
	hk, err := m64agent.LoadOrCreateHostKey(filepath.Join(defaultDir, "hostkey"))
	if err != nil {
		return err
	}

	// Dienst: automatisch starten, nach Absturz/Fehler/Update neu starten
	cfg := mgr.Config{DisplayName: serviceDisplay, Description: serviceDesc, StartType: mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal}
	runArgs := []string{"run", "--port", strconv.Itoa(port)}
	if pf.noListen {
		runArgs = append(runArgs, "--no-listen") // Ziele in <dir>\connect (nicht in der Befehlszeile)
	}
	if noTray {
		runArgs = append(runArgs, "--no-tray")
	}
	if s == nil {
		if s, err = m.CreateService(serviceName, exePath, cfg, runArgs...); err != nil {
			return fmt.Errorf("create service: %w", err)
		}
	} else {
		cur, err := s.Config()
		if err != nil {
			s.Close()
			return fmt.Errorf("service config: %w", err)
		}
		cur.DisplayName, cur.Description, cur.StartType, cur.ErrorControl = cfg.DisplayName, cfg.Description, cfg.StartType, cfg.ErrorControl
		cur.BinaryPathName = binaryPath(exePath, runArgs)
		cur.ServiceStartName = "LocalSystem"
		cur.Password = ""
		if err := s.UpdateConfig(cur); err != nil {
			s.Close()
			return fmt.Errorf("update service: %w", err)
		}
	}
	defer s.Close()
	if err := s.SetRecoveryActions(recoveryActions(), 24*60*60); err != nil {
		say("WARNING: recovery actions not set (no automatic restart after an update): %v", err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		say("WARNING: recovery on errors not set: %v", err)
	}

	// Firewall (eingehend TCP-Port, nur fuer diese Datei); nur Push: keine eingehende Regel
	if pf.noListen {
		netsh := netshPath()
		del, _ := firewallCmdLines(netsh, "", 0)
		_, _ = runCmdLine(netsh, del)
	} else if err := setFirewall(exePath, port); err != nil {
		say("WARNING: firewall rule not created - allow %d/tcp yourself: %v", port, err)
	} else {
		say("firewall rule %q: %d/tcp allowed for %s", firewallRule, port, exeName)
	}

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	if err := waitState(s, svc.Running, 20*time.Second); err != nil {
		return fmt.Errorf("start service: %w (see %s)", err, filepath.Join(defaultDir, "agent.log"))
	}
	if pf.noListen {
		say("service %s started (push only, not listening)", serviceName)
	} else {
		say("service %s started (port %d/tcp)", serviceName, port)
	}
	fmt.Println()
	say("host key fingerprint (compare it in Node64):")
	fmt.Println("  " + m64agent.Fingerprint(hk.PublicKey()))
	return nil
}

// recoveryActions: Neustart nach 2 s, 5 s, dann alle 30 s (Zaehler nach einem Tag zurueck). Darueber startet auch ein
// Update neu (der Agent beendet sich dafuer, siehe restartSelf).
func recoveryActions() []mgr.RecoveryAction {
	return []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
}

// binaryPath baut die Befehlszeile des Dienstes (wie mgr.CreateService).
func binaryPath(exe string, args []string) string {
	s := syscall.EscapeArg(exe)
	for _, a := range args {
		s += " " + syscall.EscapeArg(a)
	}
	return s
}

// stopService haelt den Dienst an und wartet, bis er steht.
func stopService(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil {
			return err
		}
	}
	return waitState(s, svc.Stopped, 30*time.Second)
}

// waitState wartet, bis der Dienst den Zustand erreicht.
func waitState(s *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == want {
			return nil
		}
		if want == svc.Running && st.State == svc.Stopped {
			return fmt.Errorf("service stopped (exit code %d/%d)", st.Win32ExitCode, st.ServiceSpecificExitCode)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout (state %d)", st.State)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// netshPath liefert netsh.exe mit vollem Pfad.
func netshPath() string {
	d, err := windows.GetSystemDirectory()
	if err != nil || d == "" {
		d = `C:\Windows\System32`
	}
	return filepath.Join(d, "netsh.exe")
}

// firewallCmdLines liefert die Befehlszeilen fuer netsh: alte Regel entfernen, neue anlegen (Port und Programm).
// netsh hat eigene Regeln fuer Anfuehrungszeichen, deshalb fertige Befehlszeilen statt Argumentlisten.
func firewallCmdLines(netsh, exe string, port int) (del, add string) {
	q := `"` + netsh + `"`
	del = q + ` advfirewall firewall delete rule name="` + firewallRule + `"`
	add = q + ` advfirewall firewall add rule name="` + firewallRule + `" dir=in action=allow protocol=TCP localport=` +
		strconv.Itoa(port) + ` program="` + exe + `" enable=yes profile=any description="Monitor64-Agent (Node64)"`
	return del, add
}

func runCmdLine(exe, line string) ([]byte, error) {
	cmd := exec.Command(exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: line, HideWindow: true}
	return cmd.CombinedOutput()
}

func setFirewall(exe string, port int) error {
	if strings.ContainsRune(exe, '"') {
		return errors.New("path contains quotes")
	}
	netsh := netshPath()
	del, add := firewallCmdLines(netsh, exe, port)
	_, _ = runCmdLine(netsh, del) // fehlt beim ersten Mal
	if out, err := runCmdLine(netsh, add); err != nil {
		return fmt.Errorf("netsh: %v: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

func uninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		fmt.Fprintln(os.Stderr, "monitor64-agent: ERROR: please run as Administrator")
		return 1
	}
	if m, err := mgr.Connect(); err == nil {
		if s, err := m.OpenService(serviceName); err == nil {
			if err := stopService(s); err != nil {
				say("WARNING: stop service: %v", err)
			}
			if err := s.Delete(); err != nil {
				say("WARNING: delete service: %v", err)
			}
			s.Close()
		}
		m.Disconnect()
	} else {
		say("WARNING: service manager: %v", err)
	}
	netsh := netshPath()
	del, _ := firewallCmdLines(netsh, "", 0)
	_, _ = runCmdLine(netsh, del)

	for _, f := range []string{"keys", "hostkey", m64agent.PushFile, "agent.log", "agent.log.1", "crash.log"} {
		_ = os.Remove(filepath.Join(defaultDir, f))
	}
	local := filepath.Join(defaultDir, "local.d")
	if ents, err := os.ReadDir(local); err == nil && len(ents) > 0 {
		say("kept %s (contains your own scripts) - remove it yourself if no longer needed", local)
	} else {
		_ = os.Remove(local)
		_ = os.Remove(defaultDir)
	}
	removeProgramDir(programDir())
	say("removed")
	return 0
}

// removeProgramDir entfernt den Programmordner. Laeuft diese Datei selbst von dort, kann Windows sie erst nach dem
// Ende loeschen: dann raeumt ein kurz verzoegertes cmd.exe den Ordner ab.
func removeProgramDir(pdir string) {
	self := selfPath()
	if self == "" || !strings.EqualFold(filepath.Dir(self), pdir) {
		_ = os.RemoveAll(pdir)
		return
	}
	ents, _ := os.ReadDir(pdir)
	for _, e := range ents {
		if p := filepath.Join(pdir, e.Name()); !strings.EqualFold(p, self) {
			_ = os.RemoveAll(p)
		}
	}
	if strings.ContainsAny(pdir, `"&|<>^%`) {
		say("remove %s yourself", pdir)
		return
	}
	d, err := windows.GetSystemDirectory()
	if err != nil {
		d = `C:\Windows\System32`
	}
	comspec := filepath.Join(d, "cmd.exe")
	cmd := exec.Command(comspec)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine:       `"` + comspec + `" /d /c ping -n 3 127.0.0.1 >nul & rd /s /q "` + pdir + `"`,
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW | windows.DETACHED_PROCESS,
	}
	if err := cmd.Start(); err != nil {
		say("remove %s yourself: %v", pdir, err)
		return
	}
	_ = cmd.Process.Release()
}
