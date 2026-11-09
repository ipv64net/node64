//go:build windows

package m64agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Eigene Skripte unter Windows: .ps1 (powershell.exe -File), .bat/.cmd (cmd.exe /c) und .exe (direkt). Wie unter
// Linux (Eigentuemer root, nicht fuer Gruppe/andere schreibbar) duerfen Skript, local.d und alle Ordner darueber nur
// von SYSTEM, Administratoren bzw. TrustedInstaller geaendert werden; sonst wird das Skript ignoriert (Hinweis im
// Bericht). Die Datei bleibt waehrend des Laufs ohne Schreib- und Loeschfreigabe geoeffnet, so kann sie zwischen
// Pruefung und Ende niemand austauschen.

// Zugriffsrechte, mit denen jemand ein Skript bzw. local.d aendern koennte (Datei: Inhalt; Ordner: Eintraege anlegen,
// loeschen, umbenennen) - fuer Skript und local.d selbst.
const leafWriteMask = 0x2 | 0x4 | 0x40 | // FILE_WRITE_DATA/ADD_FILE, FILE_APPEND_DATA/ADD_SUBDIRECTORY, FILE_DELETE_CHILD
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL | windows.GENERIC_WRITE

// Fuer Ordner darueber zaehlt nur, was vorhandene Eintraege ersetzen kann (Loeschen/Umbenennen, Rechte aendern);
// Anlegen neuer Eintraege ist erlaubt (Benutzer duerfen z. B. in C:\ und C:\ProgramData Ordner anlegen, aber keine
// fremden umbenennen - wie das Sticky-Bit unter Linux).
const ancestorWriteMask = 0x40 | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL

// SID von NT SERVICE\TrustedInstaller (Eigentuemer der Systemdateien).
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// Weitere ACE-Typen (winnt.h), die Rechte gewaehren.
const (
	aceAllowedCompound       = 4
	aceAllowedObject         = 5
	aceAllowedCallback       = 9
	aceAllowedCallbackObject = 11
)

// errNoScriptType: Endung nicht unterstuetzt.
var errNoScriptType = errors.New("unsupported file type - use .ps1, .bat, .cmd or .exe")

// scriptExt liefert die (kleingeschriebene) Endung, wenn sie unterstuetzt wird.
func scriptExt(p string) (string, bool) {
	switch e := strings.ToLower(filepath.Ext(p)); e {
	case ".ps1", ".bat", ".cmd", ".exe":
		return e, true
	}
	return "", false
}

// checkDir: Ordner (aufgeloest) ist kein Verweis, gehoert SYSTEM/Administratoren/TrustedInstaller und ist fuer
// niemanden sonst schreibbar; die Ordner darueber ebenso (siehe ancestorWriteMask).
func checkDir(dir string) error {
	real, err := resolve(dir)
	if err != nil {
		return err
	}
	h, err := openNoFollow(real, true, false)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	if err := checkHandle(h, true, leafWriteMask); err != nil {
		return err
	}
	return checkAncestors(real)
}

// checkScript prueft ein Skript (Verweise aufgeloest, siehe openScript) und liefert den aufgeloesten Pfad.
func checkScript(path string) (string, error) {
	real, err := resolve(path)
	if err != nil {
		return "", err
	}
	f, err := openScript(real)
	if err != nil {
		return "", err
	}
	_ = f.Close()
	return real, nil
}

// openScript oeffnet ein Skript (aufgeloester Pfad) ohne einem Verweis zu folgen, nur mit Lesefreigabe (niemand kann
// es waehrend des Laufs aendern, loeschen oder umbenennen), und prueft Endung, Eigentuemer und Rechte samt Ordnern.
func openScript(real string) (*os.File, error) {
	ext, ok := scriptExt(real)
	if !ok {
		return nil, errNoScriptType
	}
	if (ext == ".bat" || ext == ".cmd") && strings.ContainsAny(real, `&|<>^%!"()`) {
		return nil, errors.New(`path contains characters cmd.exe interprets (&|<>^%!"())`)
	}
	if err := checkAncestors(real); err != nil {
		return nil, err
	}
	h, err := openNoFollow(real, false, true)
	if err != nil {
		return nil, err
	}
	if err := checkHandle(h, false, leafWriteMask); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	return os.NewFile(uintptr(h), real), nil
}

// openNoFollow oeffnet Datei bzw. Ordner, ohne einem Verweis (Symlink, Junction, Cloud-Platzhalter) zu folgen, und
// prueft die Art. exclusive: nur Lesefreigabe (Datei kann waehrend des Laufs nicht geaendert werden).
func openNoFollow(p string, dir, exclusive bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return 0, err
	}
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES)
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if dir {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	if exclusive {
		access |= windows.GENERIC_READ
		share = windows.FILE_SHARE_READ
	}
	h, err := windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return 0, errors.New("file is open for writing by another program")
		}
		return 0, &os.PathError{Op: "open", Path: p, Err: err}
	}
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	isDir := fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	switch {
	case fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		err = errors.New("is a link or reparse point")
	case dir && !isDir:
		err = errors.New("not a directory")
	case !dir && isDir:
		err = errors.New("not a regular file")
	}
	if err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	return h, nil
}

// checkHandle prueft Eigentuemer und Zugriffsliste eines geoeffneten Objekts.
func checkHandle(h windows.Handle, dir bool, mask uint32) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("security info: %w", err)
	}
	return checkSD(sd, mask)
}

// checkAncestors prueft alle Ordner oberhalb von p (ohne Verweise zu folgen).
func checkAncestors(p string) error {
	for d := filepath.Dir(p); ; d = filepath.Dir(d) {
		h, err := openNoFollow(d, true, false)
		if err != nil {
			return fmt.Errorf("%s: %w", d, err)
		}
		err = checkHandle(h, true, ancestorWriteMask)
		windows.CloseHandle(h)
		if err != nil {
			return fmt.Errorf("%s: %w", d, err)
		}
		if parent := filepath.Dir(d); parent == d {
			return nil
		}
	}
}

// trustedSID: SYSTEM, Administratoren, TrustedInstaller und "OWNER RIGHTS" (gilt fuer den Eigentuemer, der selbst
// vertrauenswuerdig sein muss).
func trustedSID(s *windows.SID) bool {
	if s == nil {
		return false
	}
	if s.IsWellKnown(windows.WinLocalSystemSid) || s.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	str := s.String()
	return str == trustedInstallerSID || str == "S-1-3-4"
}

// sidName liefert "DOMAENE\Name" (sonst die SID) fuer Hinweise.
func sidName(s *windows.SID) string {
	if acc, dom, _, err := s.LookupAccount(""); err == nil {
		if dom != "" {
			return dom + `\` + acc
		}
		return acc
	}
	return s.String()
}

// checkSD prueft Eigentuemer und Zugriffsliste: Eigentuemer vertrauenswuerdig (er kann sonst die Rechte aendern),
// keine Zugriffsliste = jeder darf alles; jeder gewaehrende Eintrag mit Rechten aus mask fuer jemand anderen ist ein
// Fehler. Verweigernde und nur vererbbare Eintraege zaehlen nicht ("CREATOR OWNER" wirkt nur beim Vererben).
func checkSD(sd *windows.SECURITY_DESCRIPTOR, mask uint32) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("owner unknown")
	}
	if !trustedSID(owner) {
		return fmt.Errorf("owned by %s (not SYSTEM or Administrators)", sidName(owner))
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("access list: %w", err)
	}
	if dacl == nil {
		return errors.New("no access list - everyone has full access")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("access list entry %d: %w", i, err)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || uint32(ace.Mask)&mask == 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if trustedSID(sid) || sid.String() == "S-1-3-0" { // CREATOR OWNER
				continue
			}
			return fmt.Errorf("writable by %s", sidName(sid))
		case aceAllowedCompound, aceAllowedObject, aceAllowedCallback, aceAllowedCallbackObject:
			return fmt.Errorf("access list entry of type %d grants write access - not supported", ace.Header.AceType)
		}
	}
	return nil
}

// resolve liefert den absoluten Pfad ohne Symlinks/Junctions.
func resolve(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// systemDir liefert den Windows-Ordner (SystemRoot).
func systemDir() string {
	if d, err := windows.GetSystemWindowsDirectory(); err == nil && d != "" {
		return d
	}
	if d := os.Getenv("SystemRoot"); d != "" {
		return d
	}
	return `C:\Windows`
}

// scriptCmd baut den Aufruf je Endung. Die geoeffnete Datei f bleibt bis zum Ende offen (ohne Schreibfreigabe).
func scriptCmd(ctx context.Context, _ *os.File, real string) *exec.Cmd {
	sys := systemDir()
	switch ext, _ := scriptExt(real); ext {
	case ".ps1":
		return exec.CommandContext(ctx, filepath.Join(sys, `System32\WindowsPowerShell\v1.0\powershell.exe`),
			"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", real)
	case ".bat", ".cmd":
		// cmd.exe hat eigene Regeln fuer Anfuehrungszeichen: /s /c ""pfad"" fuehrt genau den Pfad aus (Sonderzeichen
		// im Pfad lehnt openScript ab).
		comspec := filepath.Join(sys, `System32\cmd.exe`)
		cmd := exec.CommandContext(ctx, comspec)
		cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: `"` + comspec + `" /d /s /c ""` + real + `""`}
		return cmd
	}
	return exec.CommandContext(ctx, real)
}

// prepareCmd: ohne Fenster, eigene Prozessgruppe; beim Zeitlimit endet auch, was das Skript gestartet hat.
func prepareCmd(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		killTree(uint32(cmd.Process.Pid))
		return cmd.Process.Kill()
	}
}

// killTree beendet die Nachfahren eines Prozesses (zuerst die Kinder) - nur Prozesse, die nach ihrem Elternprozess
// gestartet wurden (sonst koennte eine wiederverwendete Prozessnummer einen fremden Prozess treffen).
func killTree(root uint32) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	children := map[uint32][]uint32{}
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if pe.ProcessID != 0 && pe.ProcessID != pe.ParentProcessID {
			children[pe.ParentProcessID] = append(children[pe.ParentProcessID], pe.ProcessID)
		}
	}
	windows.CloseHandle(snap)
	var order []uint32
	queue := []uint32{root}
	seen := map[uint32]bool{root: true}
	for len(queue) > 0 && len(order) < 1024 {
		p := queue[0]
		queue = queue[1:]
		pStart, ok := processStart(p)
		if !ok {
			continue
		}
		for _, c := range children[p] {
			if seen[c] {
				continue
			}
			if cStart, ok := processStart(c); ok && cStart >= pStart {
				seen[c] = true
				order = append(order, c)
				queue = append(queue, c)
			}
		}
	}
	for i := len(order) - 1; i >= 0; i-- {
		if h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, order[i]); err == nil {
			_ = windows.TerminateProcess(h, 1)
			windows.CloseHandle(h)
		}
	}
}

// processStart liefert die Startzeit eines Prozesses (100 ns).
func processStart(pid uint32) (int64, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, false
	}
	defer windows.CloseHandle(h)
	var c, e, k, u windows.Filetime
	if windows.GetProcessTimes(h, &c, &e, &k, &u) != nil {
		return 0, false
	}
	return c.Nanoseconds(), true
}

// localEnvNames: Variablen, die eigene Skripte aus der Umgebung des Agents erben (Windows braucht SystemRoot & Co.;
// sonst nichts vom Agent).
var localEnvNames = []string{"SystemRoot", "windir", "SystemDrive", "ComSpec", "PATHEXT", "ProgramData", "ProgramFiles",
	"ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles", "CommonProgramFiles(x86)", "CommonProgramW6432",
	"ALLUSERSPROFILE", "COMPUTERNAME", "NUMBER_OF_PROCESSORS", "OS", "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER",
	"PROCESSOR_LEVEL", "PROCESSOR_REVISION", "TEMP", "TMP", "USERPROFILE", "USERNAME", "USERDOMAIN", "PUBLIC"}

// localEnv: schlanke Umgebung fuer eigene Skripte; PATH fest auf die Systemordner.
func localEnv() []string {
	sys := systemDir()
	env := []string{"PATH=" + strings.Join([]string{filepath.Join(sys, "System32"), sys, filepath.Join(sys, `System32\Wbem`),
		filepath.Join(sys, `System32\WindowsPowerShell\v1.0`)}, ";")}
	for _, kv := range os.Environ() {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		for _, n := range localEnvNames {
			if strings.EqualFold(k, n) {
				env = append(env, kv)
				break
			}
		}
	}
	return env
}
