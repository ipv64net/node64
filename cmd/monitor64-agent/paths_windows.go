//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ipv64net/node64/internal/m64agent"
)

// defaultDir enthaelt keys, hostkey, local.d und das Protokoll des Dienstes (agent.log); nur SYSTEM und
// Administratoren haben Zugriff (install setzt die Rechte). Er liegt im Ordner ProgramData, wie Windows ihn kennt
// (auch wenn Windows nicht auf C: liegt oder ProgramData verlegt ist).
var defaultDir = dataDirFrom(func() (string, error) { return windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0) }, os.Getenv)

// dataDirFrom liefert <ProgramData>\monitor64-agent: KnownFolder, sonst %ProgramData%, sonst C:\ProgramData.
func dataDirFrom(known func() (string, error), getenv func(string) string) string {
	pd, err := known()
	if err != nil || !filepath.IsAbs(pd) {
		pd = getenv("ProgramData")
	}
	if !filepath.IsAbs(pd) {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "monitor64-agent")
}

// Rechte (SDDL, geschuetzt = ohne Vererbung von oben): Einstellungen nur SYSTEM und Administratoren, Programmordner
// zusaetzlich Benutzer lesen/ausfuehren. sddlRun legt der Agent selbst an, wenn der Ordner beim Start fehlt (ohne
// festen Eigentuemer; "OWNER RIGHTS" laesst einen Lauf ohne Adminrechte mit eigenem --dir an seine Dateien).
const (
	sddlData    = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	sddlProgram = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	sddlRun     = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"
)

// dataEntries sind die Eintraege in defaultDir, denen der Agent vertraut (Schluessel der Node, Hostschluessel,
// Push-Ziele, eigene Skripte).
var dataEntries = []string{"keys", "hostkey", m64agent.PushFile, "local.d"}

// trustedOwner: SYSTEM oder Administratoren. Nur sie duerfen Eigentuemer der Ablage sein - jeder Eigentuemer kann
// die Rechte aendern, und Benutzer duerfen in ProgramData eigene Ordner anlegen.
func trustedOwner(s *windows.SID) bool {
	return s != nil && (s.IsWellKnown(windows.WinLocalSystemSid) || s.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}

// accountName liefert "DOMAENE\Name" (sonst die SID) fuer Meldungen.
func accountName(s *windows.SID) string {
	if s == nil {
		return "unknown"
	}
	if acc, dom, _, err := s.LookupAccount(""); err == nil {
		if dom != "" {
			return dom + `\` + acc
		}
		return acc
	}
	return s.String()
}

// openEntry oeffnet Datei oder Ordner, ohne einem Verweis zu folgen. Die Freigabe erlaubt nur Lesen: solange das
// Handle offen ist, kann niemand den Eintrag umbenennen, loeschen oder in einen Verweis umwandeln (dafuer braucht es
// Schreib- bzw. Loeschzugriff). Fehlt er, ist das Handle 0 (ohne Fehler).
func openEntry(path string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	return h, nil
}

// checkEntry prueft einen geoeffneten Eintrag: kein Verweis (Symlink, Junction), Eigentuemer vertrauenswuerdig.
func checkEntry(h windows.Handle, path string, trusted func(*windows.SID) bool) error {
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is a link (symlink or junction) - remove it and run install again", path)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: security info: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !trusted(owner) {
		return &foreignOwnerError{path: path, owner: accountName(owner)}
	}
	return nil
}

// foreignOwnerError: der Eintrag gehoert weder SYSTEM noch den Administratoren.
type foreignOwnerError struct{ path, owner string }

func (e *foreignOwnerError) Error() string {
	return fmt.Sprintf("%s is owned by %s, not by SYSTEM or Administrators - someone else may have put keys there; "+
		"check its contents, delete it and run install again", e.path, e.owner)
}

// prepareDir legt einen Ordner der Ablage mit festen Rechten an bzw. uebernimmt einen vorhandenen nur, wenn er kein
// Verweis ist und SYSTEM/Administratoren gehoert; dann werden Eigentuemer und Rechte neu gesetzt (an vorhandene
// Eintraege vererbt) und danach die Eintraege aus entries ebenso geprueft. Sonst Abbruch: ein Benutzer koennte den
// Ordner vorher angelegt und dort Schluessel, Hostschluessel oder Push-Ziele hinterlegt haben. Ausnahme: ein leerer
// Ordner eines anderen Eigentuemers wird entfernt und neu angelegt.
func prepareDir(dir, sddl string, entries []string, trusted func(*windows.SID) bool) error {
	h, err := openEntry(dir)
	if err != nil {
		return err
	}
	if h == 0 {
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
			return err
		}
		if err := createDirSecure(dir, sddl); err != nil {
			if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
				return fmt.Errorf("%s was created by someone else in the meantime - run install again", dir)
			}
			return fmt.Errorf("%s: %w", dir, err)
		}
		return nil
	}
	closed := false
	defer func() { // bis zum Ende offen: der Ordner bleibt derselbe
		if !closed {
			windows.CloseHandle(h)
		}
	}()
	if err := checkEntry(h, dir, trusted); err != nil {
		// Leerer Ordner eines anderen Eigentuemers (z. B. lief der Agent einmal ohne Administratorrechte): darin kann
		// niemand etwas hinterlegt haben. Entfernen und mit festen Rechten neu anlegen - RemoveDirectory gelingt nur
		// bei einem leeren Ordner, sonst bleibt es beim Abbruch (auch bei Verweisen und Dateien).
		var fo *foreignOwnerError
		if !errors.As(err, &fo) {
			return err
		}
		windows.CloseHandle(h) // das Handle sperrt das Loeschen
		closed = true
		p, perr := windows.UTF16PtrFromString(dir)
		if perr != nil || windows.RemoveDirectory(p) != nil {
			return err
		}
		if cerr := createDirSecure(dir, sddl); cerr != nil {
			if errors.Is(cerr, windows.ERROR_ALREADY_EXISTS) {
				return fmt.Errorf("%s was created by someone else in the meantime - run install again", dir)
			}
			return fmt.Errorf("%s: %w", dir, cerr)
		}
		return nil
	}
	// Erst die Rechte setzen (danach kann niemand sonst mehr Eintraege anlegen), dann die Eintraege pruefen.
	if err := setSecurity(dir, sddl); err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	for _, e := range entries {
		p := filepath.Join(dir, e)
		eh, err := openEntry(p)
		if err != nil {
			return err
		}
		if eh == 0 {
			continue
		}
		err = checkEntry(eh, p, trusted)
		windows.CloseHandle(eh)
		if err != nil {
			return err
		}
	}
	return nil
}

// createDirSecure legt einen Ordner gleich mit den Rechten aus sddl an (nie mit geerbten Rechten, auch nicht kurz).
func createDirSecure(dir, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	return windows.CreateDirectory(p, &sa)
}

// setSecurity setzt Eigentuemer (falls sddl einen nennt) und geschuetzte Rechte; Windows vererbt sie an vorhandene
// Eintraege.
func setSecurity(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if owner != nil {
		info |= windows.OWNER_SECURITY_INFORMATION
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil)
}

// ensureDataDir legt den Ordner der Einstellungen beim Start an, falls er fehlt - mit eigenen, geschuetzten Rechten
// (sddlRun) statt der von ProgramData geerbten (dort duerfen Benutzer Dateien anlegen). Einen vorhandenen Ordner
// laesst er, wie er ist (install prueft ihn).
func ensureDataDir(dir string) error {
	if _, err := os.Lstat(dir); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	if err := createDirSecure(dir, sddlRun); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	return nil
}
