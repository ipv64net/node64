//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// WI8: Ablage aus dem KnownFolder ProgramData (Windows auf D:, verlegtes ProgramData), sonst %ProgramData%.
func TestDataDirFrom(t *testing.T) {
	env := func(v string) func(string) string {
		return func(string) string { return v }
	}
	known := func(p string, err error) func() (string, error) {
		return func() (string, error) { return p, err }
	}
	for _, tc := range []struct {
		known func() (string, error)
		env   func(string) string
		want  string
	}{
		{known(`D:\ProgramData`, nil), env(`C:\ProgramData`), `D:\ProgramData\monitor64-agent`},
		{known("", errors.New("x")), env(`E:\PD`), `E:\PD\monitor64-agent`},
		{known("", errors.New("x")), env(`relativ`), `C:\ProgramData\monitor64-agent`},
	} {
		if got := dataDirFrom(tc.known, tc.env); got != tc.want {
			t.Errorf("%q, erwartet %q", got, tc.want)
		}
	}
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil || !strings.EqualFold(defaultDir, filepath.Join(pd, "monitor64-agent")) {
		t.Fatalf("defaultDir %q (%q %v)", defaultDir, pd, err)
	}
}

// meSID liefert die SID des Testbenutzers (Eigentuemer von t.TempDir()).
func meSID(t *testing.T) *windows.SID {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	s, err := u.User.Sid.Copy()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// testSDDL: wie sddlData, ohne festen Eigentuemer (ohne Adminrechte nicht setzbar) und mit "OWNER RIGHTS", damit
// t.TempDir() aufraeumen kann.
const testSDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"

// junction legt einen Verzeichnis-Verweis an (geht ohne Adminrechte).
func junction(t *testing.T, link, target string) {
	t.Helper()
	cmd := filepath.Join(os.Getenv("SystemRoot"), `System32\cmd.exe`)
	if out, err := exec.Command(cmd, "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J: %v %s", err, out)
	}
}

// protectedDACL meldet, ob ein Ordner eine geschuetzte Zugriffsliste ohne geerbte Eintraege hat.
func protectedDACL(t *testing.T, p string) bool {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	ctl, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("dacl: %v", err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return false
		}
	}
	return ctl&windows.SE_DACL_PROTECTED != 0
}

// WI1: vorhandene Ablage eines fremden Eigentuemers (hier: der Testbenutzer statt SYSTEM/Administratoren) und
// Verweise werden nicht uebernommen.
func TestPrepareDirRejectsForeign(t *testing.T) {
	base := t.TempDir()
	foreign := filepath.Join(base, "fremd")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, "keys"), []byte("ssh-ed25519 AAAA fremd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := prepareDir(foreign, testSDDL, dataEntries, trustedOwner)
	if err == nil || !strings.Contains(err.Error(), "is owned by") {
		t.Fatalf("fremder Ordner: %v", err)
	}
	if protectedDACL(t, foreign) {
		t.Fatal("Rechte des fremden Ordners geaendert")
	}
	// leerer Ordner desselben fremden Eigentuemers: nichts darin - wird entfernt und mit festen Rechten neu angelegt
	empty := filepath.Join(base, "leer")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := prepareDir(empty, testSDDL, dataEntries, trustedOwner); err != nil {
		t.Fatalf("leerer fremder Ordner: %v", err)
	}
	if !protectedDACL(t, empty) {
		t.Fatal("leerer fremder Ordner nicht mit festen Rechten neu angelegt")
	}

	// Ordner als Junction (z. B. auf einen Ordner des Benutzers)
	link := filepath.Join(base, "verweis")
	junction(t, link, foreign)
	me := meSID(t)
	trustMe := func(s *windows.SID) bool { return s != nil && s.Equals(me) }
	if err := prepareDir(link, testSDDL, dataEntries, trustMe); err == nil || !strings.Contains(err.Error(), "is a link") {
		t.Fatalf("Junction: %v", err)
	}

	// vertrauenswuerdiger Ordner mit local.d als Junction
	ok := filepath.Join(base, "ok")
	if err := os.Mkdir(ok, 0o700); err != nil {
		t.Fatal(err)
	}
	junction(t, filepath.Join(ok, "local.d"), foreign)
	if err := prepareDir(ok, testSDDL, dataEntries, trustMe); err == nil || !strings.Contains(err.Error(), "local.d is a link") {
		t.Fatalf("local.d als Junction: %v", err)
	}
	if !protectedDACL(t, ok) {
		t.Fatal("Rechte nicht vor der Pruefung der Eintraege gesetzt")
	}
}

// WI1: neu angelegte und uebernommene Ordner haben sofort die eigenen, geschuetzten Rechte.
func TestPrepareDirCreatesProtected(t *testing.T) {
	base := t.TempDir()
	me := meSID(t)
	trustMe := func(s *windows.SID) bool { return s != nil && s.Equals(me) }
	fresh := filepath.Join(base, "neu")
	if err := prepareDir(fresh, testSDDL, dataEntries, trustMe); err != nil {
		t.Fatal(err)
	}
	if !protectedDACL(t, fresh) {
		t.Fatal("neuer Ordner erbt Rechte")
	}
	old := filepath.Join(base, "alt")
	if err := os.MkdirAll(filepath.Join(old, "local.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "keys"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if protectedDACL(t, old) {
		t.Fatal("Ausgangslage: Ordner sollte erben")
	}
	if err := prepareDir(old, testSDDL, dataEntries, trustMe); err != nil {
		t.Fatal(err)
	}
	if !protectedDACL(t, old) {
		t.Fatal("vorhandener Ordner nicht geschuetzt")
	}
}

// WI1: der Dienst legt den fehlenden Ordner nicht mit geerbten Rechten an (vorher os.MkdirAll).
func TestEnsureDataDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "monitor64-agent")
	if err := ensureDataDir(dir); err != nil {
		t.Fatal(err)
	}
	if !protectedDACL(t, dir) {
		t.Fatal("Ordner erbt Rechte von oben")
	}
	// Eigentuemer (hier der Testbenutzer) darf darin schreiben (OWNER RIGHTS), z. B. den Hostschluessel
	if err := os.WriteFile(filepath.Join(dir, "hostkey"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureDataDir(dir); err != nil {
		t.Fatalf("vorhanden: %v", err)
	}
}
