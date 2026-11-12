// Package privdrop hilft, wenn der Datenordner nicht dem Laufzeit-Benutzer gehoert (Host-Ordner auf Synology,
// UGREEN & Co.): Startet der Container als root (user: "0:0"), uebergibt Node64 den Ordner dem Benutzer 65532
// (oder NODE64_UID/NODE64_GID) und startet sich als dieser neu. Sonst prueft Writable den Ordner und erklaert
// den Fehler.
package privdrop

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultID ist der Benutzer des Images (Dockerfile: USER 65532:65532).
const DefaultID = 65532

// target liest NODE64_UID und NODE64_GID (Standard 65532; GID ohne Angabe = UID).
func target(getenv func(string) string) (uid, gid int, err error) {
	uid, gid = DefaultID, -1
	if v := strings.TrimSpace(getenv("NODE64_UID")); v != "" {
		if uid, err = strconv.Atoi(v); err != nil || uid < 0 {
			return 0, 0, fmt.Errorf("NODE64_UID %q is not a valid user id", v)
		}
	}
	if v := strings.TrimSpace(getenv("NODE64_GID")); v != "" {
		if gid, err = strconv.Atoi(v); err != nil || gid < 0 {
			return 0, 0, fmt.Errorf("NODE64_GID %q is not a valid group id", v)
		}
	}
	if gid < 0 {
		gid = uid
	}
	return uid, gid, nil
}

// own gibt dir samt Inhalt uid:gid und dem Besitzer Lese-/Schreibrechte (Ordner auch x). Symlinks werden nicht
// verfolgt. Fehler am Ordner selbst brechen ab; Fehler darunter (z. B. ein eingebundenes Zertifikat, read-only)
// werden nur gezaehlt.
func own(dir string, uid, gid int, chown func(string, int, int) error) (changed, failed int, err error) {
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			if p == dir {
				return werr
			}
			failed++
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			if p == dir {
				return ierr
			}
			failed++
			return nil
		}
		fuid, fgid, ok := owner(info)
		touched := false
		if !ok || fuid != uid || fgid != gid {
			if cerr := chown(p, uid, gid); cerr != nil {
				if p == dir {
					return cerr
				}
				failed++
				return nil
			}
			touched = true
		}
		if d.Type()&fs.ModeSymlink == 0 {
			need := fs.FileMode(0o600)
			if d.IsDir() {
				need = 0o700
			}
			if m := info.Mode().Perm(); m&need != need {
				if cerr := os.Chmod(p, m|need); cerr != nil {
					if p == dir {
						return cerr
					}
					failed++
					return nil
				}
				touched = true
			}
		}
		if touched {
			changed++
		}
		return nil
	})
	return changed, failed, err
}

// Writable prueft, ob der laufende Prozess in dir Dateien anlegen kann, und erklaert sonst die Abhilfe.
func Writable(dir string) error {
	f, err := os.CreateTemp(dir, ".node64-write-test-*")
	if err == nil {
		name := f.Name()
		f.Close()
		os.Remove(name)
		return nil
	}
	if !errors.Is(err, fs.ErrPermission) && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("data dir %s: %w", dir, err)
	}
	own := "unknown"
	if info, serr := os.Stat(dir); serr == nil {
		if u, g, ok := owner(info); ok {
			own = fmt.Sprintf("%d:%d", u, g)
		}
	}
	return fmt.Errorf("data dir %s is not writable for user %d:%d (folder owner %s). Fix: use a named volume, "+
		"or give the host folder to the user (chown -R %d:%d <folder>), or start the container with user \"0:0\" "+
		"- node64 then takes over the folder itself and keeps running as %d: %w",
		dir, os.Getuid(), os.Getgid(), own, os.Getuid(), os.Getgid(), DefaultID, err)
}
