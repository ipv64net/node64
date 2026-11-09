//go:build unix

package m64agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
)

// checkDir: Ordner (Symlinks aufgeloest) gehoert root und ist nicht fuer Gruppe/andere schreibbar, ebenso alle
// Vorfahren (sonst koennte jemand Skripte oder Ordner unterschieben).
func checkDir(dir string) error {
	real, err := resolve(dir)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(real)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return errors.New("not a directory")
	}
	if err := checkOwner(fi); err != nil {
		return err
	}
	return checkAncestors(real)
}

// checkScript prueft ein Skript (Symlinks aufgeloest, siehe openScript) und liefert den aufgeloesten Pfad.
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

// openScript oeffnet ein Skript (aufgeloester Pfad) ohne einem Symlink zu folgen und prueft den geoeffneten
// Deskriptor: regulaere Datei, gehoert root, nicht fuer Gruppe/andere schreibbar, ausfuehrbar; alle Vorfahren
// gehoeren root und sind nicht fuer Gruppe/andere schreibbar. Ausgefuehrt wird dann genau diese Datei (scriptCmd).
func openScript(real string) (*os.File, error) {
	if err := checkAncestors(real); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(real, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil {
		switch {
		case !fi.Mode().IsRegular():
			err = errors.New("not a regular file")
		case fi.Mode().Perm()&0o111 == 0:
			err = errors.New("not executable")
		default:
			err = checkOwner(fi)
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// resolve liefert den absoluten Pfad ohne Symlinks.
func resolve(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// checkAncestors prueft alle Ordner oberhalb von p (ohne Symlinks): gehoeren root, nicht fuer Gruppe/andere
// schreibbar. Ausnahme Sticky-Bit (z. B. /tmp): dort kann niemand fremde Eintraege umbenennen oder loeschen, und der
// naechste Ordner darunter wird ja ebenfalls geprueft.
func checkAncestors(p string) error {
	for d := filepath.Dir(p); ; d = filepath.Dir(d) {
		fi, err := os.Lstat(d)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", d)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("owner unknown")
		}
		if st.Uid != 0 {
			return fmt.Errorf("%s not owned by root (uid %d)", d, st.Uid)
		}
		if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("%s writable by group or others", d)
		}
		if parent := filepath.Dir(d); parent == d {
			return nil
		}
	}
}

func checkOwner(fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("owner unknown")
	}
	if st.Uid != 0 {
		return fmt.Errorf("not owned by root (uid %d)", st.Uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return errors.New("writable by group or others")
	}
	return nil
}

// scriptCmd fuehrt die geoeffnete Datei aus (fexecve-Ersatz): sie wird im Kind Deskriptor 3 und ueber
// /proc/self/fd/3 (bzw. /dev/fd/3) gestartet. Der Deskriptor bleibt offen, damit auch Skripte mit "#!" laufen
// (der Interpreter oeffnet denselben Pfad).
func scriptCmd(ctx context.Context, f *os.File, real string) *exec.Cmd {
	p := "/dev/fd/3"
	if runtime.GOOS == "linux" {
		p = "/proc/self/fd/3"
	}
	cmd := exec.CommandContext(ctx, p)
	cmd.Args[0] = real
	cmd.ExtraFiles = []*os.File{f}
	return cmd
}

// prepareCmd startet das Skript in einer eigenen Prozessgruppe, damit beim Zeitlimit auch Kindprozesse enden.
func prepareCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

// localEnv: schlanke Umgebung fuer eigene Skripte (keine Variablen des Agents).
func localEnv() []string {
	return []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"HOME=" + localHome,
	}
}
