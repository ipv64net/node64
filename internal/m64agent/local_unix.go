//go:build unix

package m64agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// "#!"-Zeile wie binfmt_script unter Linux: hoechstens 256 Byte, Interpreter bis 4 Ebenen verschachtelt.
const (
	shebangMax   = 256
	shebangDepth = 4
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
// gehoeren root und sind nicht fuer Gruppe/andere schreibbar. Dasselbe gilt fuer den Interpreter aus der "#!"-Zeile
// (checkShebang). Ausgefuehrt wird dann genau diese Datei (scriptCmd).
func openScript(real string) (*os.File, error) {
	return openExec(real, 0)
}

func openExec(real string, depth int) (*os.File, error) {
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
	if err == nil {
		err = checkShebang(f, depth)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// checkShebang prueft den Interpreter aus der "#!"-Zeile der geoeffneten Datei wie das Skript selbst (sonst liefe
// z. B. "#!/home/dienst/venv/bin/python" als root mit einer Datei, die der Dienstbenutzer aendern kann):
// absoluter Pfad, aufgeloest, root-eigen, nicht fuer Gruppe/andere schreibbar, samt Vorfahren. "/usr/bin/env name"
// nur mit einem Namen ohne Optionen, der im PATH der Skripte auf einen ebenso geprueften Pfad fuehrt (alle Ordner
// davor muessen ebenfalls sicher sein, sonst koennte dort jemand eine Datei unterschieben). Ein weiteres Argument
// mit absolutem Pfad muss ebenfalls root gehoeren.
func checkShebang(f *os.File, depth int) error {
	buf := make([]byte, shebangMax)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	buf = buf[:n]
	if !bytes.HasPrefix(buf, []byte("#!")) {
		return nil
	}
	if depth >= shebangDepth {
		return errors.New("interpreter nested too deeply")
	}
	line := buf[2:]
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	} else if n == shebangMax {
		return errors.New("#! line too long")
	}
	// wie der Kern: Interpreter bis zum ersten Leerzeichen/Tab, der Rest ist ein einziges Argument
	interp, arg := strings.Trim(string(line), " \t"), ""
	if i := strings.IndexAny(interp, " \t"); i >= 0 {
		interp, arg = interp[:i], strings.Trim(interp[i+1:], " \t")
	}
	if interp == "" {
		return errors.New("#! line without interpreter")
	}
	if !filepath.IsAbs(interp) {
		return fmt.Errorf("interpreter %s: path must be absolute", interp)
	}
	real, err := checkInterp(interp, depth)
	if err != nil {
		return fmt.Errorf("interpreter %s: %w", interp, err)
	}
	if filepath.Base(interp) == "env" || filepath.Base(real) == "env" {
		if err := checkEnvCommand(arg, depth); err != nil {
			return fmt.Errorf("interpreter %s %s: %w", interp, arg, err)
		}
		return nil
	}
	if filepath.IsAbs(arg) {
		r, err := resolve(arg)
		if err == nil {
			err = checkAncestors(r)
		}
		if err == nil {
			var fi os.FileInfo
			if fi, err = os.Stat(r); err == nil {
				err = checkOwner(fi)
			}
		}
		if err != nil {
			return fmt.Errorf("interpreter argument %s: %w", arg, err)
		}
	}
	return nil
}

// checkInterp prueft einen Interpreter (Symlinks aufgeloest, wie das Skript, auch dessen "#!"-Zeile).
func checkInterp(p string, depth int) (string, error) {
	real, err := resolve(p)
	if err != nil {
		return "", err
	}
	f, err := openExec(real, depth+1)
	if err != nil {
		return "", err
	}
	_ = f.Close()
	return real, nil
}

// checkEnvCommand prueft das Programm hinter "#!/usr/bin/env": genau ein Name ohne Optionen; mit "/" ein absoluter
// Pfad, sonst die erste ausfuehrbare Datei im PATH der Skripte (wie env sie findet).
func checkEnvCommand(cmd string, depth int) error {
	const hint = " - use the full interpreter path"
	switch {
	case cmd == "":
		return errors.New("no command" + hint)
	case strings.HasPrefix(cmd, "-") || strings.ContainsAny(cmd, " \t="):
		return errors.New("options or several arguments not supported" + hint)
	case strings.Contains(cmd, "/"):
		if !filepath.IsAbs(cmd) {
			return errors.New("relative path not supported" + hint)
		}
		_, err := checkInterp(cmd, depth)
		return err
	}
	for _, d := range filepath.SplitList(localPATH) {
		if err := checkPathDir(d); err != nil {
			return fmt.Errorf("PATH directory %s: %w%s", d, err, hint)
		}
		c := filepath.Join(d, cmd)
		fi, err := os.Stat(c)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
			continue
		}
		if _, err := checkInterp(c, depth); err != nil {
			return fmt.Errorf("%s: %w", c, err)
		}
		return nil
	}
	return errors.New("not found in PATH" + hint)
}

// checkPathDir: ein Ordner aus dem PATH ist sicher (wie checkDir); fehlt er, muss der naechste vorhandene Vorfahr
// sicher sein (sonst koennte ihn jemand anlegen und ein Programm unterschieben).
func checkPathDir(d string) error {
	for {
		_, err := os.Lstat(d)
		if err == nil {
			return checkDir(d)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(d)
		if parent == d {
			return err
		}
		d = parent
	}
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
// (der Interpreter oeffnet denselben Pfad). FreeBSD kennt unter /dev/fd ohne eingehaengtes fdescfs nur 0 bis 2
// (Standard bei FreeBSD 14): dann startet das Skript ueber seinen geprueften Pfad (Datei und alle
// Ordner darueber gehoeren root und sind fuer andere nicht schreibbar, siehe checkScript).
func scriptCmd(ctx context.Context, f *os.File, real string) *exec.Cmd {
	p := "/dev/fd/3"
	if runtime.GOOS == "linux" {
		p = "/proc/self/fd/3"
	} else if !fdPathWorks(f) {
		p = real
	}
	cmd := exec.CommandContext(ctx, p)
	cmd.Args[0] = real
	cmd.ExtraFiles = []*os.File{f}
	return cmd
}

// fdPathWorks sagt, ob offene Deskriptoren ueber /dev/fd/<n> erreichbar sind (fdescfs).
func fdPathWorks(f *os.File) bool {
	fd := f.Fd()
	if fd <= 2 {
		return false
	}
	_, err := os.Stat("/dev/fd/" + strconv.FormatUint(uint64(fd), 10))
	return err == nil
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

// localPATH ist der PATH der eigenen Skripte (auch fuer "#!/usr/bin/env name", checkEnvCommand).
const localPATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// localEnv: schlanke Umgebung fuer eigene Skripte (keine Variablen des Agents).
func localEnv() []string {
	return []string{
		"PATH=" + localPATH,
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"HOME=" + localHome,
	}
}

// runCmd fuehrt den mit prepareCmd vorbereiteten Aufruf aus (Prozessgruppe, Zeitlimit ueber cmd.Cancel).
func runCmd(cmd *exec.Cmd) error { return cmd.Run() }
