//go:build unix

package m64agent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// checkDir: Ordner gehoert root und ist nicht fuer Gruppe/andere schreibbar (sonst koennte jemand Skripte
// unterschieben).
func checkDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	return checkOwner(fi)
}

// checkScript: regulaere Datei, gehoert root, nicht fuer Gruppe/andere schreibbar, ausfuehrbar.
func checkScript(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if err := checkOwner(fi); err != nil {
		return err
	}
	if fi.Mode().Perm()&0o111 == 0 {
		return errors.New("not executable")
	}
	return nil
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
		"HOME=/root",
	}
}
