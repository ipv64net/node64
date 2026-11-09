package m64linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Ordner, in denen Programme auch ohne passenden PATH gesucht werden (Agent unter systemd, smartctl in sbin).
var extraPath = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// lookPath sucht ein Programm in PATH und den sbin-Ordnern; "" = nicht gefunden. Absolute Pfade werden direkt
// geprueft.
func lookPath(name string) string {
	if strings.HasPrefix(name, "/") {
		if st, err := os.Stat(name); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return name
		}
		return ""
	}
	if strings.ContainsAny(name, `/\`) || name == "" {
		return ""
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, d := range extraPath {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

// limitBuf nimmt hoechstens max Bytes auf und verwirft den Rest (das Programm laeuft weiter).
type limitBuf struct {
	b   []byte
	max int
}

func (l *limitBuf) Write(p []byte) (int, error) {
	if room := l.max - len(l.b); room > 0 {
		if len(p) > room {
			l.b = append(l.b, p[:room]...)
		} else {
			l.b = append(l.b, p...)
		}
	}
	return len(p), nil
}

// DefaultExec startet ein Programm direkt (keine Shell) mit LC_ALL=C; stdout bis MaxReportBytes, stderr bis 64 KB.
func DefaultExec(ctx context.Context, name string, args ...string) (ExecResult, error) {
	p := lookPath(name)
	if p == "" {
		return ExecResult{}, fmt.Errorf("%s: %w", name, ErrNotFound)
	}
	cmd := exec.CommandContext(ctx, p, args...)
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=" + strings.Join(extraPath, ":"), "HOME=/root"}
	cmd.Stdin = nil
	out := &limitBuf{max: m64proto.MaxReportBytes}
	serr := &limitBuf{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, serr
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	res := ExecResult{Stdout: out.b, Stderr: serr.b}
	if cmd.ProcessState != nil {
		res.Code = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() != nil {
		return res, fmt.Errorf("%s: Zeitlimit", name)
	}
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return res, fmt.Errorf("%s: %w", name, err)
	}
	return res, nil
}

// joinRoot setzt einen Host-Pfad unter die Wurzel.
func joinRoot(root, p string) string {
	if root == "" || root == "/" {
		return p
	}
	return filepath.Join(root, filepath.FromSlash(p))
}
