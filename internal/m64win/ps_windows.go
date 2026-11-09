//go:build windows

package m64win

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// powershellPath liefert Windows PowerShell 5.1 mit vollem Pfad (nicht ueber PATH).
func powershellPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		if d, err := windows.GetSystemWindowsDirectory(); err == nil {
			root = d
		} else {
			root = `C:\Windows`
		}
	}
	return filepath.Join(root, `System32\WindowsPowerShell\v1.0\powershell.exe`)
}

// hasPowerShell: powershell.exe vorhanden (fehlt nur auf Server Core ohne PowerShell bzw. Nano Server).
func hasPowerShell() bool {
	fi, err := os.Stat(powershellPath())
	return err == nil && fi.Mode().IsRegular()
}

// limitWriter nimmt hoechstens max Bytes auf.
type limitWriter struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if room := w.max - w.buf.Len(); room > 0 {
		if len(p) > room {
			w.buf.Write(p[:room])
			w.over = true
		} else {
			w.buf.Write(p)
		}
	} else if len(p) > 0 {
		w.over = true
	}
	return len(p), nil
}

// runPS fuehrt ein festes Skript aus (-EncodedCommand: kein Quoting, keine Datei; -NoProfile: keine Profile des
// Benutzers) und liefert stdout. Das Zeitlimit kommt ueber ctx.
func runPS(ctx context.Context, script string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	enc := base64.StdEncoding.EncodeToString(utf16le(script))
	cmd := exec.CommandContext(ctx, powershellPath(), "-NoLogo", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-EncodedCommand", enc)
	out := &limitWriter{max: maxPSOutput}
	errOut := &limitWriter{max: maxPSErr}
	cmd.Stdout, cmd.Stderr, cmd.Stdin = out, errOut, nil
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("powershell: Zeitlimit")
	}
	if out.over {
		return nil, fmt.Errorf("powershell: Ausgabe groesser als %d Byte", maxPSOutput)
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && out.buf.Len() > 0 {
			return out.buf.Bytes(), nil // JSON mit "fatal" bzw. "errors" kommt trotzdem
		}
		msg := firstLine(errOut.buf.Bytes())
		if msg != "" {
			return nil, fmt.Errorf("powershell: %v: %s", err, msg)
		}
		return nil, fmt.Errorf("powershell: %w", err)
	}
	return out.buf.Bytes(), nil
}

// utf16le kodiert den Text fuer -EncodedCommand.
func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return b
}

// firstLine liefert die erste nicht leere Zeile (gekuerzt), ohne CLIXML-Kopf.
func firstLine(b []byte) string {
	for _, l := range bytes.Split(b, []byte("\n")) {
		s := clip(string(l))
		if s != "" && s != "#< CLIXML" {
			return s
		}
	}
	return ""
}
