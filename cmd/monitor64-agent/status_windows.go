//go:build windows

package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/ipv64net/node64/internal/m64agent"
)

// Stand des Dienstes fuer das Symbol im Infobereich (tray_windows.go): <Programmordner>\status.json. Der
// Programmordner ist fuer Benutzer lesbar, aber nur fuer SYSTEM/Administratoren schreibbar; die Datei enthaelt nichts
// Geheimes (m64agent.Status).
const (
	statusFile  = "status.json"
	statusEvery = 5 * time.Second
	statusBeat  = time.Minute // auch ohne Aenderung so oft neu schreiben
)

func statusPath(exe string) string { return filepath.Join(filepath.Dir(exe), statusFile) }

// readStatus liest den Stand (ok = false: keine bzw. unlesbare Datei).
func readStatus(path string) (m64agent.Status, bool) {
	var st m64agent.Status
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &st) != nil || st.Version == "" {
		return m64agent.Status{}, false
	}
	return st, true
}

// writeStatus schreibt den Stand ueber eine Nachbardatei (nie halb geschrieben).
func writeStatus(path string, st m64agent.Status) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// statusLoop schreibt den Stand des Dienstes bei jeder Aenderung und entfernt die Datei beim Beenden. Eine von der
// Node gemeldete verfuegbare Version uebersteht den Neustart nach einem Update (aus der vorigen Datei): das Symbol
// zeigt dann gleich "aktuell" statt "noch keine Angabe".
func statusLoop(ctx context.Context, srv *m64agent.Server, exe string, log *slog.Logger) {
	path := statusPath(exe)
	if old, ok := readStatus(path); ok && old.Latest != "" {
		srv.SetLatest(old.Latest, time.Unix(old.LatestAt, 0))
	}
	var last m64agent.Status
	var at time.Time
	write := func() {
		st := srv.Status()
		st.PID = os.Getpid()
		if st == last && time.Since(at) < statusBeat {
			return
		}
		if err := writeStatus(path, st); err != nil {
			if at.IsZero() {
				log.Warn("monitor64-agent: status file", "err", err)
			}
			at = time.Now() // nicht jede Runde erneut versuchen und melden
			return
		}
		last, at = st, time.Now()
	}
	write()
	t := time.NewTicker(statusEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = os.Remove(path)
			return
		case <-t.C:
			write()
		}
	}
}
