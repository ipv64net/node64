package store

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Datenbank, -wal/-shm und Backups nur fuer den Besitzer (vorher 0644 – auf dem Host fuer jeden lesbar).
func TestPrivateFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-Rechte")
	}
	dir := t.TempDir()
	path, bdir := filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups")
	_ = os.MkdirAll(bdir, 0o750)
	old := filepath.Join(bdir, "agent-old-pre-migration.db")
	if err := os.WriteFile(old, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil { // vorhandene Datenbank mit alten Rechten
		t.Fatal(err)
	}
	s, err := Open(context.Background(), path, bdir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dest := filepath.Join(bdir, "neu.db")
	if err := s.Backup(context.Background(), dest); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + "-wal", old, dest} {
		fi, err := os.Stat(p)
		if err != nil {
			continue // -wal fehlt je nach Zeitpunkt
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s: %v", filepath.Base(p), fi.Mode().Perm())
		}
	}
}
