package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/web"
)

func TestApplyRestoreArchive(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{DataDir: dir}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	write := func(p, s string) {
		os.MkdirAll(filepath.Dir(p), 0o750)
		os.WriteFile(p, []byte(s), 0o600)
	}
	write(filepath.Join(dir, "node64.db"), "alt")
	write(filepath.Join(dir, "node64.db-wal"), "wal")
	write(filepath.Join(dir, "secret.key"), "alter-schluessel")
	src := filepath.Join(dir, web.RestoreDirName)
	write(filepath.Join(src, "node64.db"), "neu")
	write(filepath.Join(src, "secret.key"), "neuer-schluessel")
	write(filepath.Join(src, "dns64", "allowlist.txt"), "example.org")
	write(filepath.Join(dir, "bin", "state.json"), "eigener-stand")
	write(filepath.Join(src, "bin", "state.json"), `{"current":"9.9.9"}`)
	write(filepath.Join(src, "bin", "node64-9.9.9"), "fremdes-programm")

	if err := applyRestore(cfg, log); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "bin", "node64-9.9.9")); err == nil {
		t.Fatal("program from the archive placed under bin/")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "bin", "state.json")); string(b) != "eigener-stand" {
		t.Fatalf("bin/state.json replaced from the archive: %q", b)
	}
	for p, want := range map[string]string{"node64.db": "neu", "secret.key": "neuer-schluessel", "dns64/allowlist.txt": "example.org"} {
		if b, _ := os.ReadFile(filepath.Join(dir, p)); string(b) != want {
			t.Fatalf("%s = %q", p, b)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "node64.db-wal")); err == nil {
		t.Fatal("old wal kept next to restored database")
	}
	if _, err := os.Stat(src); err == nil {
		t.Fatal("restore dir not removed")
	}
	kept, _ := filepath.Glob(filepath.Join(cfg.BackupDir(), "pre-restore-*", "secret.key"))
	if len(kept) != 1 {
		t.Fatalf("old secret.key not kept: %v", kept)
	}
	if b, _ := os.ReadFile(kept[0]); string(b) != "alter-schluessel" {
		t.Fatalf("kept key: %q", b)
	}
}
