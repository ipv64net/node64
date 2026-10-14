package dyndns

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/store"
)

// Ausgeschaltet: keine Tabellen; erst die erste Aktivierung legt sie an. An/Aus laeuft sauber.
func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(ctx, filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	cm, _ := store.CoreMigrations()
	if err := core.Migrate(ctx, "core", cm); err != nil {
		t.Fatal(err)
	}
	reg := module.NewRegistry(core, log)
	reg.Register(New(core, log, nil, nil, "test"))
	reg.StartEnabled(ctx)

	tables := func() int {
		var n int
		_ = core.Reader().QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name LIKE 'dyn_%'`).Scan(&n)
		return n
	}
	if reg.IsRunning(Name) || tables() != 0 {
		t.Fatalf("disabled module must not run or create tables (running=%v tables=%d)", reg.IsRunning(Name), tables())
	}
	if err := reg.Enable(ctx, Name); err != nil {
		t.Fatal(err)
	}
	if !reg.IsRunning(Name) || tables() != 3 {
		t.Fatalf("enabled: running=%v tables=%d", reg.IsRunning(Name), tables())
	}
	if err := reg.Disable(ctx, Name); err != nil {
		t.Fatal(err)
	}
	if reg.IsRunning(Name) {
		t.Fatal("still running after disable")
	}
	if err := reg.Enable(ctx, Name); err != nil { // zweites Einschalten ohne erneute Migration
		t.Fatal(err)
	}
	reg.StopAll()
}
