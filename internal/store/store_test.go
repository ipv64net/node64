package store

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	st, err := Open(context.Background(), filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	core, err := CoreMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(context.Background(), "core", core); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestMigrateIsIdempotentAndBacksUp(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	core, _ := CoreMigrations()
	if err := st.Migrate(ctx, "core", core); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	// Eine neue Modul-Migration loest ein Backup aus, weil schon etwas angewendet wurde
	ms := []Migration{{Version: 1, Name: "test", SQL: `CREATE TABLE t1 (id INTEGER PRIMARY KEY)`}}
	if err := st.Migrate(ctx, "testmod", ms); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(st.backupDir)
	if len(entries) != 1 {
		t.Fatalf("expected 1 backup, got %d", len(entries))
	}
	// Gleiche Migration nochmal: nichts passiert, kein zweites Backup
	if err := st.Migrate(ctx, "testmod", ms); err != nil {
		t.Fatal(err)
	}
	entries, _ = os.ReadDir(st.backupDir)
	if len(entries) != 1 {
		t.Fatalf("expected still 1 backup, got %d", len(entries))
	}
	// Version 2 dazu
	ms = append(ms, Migration{Version: 2, Name: "col", SQL: `ALTER TABLE t1 ADD COLUMN name TEXT NOT NULL DEFAULT ''`})
	if err := st.Migrate(ctx, "testmod", ms); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Writer().ExecContext(ctx, `INSERT INTO t1 (name) VALUES ('x')`); err != nil {
		t.Fatal(err)
	}
}

// Aelteres Programm auf neuerem Schema: Start geht weiter, SchemaNewer meldet die unbekannten Versionen.
func TestMigrateDetectsNewerSchema(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	ms := []Migration{{Version: 1, Name: "a", SQL: `CREATE TABLE t3 (id INTEGER PRIMARY KEY)`}, {Version: 2, Name: "b", SQL: `ALTER TABLE t3 ADD COLUMN x TEXT`}}
	if err := st.Migrate(ctx, "mod", ms); err != nil {
		t.Fatal(err)
	}
	if n := st.SchemaNewer(); len(n) != 0 {
		t.Fatalf("nothing newer expected: %v", n)
	}
	if err := st.Migrate(ctx, "mod", ms[:1]); err != nil {
		t.Fatalf("older program must still start: %v", err)
	}
	if n := st.SchemaNewer(); len(n["mod"]) != 1 || n["mod"][0] != 2 || len(n) != 1 {
		t.Fatalf("newer schema not detected: %v", n)
	}
}

func TestMigrationFailureRollsBack(t *testing.T) {
	st := openTest(t)
	ms := []Migration{{Version: 1, Name: "bad", SQL: `CREATE TABLE t2 (id INTEGER); INSERT INTO nope VALUES (1)`}}
	if err := st.Migrate(context.Background(), "bad", ms); err == nil {
		t.Fatal("expected error")
	}
	var n int
	if err := st.Reader().QueryRow(`SELECT count(*) FROM sqlite_master WHERE name = 't2'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("table t2 should have been rolled back")
	}
}

func TestBackupIsReadable(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	if err := st.SetSetting(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "copy.db")
	if err := st.Backup(ctx, dest); err != nil {
		t.Fatal(err)
	}
	copy, err := Open(ctx, dest, t.TempDir(), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer copy.Close()
	if v := copy.SettingOr(ctx, "k", ""); v != "v" {
		t.Fatalf("backup content: got %q", v)
	}
}

func TestUsersSessionsAudit(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	if n, _ := st.UserCount(ctx); n != 0 {
		t.Fatal("expected no users")
	}
	u, err := st.CreateUser(ctx, "Admin", "hash", "de", "Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := st.UserByName(ctx, "admin"); got == nil || got.ID != u.ID {
		t.Fatal("username lookup should be case-insensitive")
	}
	if _, err := st.CreateUser(ctx, "ADMIN", "hash", "", ""); err == nil {
		t.Fatal("duplicate username must fail")
	}

	now := time.Now()
	sess := &Session{ID: "s1", UserID: u.ID, CSRF: "c", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := st.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.SessionByID(ctx, "s1"); got == nil {
		t.Fatal("session should be valid")
	}
	if err := st.TouchSession(ctx, "s1", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.SessionByID(ctx, "s1"); got != nil {
		t.Fatal("expired session must not be returned")
	}
	if n, _ := st.PurgeSessions(ctx); n != 1 {
		t.Fatalf("purge: got %d", n)
	}

	if err := st.Audit(ctx, AuditEntry{Actor: "admin", Action: "test"}); err != nil {
		t.Fatal(err)
	}
	list, err := st.AuditList(ctx, 10, 0)
	if err != nil || len(list) != 1 || list[0].Origin != "local" {
		t.Fatalf("audit list: %v %+v", err, list)
	}

	if on, _ := st.ModuleEnabled(ctx, "x"); on {
		t.Fatal("module should default to disabled")
	}
	if err := st.SetModuleEnabled(ctx, "x", true); err != nil {
		t.Fatal(err)
	}
	if on, _ := st.ModuleEnabled(ctx, "x"); !on {
		t.Fatal("module should be enabled")
	}
}

// Das Audit-Log behaelt nur die eingestellte Zeit (0 = unbegrenzt).
func TestPruneAudit(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	if _, err := st.w.ExecContext(ctx, `INSERT INTO audit_log (time, actor, action) VALUES (?, 'a', 'alt'), (?, 'a', 'neu')`,
		FormatTime(time.Now().AddDate(0, 0, -400)), Now()); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneAudit(ctx, 0); err != nil || n != 0 {
		t.Fatalf("unlimited: %d %v", n, err)
	}
	if n, err := st.PruneAudit(ctx, 365*24*time.Hour); err != nil || n != 1 {
		t.Fatalf("pruned %d %v", n, err)
	}
	list, _ := st.AuditList(ctx, 10, 0)
	if len(list) != 1 || list[0].Action != "neu" {
		t.Fatalf("left: %+v", list)
	}
}
