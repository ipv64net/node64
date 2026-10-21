package web

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/ipv64net/node64/internal/store/storetest"
)

// Backup -> frische Node -> Wiederherstellen: jede Tabelle aller Scopes (generisch aus sqlite_master) kommt mit
// gleichem Inhalt an, dazu secret.key und die Dateien der Module (Honeypot-Schluessel, DNS64-Freigaben, TLS,
// Statistik-Datenbanken); Caches (Blocklisten, Laenderdaten) und alte Sicherungen nicht.
func TestBackupArchiveAllTables(t *testing.T) {
	ctx := context.Background()
	a := newTestApp(t)
	storetest.MigrateAll(t, a.store)
	storetest.FillAll(t, a.store)
	want := storetest.Snapshot(t, a.store.Reader())
	dir := a.s.Cfg.DataDir
	write := func(rel, s string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o750)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{"secret.key": "0123456789abcdef0123456789abcdef", "tls/cert.pem": "cert", "honeypot/ssh_host_ed25519_key": "hostkey",
		"honeypot/sensor.crt": "crt", "honeypot/sensor_id": "id", "dns64/allowlist.txt": "example.org\n", "dns64/tls/cert.pem": "dnscert"}
	for rel, s := range files {
		write(rel, s)
	}
	skipped := []string{"geoip/country_ranges.txt.gz", "dns64/lists/list-0123.txt", "cdn64/blocklists/index.json", "backups/agent-1-pre-migration.db"}
	for _, rel := range skipped {
		write(rel, "cache")
	}
	for _, rel := range []string{"dns64/dns64.db", "cdn64/cdn64.db"} { // Statistik: echte SQLite-Dateien (VACUUM INTO)
		os.MkdirAll(filepath.Join(dir, filepath.Dir(rel)), 0o750)
		db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(dir, rel)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`CREATE TABLE stats (v TEXT); INSERT INTO stats VALUES ('` + rel + `')`); err != nil {
			t.Fatal(err)
		}
		db.Close()
	}

	var buf bytes.Buffer
	if err := a.s.writeArchive(ctx, &buf, "backup-passwort", true); err != nil {
		t.Fatal(err)
	}
	b := newTestApp(t)
	if _, err := b.s.restoreArchive(ctx, &buf, "backup-passwort"); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(b.s.Cfg.DataDir, RestoreDirName)
	open := func(p string) *sql.DB {
		db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(p)+"?mode=ro")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
	got := storetest.Snapshot(t, open(filepath.Join(stage, "node64.db")))
	if len(got) != len(want) {
		t.Fatalf("tables: %d restored, %d in the backup", len(got), len(want))
	}
	for tbl, rows := range want {
		if rows == "" {
			t.Fatalf("table %s empty before the backup", tbl)
		}
		if got[tbl] != rows {
			t.Fatalf("table %s differs:\n%s\n---\n%s", tbl, got[tbl], rows)
		}
	}
	for rel, s := range files {
		if b, _ := os.ReadFile(filepath.Join(stage, filepath.FromSlash(rel))); string(b) != s {
			t.Fatalf("%s not restored: %q", rel, b)
		}
	}
	for _, rel := range []string{"dns64/dns64.db", "cdn64/cdn64.db"} {
		var v string
		if err := open(filepath.Join(stage, rel)).QueryRow(`SELECT v FROM stats`).Scan(&v); err != nil || v != rel {
			t.Fatalf("%s: %q %v", rel, v, err)
		}
	}
	for _, rel := range skipped {
		if _, err := os.Stat(filepath.Join(stage, filepath.FromSlash(rel))); err == nil {
			t.Fatalf("cache in backup: %s", rel)
		}
	}
}
