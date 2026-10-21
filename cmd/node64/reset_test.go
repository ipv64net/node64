package main

import (
	"context"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/store"
	"github.com/ipv64net/node64/internal/store/storetest"
	"github.com/ipv64net/node64/internal/web"
)

// Zuruecksetzen laesst nichts uebrig: jede Tabelle aller Scopes (generisch aus sqlite_master, neue Module zaehlen
// automatisch mit) und jede Datei unter /data (Schluessel, Zertifikate, Moduldateien, Caches, Backups). Nur ein
// eigenes Zertifikat der Oberflaeche (NODE64_TLS_CERT/KEY) unter /data bleibt.
func TestResetLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{DataDir: dir, TLSCertFile: filepath.Join(dir, "own", "cert.pem"), TLSKeyFile: filepath.Join(dir, "own", "key.pem")}

	st, err := store.Open(ctx, cfg.DBPath(), cfg.BackupDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	storetest.MigrateAll(t, st)
	storetest.FillAll(t, st)
	for tbl, n := range storetest.Counts(t, st.Reader()) {
		if n == 0 {
			t.Fatalf("table %s not filled", tbl)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	write := func(rel, s string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, rel := range []string{"secret.key", "tls/cert.pem", "tls/key.pem", "node64.db-wal",
		"honeypot/ssh_host_ed25519_key", "honeypot/sensor.crt", "honeypot/sensor.key", "honeypot/sensor_id", "honeypot/report_state.json", "honeypot/firewall/x.txt",
		"geoip/country_ranges.txt.gz", "geoip/meta.json",
		"dns64/dns64.db", "dns64/allowlist.txt", "dns64/lists/list-0123.txt", "dns64/tls/cert.pem", "dns64/acme/account.json",
		"cdn64/cdn64.db", "cdn64/blocklists/index.json", "cdn64/blocklists/countries/de.txt",
		"backups/agent-20261021-000000-pre-migration.db", "backups/pre-restore-20261021-000000/node64.db",
		"restore.new/node64.db", "tmp/x", "own/cert.pem", "own/key.pem"} {
		write(rel, "x")
	}
	write(web.ResetFileName, "2026-10-21T00:00:00Z") // Merker wie nach requestReset

	if err := applyReset(cfg, log); err != nil {
		t.Fatal(err)
	}
	var left []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel = filepath.ToSlash(rel); rel != "own/cert.pem" && rel != "own/key.pem" {
			left = append(left, rel)
		}
		return nil
	})
	if len(left) > 0 {
		t.Fatalf("left after reset: %v", left)
	}
	for _, rel := range []string{"own/cert.pem", "own/key.pem"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("own certificate removed: %s", rel)
		}
	}

	// Neustart wie nach dem Reset: alle Tabellen leer
	st, err = store.Open(ctx, cfg.DBPath(), cfg.BackupDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	storetest.MigrateAll(t, st)
	for tbl, n := range storetest.Counts(t, st.Reader()) {
		if n != 0 {
			t.Fatalf("table %s has %d rows after reset", tbl, n)
		}
	}
}

// Staende vor einer Wiederherstellung bleiben nur die letzten fuenf je Art.
func TestPruneRestoreBackups(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{DataDir: dir}
	for i := 0; i < 7; i++ {
		ts := "2026102" + string(rune('0'+i)) + "-000000"
		os.MkdirAll(filepath.Join(cfg.BackupDir(), "pre-restore-"+ts), 0o750)
		os.WriteFile(filepath.Join(cfg.BackupDir(), "node64-"+ts+"-pre-restore.db"), []byte("x"), 0o600)
	}
	os.WriteFile(filepath.Join(cfg.BackupDir(), "agent-20261020-000000-pre-migration.db"), []byte("x"), 0o600)
	pruneRestoreBackups(cfg, 5)
	for name, want := range map[string]bool{"pre-restore-20261020-000000": false, "pre-restore-20261021-000000": false, "pre-restore-20261022-000000": true,
		"node64-20261021-000000-pre-restore.db": false, "node64-20261026-000000-pre-restore.db": true, "agent-20261020-000000-pre-migration.db": true} {
		if _, err := os.Stat(filepath.Join(cfg.BackupDir(), name)); (err == nil) != want {
			t.Fatalf("%s kept=%v, want %v", name, err == nil, want)
		}
	}
}
