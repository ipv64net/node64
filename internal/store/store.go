// Package store kapselt die SQLite-Datenbank des Nodes.
//
// Eine Datei unter /data, WAL-Modus, versionierte Migrationen je Scope
// (Kern und jedes Modul getrennt), automatisches Backup vor Migrationen.
// Alle Zeiten werden als RFC 3339 in UTC gespeichert.
//
// Es gibt zwei Verbindungs-Pools: einen einzelnen Schreiber (SQLite erlaubt
// ohnehin nur einen) und mehrere Leser. Damit blockieren lange Leseabfragen
// (Charts) keine Schreibvorgaenge und umgekehrt.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var coreFS embed.FS

// Migration ist eine Datenbankaenderung. Version ist je Scope eindeutig und
// streng steigend; jede Migration laeuft genau einmal in einer Transaktion.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

type Store struct {
	w         *sql.DB // genau eine Verbindung: alle Schreibzugriffe
	r         *sql.DB // Leser
	path      string
	backupDir string
	log       *slog.Logger
	backedUp  bool

	newerMu sync.Mutex
	newer   map[string][]int // Scope -> angewendete, hier unbekannte Migrationen (SchemaNewer)

	settingHook atomic.Pointer[func(ctx context.Context, key string)] // nach jedem SetSetting (core.go)
}

// Open oeffnet oder erzeugt die Datenbank.
func Open(ctx context.Context, path, backupDir string, log *slog.Logger) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	dsn := "file:" + filepath.ToSlash(path) + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_pragma=temp_store(MEMORY)"
	w, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	w.SetConnMaxLifetime(0)
	r, err := sql.Open("sqlite", dsn)
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(8)
	r.SetConnMaxLifetime(0)
	s := &Store{w: w, r: r, path: path, backupDir: backupDir, log: log.With("module", "store")}
	if err := s.w.PingContext(ctx); err != nil {
		s.Close()
		return nil, fmt.Errorf("open database: %w", err)
	}
	if _, err := s.w.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		scope TEXT NOT NULL, version INTEGER NOT NULL, name TEXT NOT NULL, applied_at TEXT NOT NULL,
		PRIMARY KEY (scope, version))`); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	err1 := s.r.Close()
	err2 := s.w.Close()
	return errors.Join(err1, err2)
}

// Path liefert den Dateipfad der Datenbank.
func (s *Store) Path() string { return s.path }

// Size liefert die Groesse der Datenbankdatei in Bytes (ohne WAL).
func (s *Store) Size() int64 {
	fi, err := os.Stat(s.path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// Writer liefert den Schreib-Pool, Reader den Lese-Pool (fuer Module).
func (s *Store) Writer() *sql.DB { return s.w }
func (s *Store) Reader() *sql.DB { return s.r }

// Now liefert die aktuelle Zeit im Speicherformat.
func Now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// FormatTime wandelt eine Zeit ins Speicherformat.
func FormatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// ParseTime liest das Speicherformat; leer oder ungueltig = Nullzeit.
func ParseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// CoreMigrations liest die eingebetteten Migrationen des Kerns
// (migrations/NNNN_name.sql).
func CoreMigrations() ([]Migration, error) {
	return readMigrations(coreFS, "migrations")
}

// ReadMigrations liest Migrationen aus einem eingebetteten Dateisystem.
// Dateiname: NNNN_name.sql.
func ReadMigrations(fsys fs.FS, dir string) ([]Migration, error) { return readMigrations(fsys, dir) }

func readMigrations(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	var ms []Migration
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		base := strings.TrimSuffix(name, ".sql")
		num, rest, ok := strings.Cut(base, "_")
		if !ok {
			return nil, fmt.Errorf("migration file %q: expected NNNN_name.sql", name)
		}
		v, err := strconv.Atoi(num)
		if err != nil {
			return nil, fmt.Errorf("migration file %q: bad version", name)
		}
		b, err := fs.ReadFile(fsys, dir+"/"+name)
		if err != nil {
			return nil, err
		}
		ms = append(ms, Migration{Version: v, Name: rest, SQL: string(b)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].Version < ms[j].Version })
	return ms, nil
}

// Migrate wendet alle noch fehlenden Migrationen eines Scopes an. Vor der
// ersten Aenderung in diesem Prozesslauf wird ein Backup geschrieben.
func (s *Store) Migrate(ctx context.Context, scope string, ms []Migration) error {
	applied := map[int]bool{}
	rows, err := s.r.QueryContext(ctx, `SELECT version FROM schema_migrations WHERE scope = ?`, scope)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()

	var pending []Migration
	known := 0
	for _, m := range ms {
		if !applied[m.Version] {
			pending = append(pending, m)
		}
		known = max(known, m.Version)
	}
	s.checkNewer(scope, applied, known)
	if len(pending) == 0 {
		return nil
	}
	// Backup nur, wenn die Datenbank schon Inhalt hat (irgendeine Migration
	// irgendeines Scopes), nicht beim allerersten Anlegen.
	var total int
	if err := s.r.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&total); err != nil {
		return err
	}
	if !s.backedUp && total > 0 {
		if _, err := s.BackupBeforeMigration(ctx); err != nil {
			return fmt.Errorf("backup before migration: %w", err)
		}
		s.backedUp = true
	}
	for _, m := range pending {
		if err := s.applyMigration(ctx, scope, m); err != nil {
			return fmt.Errorf("migration %s/%d (%s): %w", scope, m.Version, m.Name, err)
		}
		s.log.Info("migration applied", "scope", scope, "version", m.Version, "name", m.Name)
	}
	return nil
}

// checkNewer merkt Scopes, deren Datenbank Migrationen hat, die dieses Programm nicht kennt (aelteres Programm auf
// neuerem Schema, z. B. nach einem Rueckfall ohne zurueckgespielte Sicherung). Kein Abbruch: ein Start-Verbot
// wuerde die Node nach einem Rueckfall unbrauchbar machen; deutliche Warnung im Log und SchemaNewer fuer die Anzeige.
func (s *Store) checkNewer(scope string, applied map[int]bool, known int) {
	var newer []int
	for v := range applied {
		if v > known {
			newer = append(newer, v)
		}
	}
	if len(newer) == 0 {
		return
	}
	sort.Ints(newer)
	s.newerMu.Lock()
	if s.newer == nil {
		s.newer = map[string][]int{}
	}
	s.newer[scope] = newer
	s.newerMu.Unlock()
	s.log.Error("database schema is newer than this program: update Node64 or restore a matching backup",
		"scope", scope, "known_version", known, "unknown_versions", fmt.Sprint(newer))
}

// SchemaNewer liefert je Scope die angewendeten Migrationen, die dieses Programm nicht kennt (leer = alles passt).
func (s *Store) SchemaNewer() map[string][]int {
	s.newerMu.Lock()
	defer s.newerMu.Unlock()
	out := make(map[string][]int, len(s.newer))
	for k, v := range s.newer {
		out[k] = append([]int(nil), v...)
	}
	return out
}

func (s *Store) applyMigration(ctx context.Context, scope string, m Migration) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (scope, version, name, applied_at) VALUES (?, ?, ?, ?)`,
		scope, m.Version, m.Name, Now()); err != nil {
		return err
	}
	return tx.Commit()
}

// Backup schreibt eine konsistente Kopie der Datenbank nach dest, auch im
// laufenden Betrieb (VACUUM INTO arbeitet in einer Lesetransaktion).
func (s *Store) Backup(ctx context.Context, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return err
	}
	_ = os.Remove(dest)
	q := "VACUUM INTO '" + strings.ReplaceAll(filepath.ToSlash(dest), "'", "''") + "'"
	_, err := s.w.ExecContext(ctx, q)
	return err
}

// BackupBeforeMigration legt ein Backup unter backupDir an und behaelt die
// letzten fuenf.
func (s *Store) BackupBeforeMigration(ctx context.Context) (string, error) {
	name := "agent-" + time.Now().UTC().Format("20060102-150405") + "-pre-migration.db"
	dest := filepath.Join(s.backupDir, name)
	if err := s.Backup(ctx, dest); err != nil {
		return "", err
	}
	s.log.Info("backup written before migration", "file", dest)
	s.pruneBackups("-pre-migration.db", 5)
	return dest, nil
}

func (s *Store) pruneBackups(suffix string, keep int) {
	entries, err := os.ReadDir(s.backupDir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), suffix) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for len(names) > keep {
		_ = os.Remove(filepath.Join(s.backupDir, names[0]))
		names = names[1:]
	}
}
