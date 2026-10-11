package store

import (
	"context"
	"os"
	"path/filepath"
)

// DataStats beschreibt den belegten Speicher der Node.
type DataStats struct {
	DB, WAL, Backups int64
	Backupfiles      int
	Rows             map[string]int64 // Tabelle -> Zeilen (nur die grossen)
}

// Total ist die Summe aller Dateien.
func (d DataStats) Total() int64 { return d.DB + d.WAL + d.Backups }

func fileSize(p string) int64 {
	if fi, err := os.Stat(p); err == nil {
		return fi.Size()
	}
	return 0
}

// Stats liefert Dateigroessen und Zeilenzahlen der grossen Tabellen.
func (s *Store) Stats(ctx context.Context) DataStats {
	d := DataStats{DB: fileSize(s.path), WAL: fileSize(s.path+"-wal") + fileSize(s.path+"-shm"), Rows: map[string]int64{}}
	if s.backupDir != "" {
		_ = filepath.WalkDir(s.backupDir, func(_ string, e os.DirEntry, err error) error {
			if err == nil && !e.IsDir() {
				if fi, err := e.Info(); err == nil {
					d.Backups += fi.Size()
					d.Backupfiles++
				}
			}
			return nil
		})
	}
	for _, t := range []string{"hc_measurements", "hc_events", "hc_hourly", "hc_daily", "nf_deliveries", "audit_log"} {
		var n int64
		if err := s.r.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+t).Scan(&n); err == nil {
			d.Rows[t] = n
		}
	}
	return d
}
