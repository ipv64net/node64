package tsdb

import (
	"context"
	"errors"
	"strings"
	"time"
)

const purgeChunk = 1000 // Bloecke je Loeschschritt; dazwischen kommt der Schreiber wieder dran

// Purge loescht Bloecke ausserhalb der Aufbewahrung, danach Reihen ohne Daten, und gibt freie Seiten
// an das Dateisystem zurueck. Gearbeitet wird in Stuecken; Flush und Append laufen dazwischen weiter.
// Gedacht fuer einen naechtlichen Aufruf. Liefert die Zahl geloeschter Bloecke.
func (db *DB) Purge(ctx context.Context, now time.Time) (int64, error) {
	if db.closed.Load() {
		return 0, ErrClosed
	}
	keep := [...]time.Duration{db.opts.RetentionRaw, db.opts.Retention5m, db.opts.Retention1h}
	var total int64
	for lv, L := range levels {
		if keep[lv] <= 0 {
			continue
		}
		// ein Block faellt weg, wenn sein ganzer Zeitraum vor der Grenze liegt
		limit := now.Unix() - int64(keep[lv]/time.Second) - L.span
		q := `DELETE FROM ` + L.table + ` WHERE rowid IN (SELECT rowid FROM ` + L.table + ` WHERE start <= ?`
		if lv == 0 {
			q += ` AND fin = 1` // offene Bloecke erst nach dem Abschluss
		}
		q += ` LIMIT ?)`
		for {
			n, err := db.step(ctx, func() (int64, error) {
				res, err := db.sql.ExecContext(ctx, q, limit, purgeChunk)
				if err != nil {
					return 0, err
				}
				return res.RowsAffected()
			})
			total += n
			if err != nil {
				return total, err
			}
			if n < purgeChunk {
				break
			}
		}
	}
	if err := db.dropOrphans(ctx); err != nil {
		return total, err
	}
	return total, db.vacuum(ctx)
}

// step fuehrt einen Schreibschritt unter der Schreibsperre aus.
func (db *DB) step(ctx context.Context, f func() (int64, error)) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	db.wmu.Lock()
	defer db.wmu.Unlock()
	if db.closed.Load() {
		return 0, ErrClosed
	}
	return f()
}

// dropOrphans entfernt Reihen, die weder Bloecke noch Punkte im Speicher haben.
func (db *DB) dropOrphans(ctx context.Context) error {
	_, err := db.step(ctx, func() (int64, error) {
		rows, err := db.sql.QueryContext(ctx, `SELECT id, key FROM series s
			WHERE NOT EXISTS (SELECT 1 FROM blk_raw WHERE sid = s.id)
			AND NOT EXISTS (SELECT 1 FROM blk_5m WHERE sid = s.id)
			AND NOT EXISTS (SELECT 1 FROM blk_1h WHERE sid = s.id)`)
		if err != nil {
			return 0, err
		}
		cand := map[string]int64{}
		for rows.Next() {
			var id int64
			var key string
			if err := rows.Scan(&id, &key); err != nil {
				rows.Close()
				return 0, err
			}
			cand[key] = id
		}
		rows.Close()
		if err := rows.Err(); err != nil || len(cand) == 0 {
			return 0, err
		}
		var ids []any
		db.mu.Lock()
		for key, id := range cand {
			s := db.series[key]
			if s != nil {
				s.mu.Lock()
				idle := s.id == id && len(s.off) == 0 && len(s.sealed) == 0
				if idle {
					s.gone = true
				}
				s.mu.Unlock()
				if !idle {
					continue
				}
				delete(db.series, key)
			}
			ids = append(ids, id)
		}
		db.mu.Unlock()
		return 0, db.deleteIDs(ctx, ids, false)
	})
	return err
}

// deleteIDs loescht Reihen (und auf Wunsch ihre Bloecke) in Transaktionen zu je 200 Reihen.
func (db *DB) deleteIDs(ctx context.Context, ids []any, blocks bool) error {
	for len(ids) > 0 {
		n := min(len(ids), 200)
		in := "(" + strings.TrimSuffix(strings.Repeat("?,", n), ",") + ")"
		tx, err := db.sql.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		qs := []string{`DELETE FROM series WHERE id IN ` + in}
		if blocks {
			for _, L := range levels {
				qs = append(qs, `DELETE FROM `+L.table+` WHERE sid IN `+in)
			}
		}
		for _, q := range qs {
			if _, err := tx.ExecContext(ctx, q, ids[:n]...); err != nil {
				tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		ids = ids[n:]
	}
	return nil
}

// vacuum gibt freie Seiten in Stuecken zurueck (auto_vacuum=INCREMENTAL).
func (db *DB) vacuum(ctx context.Context) error {
	prev := int64(-1)
	for {
		free, err := db.step(ctx, func() (int64, error) {
			var free int64
			if err := db.sql.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&free); err != nil || free == 0 {
				return free, err
			}
			_, err := db.sql.ExecContext(ctx, `PRAGMA incremental_vacuum(2000)`)
			return free, err
		})
		if err != nil {
			return err
		}
		if free == 0 || free == prev {
			return nil // nichts frei oder kein Fortschritt (z. B. Datei ohne auto_vacuum)
		}
		prev = free
	}
}

// DeleteSeriesPrefix loescht alle Reihen, deren Schluessel mit prefix beginnt (Host entfernt), samt
// Punkten im Speicher. Liefert die Zahl der Reihen.
func (db *DB) DeleteSeriesPrefix(ctx context.Context, prefix string) (int, error) {
	if prefix == "" {
		return 0, errors.New("tsdb: leeres Praefix")
	}
	if db.closed.Load() {
		return 0, ErrClosed
	}
	db.wmu.Lock()
	defer db.wmu.Unlock()
	n := 0
	db.mu.Lock()
	for key, s := range db.series {
		if strings.HasPrefix(key, prefix) {
			s.mu.Lock()
			s.gone = true
			s.mu.Unlock()
			delete(db.series, key)
			n++
		}
	}
	db.mu.Unlock()

	rows, err := db.sql.QueryContext(ctx, `SELECT id FROM series WHERE instr(key, ?) = 1`, prefix)
	if err != nil {
		return n, err
	}
	var ids []any
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return n, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return n, err
	}
	return max(n, len(ids)), db.deleteIDs(ctx, ids, true)
}
