package tsdb

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"time"
)

// Aufloesungen: Rohwerte je Stunde, 5-Minuten-Werte je Tag, Stundenwerte je 7 Tage (an der Epoche
// ausgerichtet, damit eine Stunde immer ganz in einem Block liegt). Jeder Stundenabschluss liest, mischt
// und schreibt je Reihe beide Verdichtungsbloecke; die Spannen halten diese Bloecke klein (hoechstens 288
// bzw. 168 Punkte, ca. 1 KB bzw. 0,7 KB). Vor Dateiversion 2 waren es 30 Tage (720 Punkte, migrate).
type level struct {
	name  string
	table string
	step  int64 // Breite eines Punkts (0 = Rohwerte)
	span  int64 // Zeitraum eines Blocks
}

var levels = [...]level{
	{name: "raw", table: "blk_raw", step: 0, span: hour},
	{name: "5m", table: "blk_5m", step: 300, span: 86400},
	{name: "1h", table: "blk_1h", step: hour, span: 7 * 86400},
}

// migrate bringt die Datei auf fileVersion. old1h: die Stundenbloecke stammen aus einer aelteren Version
// (Version 0: je 30 Tage) und werden in Bloecke der aktuellen Spanne aufgeteilt (eine Transaktion).
func (db *DB) migrate(old1h bool) error {
	tx, err := db.sql.Begin()
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	defer tx.Rollback()
	if old1h {
		L := levels[2]
		rows, err := tx.Query(`SELECT sid, start, data FROM ` + L.table + ` ORDER BY sid, start`)
		if err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		bySid := map[int64][]aggPt{}
		var sids []int64
		for rows.Next() {
			var sid, start int64
			var data []byte
			if err := rows.Scan(&sid, &start, &data); err != nil {
				rows.Close()
				return fmt.Errorf("migrate: %w", err)
			}
			pts, derr := decodeAgg(data)
			if derr != nil {
				db.log.Warn("monitor64: aggregate block unreadable, dropped", "level", L.name, "sid", sid, "start", start)
				continue
			}
			if _, ok := bySid[sid]; !ok {
				sids = append(sids, sid)
			}
			bySid[sid] = mergeAgg(bySid[sid], pts)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM ` + L.table); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		for _, sid := range sids {
			pts := bySid[sid]
			for len(pts) > 0 {
				start := pts[0].t - pts[0].t%L.span
				n := 1
				for n < len(pts) && pts[n].t-pts[n].t%L.span == start {
					n++
				}
				if _, err := tx.Exec(`INSERT INTO `+L.table+`(sid, start, n, data) VALUES(?, ?, ?, ?)`, sid, start, n, encodeAgg(pts[:n], db.digits)); err != nil {
					return fmt.Errorf("migrate: %w", err)
				}
				pts = pts[n:]
			}
		}
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, fileVersion)); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return tx.Commit()
}

// Flush sichert alle geaenderten laufenden Bloecke und schreibt abgeschlossene Stunden samt Verdichtung.
// Stunden, die seit sealGrace vorbei sind, werden dabei auch ohne neuen Punkt abgeschlossen.
func (db *DB) Flush(ctx context.Context) error {
	if db.closed.Load() {
		return ErrClosed
	}
	db.wmu.Lock()
	defer db.wmu.Unlock()
	return db.flushLocked(ctx)
}

// flushJob ist der Schnappschuss einer Reihe fuer eine Sicherung.
type flushJob struct {
	s        *series
	key      string
	id       int64
	runStart int64
	runN     int
	runData  []byte        // nil = laufender Block unveraendert
	sealed   []sealedBlock // Kopie (pushSealed veraendert s.sealed waehrend des Schreibens)
	floor    int64
	setFloor bool // floor weicht von der Datenbank ab
}

func (db *DB) flushLocked(ctx context.Context) error {
	began := time.Now()
	now := db.now().Unix()
	db.mu.RLock()
	list := make([]*series, 0, len(db.series))
	for _, s := range db.series {
		list = append(list, s)
	}
	db.mu.RUnlock()

	jobs := make([]flushJob, 0, flushBatch)
	for i, s := range list {
		s.mu.Lock()
		if len(s.off) > 0 && now >= s.start+hour+sealGrace {
			db.seal(s)
		}
		j := flushJob{s: s, key: s.key, id: s.id, sealed: slices.Clone(s.sealed), floor: s.floor, setFloor: s.floor != s.dbFloor}
		if len(s.off) > s.saved {
			j.runStart, j.runN = s.start, len(s.off)
			j.runData = encodeBlock(s.times(), [][]float64{s.val}, db.digits)
		}
		s.mu.Unlock()
		if j.runData != nil || len(j.sealed) > 0 || j.setFloor {
			jobs = append(jobs, j)
		}
		if len(jobs) == flushBatch || (i == len(list)-1 && len(jobs) > 0) {
			if err := db.writeJobs(ctx, jobs); err != nil {
				return err
			}
			jobs = jobs[:0]
		}
	}
	db.lastFlush.Store(time.Now().UnixNano())
	db.flushDur.Store(int64(time.Since(began)))
	return nil
}

// stmts sind die vorbereiteten Anweisungen einer Schreib-Transaktion.
type stmts struct {
	insSeries, selSeries, updFloor, upRaw *sql.Stmt
	sel, up                               [3]*sql.Stmt // je Aufloesung (Index 0 ungenutzt)
}

func prepare(ctx context.Context, tx *sql.Tx) (*stmts, error) {
	st := &stmts{}
	var err error
	p := func(q string) *sql.Stmt {
		if err != nil {
			return nil
		}
		var s *sql.Stmt
		s, err = tx.PrepareContext(ctx, q)
		return s
	}
	st.insSeries = p(`INSERT INTO series(key) VALUES(?) ON CONFLICT(key) DO NOTHING`)
	st.selSeries = p(`SELECT id FROM series WHERE key = ?`)
	st.updFloor = p(`UPDATE series SET sealed = ? WHERE id = ?`) // auch kleiner (Uhr zurueckgestellt)
	st.upRaw = p(`INSERT INTO blk_raw(sid, start, n, fin, data) VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(sid, start) DO UPDATE SET n = excluded.n, fin = excluded.fin, data = excluded.data`)
	for i := 1; i < len(levels); i++ {
		t := levels[i].table
		st.sel[i] = p(`SELECT data FROM ` + t + ` WHERE sid = ? AND start = ?`)
		st.up[i] = p(`INSERT INTO ` + t + `(sid, start, n, data) VALUES(?, ?, ?, ?)
			ON CONFLICT(sid, start) DO UPDATE SET n = excluded.n, data = excluded.data`)
	}
	return st, err
}

func (db *DB) writeJobs(ctx context.Context, jobs []flushJob) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := prepare(ctx, tx)
	if err != nil {
		return err
	}
	for k := range jobs {
		j := &jobs[k]
		if j.id == 0 {
			if _, err := st.insSeries.ExecContext(ctx, j.key); err != nil {
				return fmt.Errorf("series: %w", err)
			}
			if err := st.selSeries.QueryRowContext(ctx, j.key).Scan(&j.id); err != nil {
				return fmt.Errorf("series: %w", err)
			}
		}
		for _, b := range j.sealed {
			if _, err := st.upRaw.ExecContext(ctx, j.id, b.start, b.n, 1, b.data); err != nil {
				return fmt.Errorf("raw block: %w", err)
			}
			if err := db.mergeLevel(ctx, st, 1, j.id, b.agg5); err != nil {
				return err
			}
			if err := db.mergeLevel(ctx, st, 2, j.id, b.agg1h); err != nil {
				return err
			}
		}
		if j.setFloor {
			if _, err := st.updFloor.ExecContext(ctx, j.floor, j.id); err != nil {
				return err
			}
		}
		if j.runData != nil {
			if _, err := st.upRaw.ExecContext(ctx, j.id, j.runStart, j.runN, 0, j.runData); err != nil {
				return fmt.Errorf("raw block: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// erst nach dem Commit aus dem Speicher nehmen, damit Abfragen dazwischen nichts fehlt
	for _, j := range jobs {
		s := j.s
		s.mu.Lock()
		s.id = j.id
		if n := len(j.sealed); n > 0 {
			db.unqueue(s, j.sealed[n-1].seq)
		}
		if j.setFloor {
			s.dbFloor = j.floor
		}
		if j.runData != nil && len(s.off) > 0 && s.start == j.runStart && len(s.off) >= j.runN {
			s.saved = j.runN
		}
		s.mu.Unlock()
	}
	return nil
}

// mergeLevel schreibt verdichtete Punkte in den Block ihrer Aufloesung (lesen, mischen, schreiben).
func (db *DB) mergeLevel(ctx context.Context, st *stmts, lv int, sid int64, pts []aggPt) error {
	span := levels[lv].span
	for len(pts) > 0 {
		start := pts[0].t - pts[0].t%span
		n := 1
		for n < len(pts) && pts[n].t-pts[n].t%span == start {
			n++
		}
		var old []byte
		err := st.sel[lv].QueryRowContext(ctx, sid, start).Scan(&old)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		merged := pts[:n]
		if old != nil {
			prev, derr := decodeAgg(old)
			if derr != nil {
				db.log.Warn("monitor64: aggregate block unreadable, replaced", "level", levels[lv].name, "sid", sid, "start", start)
			}
			merged = mergeAgg(prev, pts[:n])
		}
		if _, err := st.up[lv].ExecContext(ctx, sid, start, len(merged), encodeAgg(merged, db.digits)); err != nil {
			return fmt.Errorf("%s block: %w", levels[lv].name, err)
		}
		pts = pts[n:]
	}
	return nil
}
