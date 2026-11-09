package tsdb

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Aufloesungen: Rohwerte je Stunde, 5-Minuten-Werte je Tag, Stundenwerte je 30 Tage (an der Epoche
// ausgerichtet, damit eine Stunde immer ganz in einem Block liegt).
type level struct {
	name  string
	table string
	step  int64 // Breite eines Punkts (0 = Rohwerte)
	span  int64 // Zeitraum eines Blocks
}

var levels = [...]level{
	{name: "raw", table: "blk_raw", step: 0, span: hour},
	{name: "5m", table: "blk_5m", step: 300, span: 86400},
	{name: "1h", table: "blk_1h", step: hour, span: 30 * 86400},
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
	runData  []byte // nil = laufender Block unveraendert
	sealed   []sealedBlock
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
			s.seal(db.digits)
		}
		j := flushJob{s: s, key: s.key, id: s.id, sealed: s.sealed}
		if len(s.off) > s.saved {
			j.runStart, j.runN = s.start, len(s.off)
			j.runData = encodeBlock(s.times(), [][]float64{s.val}, db.digits)
		}
		s.mu.Unlock()
		if j.runData != nil || len(j.sealed) > 0 {
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
	st.updFloor = p(`UPDATE series SET sealed = max(sealed, ?) WHERE id = ?`)
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
			if _, err := st.updFloor.ExecContext(ctx, b.start+hour, j.id); err != nil {
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
			if rest := s.sealed[n:]; len(rest) > 0 {
				s.sealed = append([]sealedBlock(nil), rest...)
			} else {
				s.sealed = nil
			}
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
