package querylog

import (
	"context"
	"database/sql"
	"time"
)

// Aggregate fuer Uebersicht, Dashboard-Karte und Geraeteliste: Statt bei jedem Aufruf Millionen Zeilen in queries zu
// zaehlen, fuehrt write() je Minute die Zaehler (agg_min) und je Stunde die Haeufigkeiten je Domain bzw. Client
// (agg_top) mit. Die Auswertungen lesen nur noch diese kleinen Tabellen; aufgeraeumt wird mit derselben Aufbewahrung.

const aggSchema = `
CREATE TABLE IF NOT EXISTS agg_min (
	m       INTEGER PRIMARY KEY, -- Unix-Minute
	total   INTEGER NOT NULL DEFAULT 0,
	blocked INTEGER NOT NULL DEFAULT 0,
	cached  INTEGER NOT NULL DEFAULT 0,
	up_n    INTEGER NOT NULL DEFAULT 0, -- weitergeleitete Anfragen (fuer die mittlere Antwortzeit)
	up_us   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS agg_top (
	h       INTEGER NOT NULL, -- Unix-Stunde
	kind    INTEGER NOT NULL, -- topAllowed, topBlocked, topClient
	name    TEXT    NOT NULL,
	n       INTEGER NOT NULL DEFAULT 0,
	blocked INTEGER NOT NULL DEFAULT 0,
	last    INTEGER NOT NULL DEFAULT 0, -- letzte Anfrage (Unix-ms), nur Clients
	grp     TEXT    NOT NULL DEFAULT '',
	PRIMARY KEY (h, kind, name)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_agg_top_kind ON agg_top(kind, h);
`

const (
	topAllowed = 0
	topBlocked = 1
	topClient  = 2
)

type aggMin struct{ total, blocked, cached, upN, upUs int64 }

type topKey struct {
	h    int64
	kind int
	name string
}

type topVal struct {
	n, blocked, last int64
	grp              string
}

// aggregate fasst einen Stapel fuer die Aggregat-Tabellen zusammen.
func aggregate(batch []Entry) (map[int64]*aggMin, map[topKey]*topVal) {
	mins, tops := map[int64]*aggMin{}, map[topKey]*topVal{}
	add := func(k topKey, blocked bool, ts int64, grp string) {
		v := tops[k]
		if v == nil {
			v = &topVal{}
			tops[k] = v
		}
		v.n++
		if blocked {
			v.blocked++
		}
		if ts > v.last {
			v.last = ts
		}
		if grp != "" {
			v.grp = grp
		}
	}
	for _, e := range batch {
		ms := e.Time.UnixMilli()
		m := mins[ms/60000]
		if m == nil {
			m = &aggMin{}
			mins[ms/60000] = m
		}
		m.total++
		switch e.Status {
		case StatusBlocked:
			m.blocked++
		case StatusCached:
			m.cached++
		case StatusAllowed:
			m.upN++
			m.upUs += e.Duration.Microseconds()
		}
		h := ms / 3600000
		switch e.Status {
		case StatusBlocked:
			add(topKey{h, topBlocked, e.Domain}, true, 0, "")
		case StatusAllowed, StatusCached, StatusLocal, StatusCustom: // wie Top "allowed" bisher (0, 1, 3, 5)
			add(topKey{h, topAllowed, e.Domain}, false, 0, "")
		}
		if e.Client != "" {
			add(topKey{h, topClient, e.Client}, e.Status == StatusBlocked, ms, e.Group)
		}
	}
	return mins, tops
}

// writeAgg schreibt die Aggregate eines Stapels in der Transaktion des Stapels.
func writeAgg(tx *sql.Tx, batch []Entry) error {
	mins, tops := aggregate(batch)
	sm, err := tx.Prepare(`INSERT INTO agg_min (m, total, blocked, cached, up_n, up_us) VALUES (?,?,?,?,?,?)
		ON CONFLICT(m) DO UPDATE SET total = total + excluded.total, blocked = blocked + excluded.blocked, cached = cached + excluded.cached,
		up_n = up_n + excluded.up_n, up_us = up_us + excluded.up_us`)
	if err != nil {
		return err
	}
	defer sm.Close()
	for m, v := range mins {
		if _, err := sm.Exec(m, v.total, v.blocked, v.cached, v.upN, v.upUs); err != nil {
			return err
		}
	}
	st, err := tx.Prepare(`INSERT INTO agg_top (h, kind, name, n, blocked, last, grp) VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(h, kind, name) DO UPDATE SET n = n + excluded.n, blocked = blocked + excluded.blocked, last = MAX(last, excluded.last),
		grp = CASE WHEN excluded.grp != '' THEN excluded.grp ELSE grp END`)
	if err != nil {
		return err
	}
	defer st.Close()
	for k, v := range tops {
		if _, err := st.Exec(k.h, k.kind, k.name, v.n, v.blocked, v.last, v.grp); err != nil {
			return err
		}
	}
	return nil
}

// backfillAgg baut die Aggregate einmalig aus vorhandenen Eintraegen (Update von einer Version ohne Aggregate).
func (s *Store) backfillAgg() {
	var have, rows int64
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM (SELECT 1 FROM agg_min LIMIT 1)`).Scan(&have)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM (SELECT 1 FROM queries LIMIT 1)`).Scan(&rows)
	if have > 0 || rows == 0 {
		return
	}
	start := time.Now()
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	for _, q := range []string{
		`INSERT INTO agg_min (m, total, blocked, cached, up_n, up_us)
			SELECT ts / 60000, COUNT(*), SUM(status = 2), SUM(status = 1), SUM(status = 0), SUM(CASE WHEN status = 0 THEN duration_us ELSE 0 END)
			FROM queries GROUP BY ts / 60000`,
		`INSERT INTO agg_top (h, kind, name, n, blocked, last, grp)
			SELECT ts / 3600000, 1, domain, COUNT(*), COUNT(*), 0, '' FROM queries WHERE status = 2 GROUP BY ts / 3600000, domain`,
		`INSERT INTO agg_top (h, kind, name, n, blocked, last, grp)
			SELECT ts / 3600000, 0, domain, COUNT(*), 0, 0, '' FROM queries WHERE status IN (0, 1, 3, 5) GROUP BY ts / 3600000, domain`,
		`INSERT INTO agg_top (h, kind, name, n, blocked, last, grp)
			SELECT ts / 3600000, 2, client, COUNT(*), SUM(status = 2), MAX(ts), MAX(grp) FROM queries WHERE client != '' GROUP BY ts / 3600000, client`,
	} {
		if _, err := tx.Exec(q); err != nil {
			tx.Rollback()
			s.log.Error("querylog backfill", "err", err)
			return
		}
	}
	if err := tx.Commit(); err == nil {
		s.log.Info("querylog statistics built from existing entries", "took", time.Since(start).Round(time.Millisecond))
	}
}

// pruneAgg loescht abgelaufene Aggregate (klein, in einem Schritt).
func (s *Store) pruneAgg(cutoffMs int64) {
	_, _ = s.db.Exec(`DELETE FROM agg_min WHERE m < ?`, cutoffMs/60000)
	_, _ = s.db.Exec(`DELETE FROM agg_top WHERE h < ?`, cutoffMs/3600000)
}

// CountCap: hoechstens so viele Treffer zaehlt die Log-Seite (danach "mehr als"); Zaehlen ueber Millionen Zeilen
// mit Textsuche dauert sonst Sekunden.
const CountCap = 100000

func (s *Store) cappedCount(ctx context.Context, cond string, args []any) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM (SELECT 1 FROM queries"+cond+" LIMIT ?)", append(args, CountCap)...).Scan(&n)
	return n, err
}
