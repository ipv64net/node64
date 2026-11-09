// Package tsdb ist der Verlaufsspeicher von Monitor64: Messreihen (float64 mit Zeitstempel) in einer
// eigenen SQLite-Datei (monitor64.db).
//
// Je Reihe und Stunde entsteht ein Rohblock (Delta-of-Delta-Zeitstempel, skalierte Ganzzahl-Deltas,
// Varint, deflate). Der laufende Block liegt im Speicher und wird alle FlushInterval gesichert (Upsert),
// ausserdem bei Close. Ist eine Stunde voll, entstehen 5-Minuten- und Stundenwerte (Min/Mittel/Max/Anzahl),
// gespeichert als Bloecke je Reihe und Tag bzw. je Reihe und 30 Tage. Query waehlt die Aufloesung selbst.
package tsdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/store"
	_ "modernc.org/sqlite"
)

const (
	hour      = 3600
	sealGrace = 120 // Sekunden nach Stundenende, bis Flush eine Stunde ohne neue Punkte abschliesst
	maxFuture = 600 // Punkte weiter in der Zukunft werden verworfen (Uhr falsch)

	defaultDigits    = 3
	defaultMaxPoints = 700
	flushBatch       = 500 // Reihen je Transaktion
)

// ErrClosed: die Datenbank ist geschlossen.
var ErrClosed = errors.New("tsdb: geschlossen")

// Options steuert Aufbewahrung und Sicherung. Bei den Aufbewahrungen bedeutet 0 unbegrenzt; die
// Standardwerte liefert DefaultOptions.
type Options struct {
	RetentionRaw time.Duration // Rohwerte (Standard 48 h)
	Retention5m  time.Duration // 5-Minuten-Werte (Standard 30 Tage)
	Retention1h  time.Duration // Stundenwerte (Standard 1 Jahr)

	FlushInterval time.Duration    // Sicherung des laufenden Blocks (0 = 5 min, < 0 = keine Hintergrund-Sicherung)
	Digits        int              // Nachkommastellen beim Speichern (0 = 3, hoechstens 6)
	Logger        *slog.Logger     // nil = keine Ausgabe
	Now           func() time.Time // nil = time.Now (Tests)
}

// DefaultOptions liefert die Standard-Aufbewahrung (roh 48 h, 5 min 30 Tage, 1 h 1 Jahr).
func DefaultOptions() Options {
	return Options{
		RetentionRaw: 48 * time.Hour,
		Retention5m:  30 * 24 * time.Hour,
		Retention1h:  365 * 24 * time.Hour,
	}
}

// Stats beschreibt den Zustand fuer die Einstellungen und Prometheus.
type Stats struct {
	Series        int           // bekannte Reihen
	Points        int           // Rohpunkte im Speicher (laufende und noch nicht gesicherte Stunden)
	Dropped       uint64        // verworfene Punkte (NaN, verspaetet, doppelt, Zukunft)
	LastFlush     time.Time     // letzte erfolgreiche Sicherung
	FlushDuration time.Duration // Dauer der letzten Sicherung
}

// DB ist ein geoeffneter Verlaufsspeicher. Alle Methoden sind nebenlaeufig sicher.
type DB struct {
	sql    *sql.DB
	path   string
	opts   Options
	log    *slog.Logger
	now    func() time.Time
	digits int

	mu     sync.RWMutex // schuetzt die Map (nicht die Reihen selbst)
	series map[string]*series

	wmu sync.Mutex // ein Schreiber: Flush, Purge, DeleteSeriesPrefix

	dropped   atomic.Uint64
	lastFlush atomic.Int64 // UnixNano
	flushDur  atomic.Int64
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
	stop      chan struct{}
	done      chan struct{}
}

// series ist eine Messreihe mit laufendem Block im Speicher.
type series struct {
	mu     sync.Mutex
	key    string
	id     int64 // 0 = noch nicht in der Datenbank
	floor  int64 // Ende der letzten abgeschlossenen Stunde; aeltere Punkte werden verworfen
	start  int64 // Beginn der laufenden Stunde (gueltig, wenn len(off) > 0)
	off    []uint16
	val    []float64
	saved  int           // so viele Punkte des laufenden Blocks sind gesichert
	sealed []sealedBlock // abgeschlossene Stunden, noch nicht geschrieben
	gone   bool          // aus der Map entfernt (geloescht oder aufgeraeumt)
}

// sealedBlock ist eine abgeschlossene Stunde samt Verdichtung.
type sealedBlock struct {
	start int64
	n     int
	data  []byte
	agg5  []aggPt
	agg1h []aggPt
}

const schema = `
CREATE TABLE IF NOT EXISTS series (
	id     INTEGER PRIMARY KEY,
	key    TEXT    NOT NULL UNIQUE,
	sealed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS blk_raw (
	sid   INTEGER NOT NULL,
	start INTEGER NOT NULL,
	n     INTEGER NOT NULL,
	fin   INTEGER NOT NULL DEFAULT 0,
	data  BLOB    NOT NULL,
	PRIMARY KEY (sid, start)
);
CREATE INDEX IF NOT EXISTS blk_raw_start ON blk_raw(start);
CREATE INDEX IF NOT EXISTS blk_raw_open ON blk_raw(sid) WHERE fin = 0;
CREATE TABLE IF NOT EXISTS blk_5m (
	sid   INTEGER NOT NULL,
	start INTEGER NOT NULL,
	n     INTEGER NOT NULL,
	data  BLOB    NOT NULL,
	PRIMARY KEY (sid, start)
);
CREATE INDEX IF NOT EXISTS blk_5m_start ON blk_5m(start);
CREATE TABLE IF NOT EXISTS blk_1h (
	sid   INTEGER NOT NULL,
	start INTEGER NOT NULL,
	n     INTEGER NOT NULL,
	data  BLOB    NOT NULL,
	PRIMARY KEY (sid, start)
);
CREATE INDEX IF NOT EXISTS blk_1h_start ON blk_1h(start);
`

// Open oeffnet (oder legt an) die Datei path. Unvollstaendige Bloecke der laufenden Stunde werden wieder
// in den Speicher geladen, aeltere unvollstaendige beim naechsten Flush abgeschlossen.
func Open(path string, opts Options) (*DB, error) {
	// auto_vacuum wirkt nur beim Anlegen und muss vor den Tabellen stehen
	dsn := "file:" + path + "?_pragma=auto_vacuum(INCREMENTAL)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=temp_store(MEMORY)"
	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	sdb.SetMaxOpenConns(4)
	if _, err := sdb.Exec(schema); err != nil {
		sdb.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	store.PrivateFiles(path) // Messwerte der Hosts: nur der Node-Benutzer

	db := &DB{sql: sdb, path: path, opts: opts, series: map[string]*series{}}
	db.log = opts.Logger
	if db.log == nil {
		db.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	db.now = opts.Now
	if db.now == nil {
		db.now = time.Now
	}
	db.digits = opts.Digits
	if db.digits <= 0 {
		db.digits = defaultDigits
	}
	db.digits = min(db.digits, 6)
	if err := db.load(); err != nil {
		sdb.Close()
		return nil, err
	}
	interval := opts.FlushInterval
	if interval == 0 {
		interval = 5 * time.Minute
	}
	if interval > 0 {
		db.stop = make(chan struct{})
		db.done = make(chan struct{})
		go db.loop(interval)
	}
	return db, nil
}

// load liest alle Reihen und die noch offenen Bloecke.
func (db *DB) load() error {
	rows, err := db.sql.Query(`SELECT id, key, sealed FROM series`)
	if err != nil {
		return fmt.Errorf("load series: %w", err)
	}
	byID := map[int64]*series{}
	for rows.Next() {
		s := &series{}
		if err := rows.Scan(&s.id, &s.key, &s.floor); err != nil {
			rows.Close()
			return err
		}
		db.series[s.key] = s
		byID[s.id] = s
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	rows, err = db.sql.Query(`SELECT sid, start, data FROM blk_raw WHERE fin = 0 ORDER BY sid, start`)
	if err != nil {
		return fmt.Errorf("load blocks: %w", err)
	}
	defer rows.Close()
	now := db.now().Unix()
	nowHour := now - now%hour
	for rows.Next() {
		var sid, start int64
		var data []byte
		if err := rows.Scan(&sid, &start, &data); err != nil {
			return err
		}
		s := byID[sid]
		if s == nil {
			continue
		}
		ts, vs, err := decodeRaw(data)
		if err != nil {
			db.log.Warn("monitor64: block unreadable", "series", s.key, "start", start, "err", err)
			continue
		}
		if len(s.off) > 0 {
			s.seal(db.digits)
		}
		if start < nowHour {
			// Stunde vorbei, aber nie abgeschlossen (Absturz): beim naechsten Flush nachholen
			s.sealed = append(s.sealed, makeSealed(start, ts, vs, db.digits))
			s.floor = max(s.floor, start+hour)
			continue
		}
		s.start = start
		for i, t := range ts {
			if t >= start && t < start+hour && (len(s.off) == 0 || uint16(t-start) > s.off[len(s.off)-1]) {
				s.off = append(s.off, uint16(t-start))
				s.val = append(s.val, vs[i])
			}
		}
		s.saved = len(s.off)
	}
	return rows.Err()
}

func (db *DB) loop(interval time.Duration) {
	defer close(db.done)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-db.stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), interval)
			if err := db.Flush(ctx); err != nil && !errors.Is(err, ErrClosed) {
				db.log.Warn("monitor64: flush failed", "err", err)
			}
			cancel()
		}
	}
}

// Close beendet die Hintergrund-Sicherung, sichert alles und schliesst die Datei.
func (db *DB) Close() error {
	db.closeOnce.Do(func() {
		db.closed.Store(true)
		if db.stop != nil {
			close(db.stop)
			<-db.done
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		db.wmu.Lock()
		err := db.flushLocked(ctx)
		db.wmu.Unlock()
		if cerr := db.sql.Close(); err == nil {
			err = cerr
		}
		db.closeErr = err
	})
	return db.closeErr
}

// Append nimmt einen Messwert auf. Verworfen (und gezaehlt) werden NaN/Inf, Punkte aus bereits
// abgeschlossenen Stunden, nicht aufsteigende Zeitstempel einer Reihe und Punkte weit in der Zukunft.
func (db *DB) Append(key string, t time.Time, v float64) {
	ts := t.Unix()
	if db.closed.Load() || key == "" || !finite(v) || ts <= 0 || ts > db.now().Unix()+maxFuture {
		db.dropped.Add(1)
		return
	}
	for {
		s := db.get(key)
		s.mu.Lock()
		if s.gone {
			s.mu.Unlock()
			continue
		}
		ok := s.add(ts, v, db.digits)
		s.mu.Unlock()
		if !ok {
			db.dropped.Add(1)
		}
		return
	}
}

func (db *DB) get(key string) *series {
	db.mu.RLock()
	s := db.series[key]
	db.mu.RUnlock()
	if s != nil {
		return s
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if s = db.series[key]; s == nil {
		s = &series{key: key}
		db.series[key] = s
	}
	return s
}

func (db *DB) lookup(key string) *series {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.series[key]
}

// add haengt einen Punkt an (s.mu gehalten).
func (s *series) add(ts int64, v float64, digits int) bool {
	if ts < s.floor {
		return false
	}
	h := ts - ts%hour
	if len(s.off) > 0 {
		switch {
		case h > s.start:
			s.seal(digits)
		case h < s.start, uint16(ts-h) <= s.off[len(s.off)-1]:
			return false
		}
	}
	if len(s.off) == 0 {
		s.start = h
		s.saved = 0
	}
	s.off = append(s.off, uint16(ts-h))
	s.val = append(s.val, v)
	return true
}

// seal schliesst die laufende Stunde ab (s.mu gehalten).
func (s *series) seal(digits int) {
	if len(s.off) == 0 {
		return
	}
	s.sealed = append(s.sealed, makeSealed(s.start, s.times(), s.val, digits))
	s.floor = max(s.floor, s.start+hour)
	s.off = s.off[:0]
	s.val = s.val[:0]
	s.saved = 0
}

func (s *series) times() []int64 {
	ts := make([]int64, len(s.off))
	for i, o := range s.off {
		ts[i] = s.start + int64(o)
	}
	return ts
}

func makeSealed(start int64, ts []int64, vs []float64, digits int) sealedBlock {
	return sealedBlock{
		start: start,
		n:     len(ts),
		data:  encodeBlock(ts, [][]float64{vs}, digits),
		agg5:  aggregate(ts, vs, 300),
		agg1h: aggregate(ts, vs, hour),
	}
}

// Stats liefert Zaehler fuer Einstellungen und Prometheus.
func (db *DB) Stats() Stats {
	db.mu.RLock()
	list := make([]*series, 0, len(db.series))
	for _, s := range db.series {
		list = append(list, s)
	}
	db.mu.RUnlock()
	st := Stats{Series: len(list), Dropped: db.dropped.Load(), FlushDuration: time.Duration(db.flushDur.Load())}
	for _, s := range list {
		s.mu.Lock()
		st.Points += len(s.off)
		for _, b := range s.sealed {
			st.Points += b.n
		}
		s.mu.Unlock()
	}
	if ns := db.lastFlush.Load(); ns != 0 {
		st.LastFlush = time.Unix(0, ns)
	}
	return st
}

// Size ist die Groesse der Datei samt WAL in Byte.
func (db *DB) Size() int64 {
	var n int64
	for _, p := range []string{db.path, db.path + "-wal"} {
		if fi, err := os.Stat(p); err == nil {
			n += fi.Size()
		}
	}
	return n
}

// aggPt ist ein verdichteter Punkt (bei Rohwerten Min = Avg = Max, N = 1).
type aggPt struct {
	t                int64
	min, avg, max, n float64
}

// aggregate verdichtet aufsteigende Rohpunkte auf Zeitfenster der Breite step.
func aggregate(ts []int64, vs []float64, step int64) []aggPt {
	var out []aggPt
	for i, t := range ts {
		v := vs[i]
		b := t - t%step
		if len(out) == 0 || out[len(out)-1].t != b {
			out = append(out, aggPt{t: b, min: v, avg: v, max: v, n: 1})
			continue
		}
		p := &out[len(out)-1]
		p.min = math.Min(p.min, v)
		p.max = math.Max(p.max, v)
		p.avg += v // Summe, unten geteilt
		p.n++
	}
	for i := range out {
		out[i].avg /= out[i].n
	}
	return out
}

func decodeRaw(b []byte) ([]int64, []float64, error) {
	ts, cols, err := decodeBlock(b)
	if err != nil {
		return nil, nil, err
	}
	if len(cols) != 1 {
		return nil, nil, errBadBlock
	}
	return ts, cols[0], nil
}

func encodeAgg(pts []aggPt, digits int) []byte {
	ts := make([]int64, len(pts))
	cols := [][]float64{make([]float64, len(pts)), make([]float64, len(pts)), make([]float64, len(pts)), make([]float64, len(pts))}
	for i, p := range pts {
		ts[i] = p.t
		cols[0][i], cols[1][i], cols[2][i], cols[3][i] = p.min, p.avg, p.max, p.n
	}
	return encodeBlock(ts, cols, digits)
}

func decodeAgg(b []byte) ([]aggPt, error) {
	ts, cols, err := decodeBlock(b)
	if err != nil {
		return nil, err
	}
	if len(cols) != 4 {
		return nil, errBadBlock
	}
	pts := make([]aggPt, len(ts))
	for i, t := range ts {
		pts[i] = aggPt{t: t, min: cols[0][i], avg: cols[1][i], max: cols[2][i], n: cols[3][i]}
	}
	return pts, nil
}

// mergeAgg fuegt neue Punkte in aufsteigende alte ein; gleicher Zeitstempel: der neue gilt.
func mergeAgg(old, add []aggPt) []aggPt {
	out := make([]aggPt, 0, len(old)+len(add))
	i, j := 0, 0
	for i < len(old) || j < len(add) {
		switch {
		case j == len(add) || (i < len(old) && old[i].t < add[j].t):
			out = append(out, old[i])
			i++
		case i == len(old) || add[j].t < old[i].t:
			out = append(out, add[j])
			j++
		default:
			out = append(out, add[j])
			i++
			j++
		}
	}
	return out
}
