// Package tsdb ist der Verlaufsspeicher von Monitor64: Messreihen (float64 mit Zeitstempel) in einer
// eigenen SQLite-Datei (monitor64.db).
//
// Je Reihe und Stunde entsteht ein Rohblock (Delta-of-Delta-Zeitstempel, skalierte Ganzzahl-Deltas,
// Varint, deflate). Der laufende Block liegt im Speicher und wird alle FlushInterval gesichert (Upsert),
// ausserdem bei Close. Ist eine Stunde voll, entstehen 5-Minuten- und Stundenwerte (Min/Mittel/Max/Anzahl),
// gespeichert als Bloecke je Reihe und Tag bzw. je Reihe und 7 Tage. Query waehlt die Aufloesung selbst.
//
// Uhr zurueckgestellt: liegt der Stand einer Reihe (laufende Stunde, letzte abgeschlossene Stunde) mehr als
// maxFuture vor der Uhr, beginnt die Reihe beim naechsten Punkt neu (Zaehler Stats.ClockResets). Die Stunden
// "aus der Zukunft" bleiben gespeichert, bis neue Daten derselben Stunden sie ersetzen.
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

	fileVersion = 2 // PRAGMA user_version; 2 = Stundenbloecke je 7 Tage (0: je 30 Tage). Spanne geaendert -> erhoehen
)

// Obergrenzen fuer abgeschlossene, noch nicht gesicherte Stunden (Sicherung scheitert dauerhaft): je Reihe
// und insgesamt (Rohpunkte, ca. 12 Byte je Punkt samt Verdichtung). Darueber fallen die aeltesten weg
// (Stats.DroppedBacklog). Variablen fuer Tests.
var (
	maxSealedHours   = 24
	maxBacklogPoints = int64(2_000_000)
)

// ErrClosed: die Datenbank ist geschlossen.
var ErrClosed = errors.New("tsdb: geschlossen")

// Options steuert Aufbewahrung und Sicherung. Bei den Aufbewahrungen bedeutet 0 unbegrenzt; die
// Standardwerte liefert DefaultOptions.
type Options struct {
	RetentionRaw time.Duration // Rohwerte (Standard 48 h)
	Retention5m  time.Duration // 5-Minuten-Werte (Standard 30 Tage)
	Retention1h  time.Duration // Stundenwerte (Standard 1 Jahr)

	FlushInterval time.Duration // Sicherung des laufenden Blocks (0 = 5 min, < 0 = keine Hintergrund-Sicherung)
	// Digits: Nachkommastellen beim Speichern (0 = 3, hoechstens 6). Mindestwert: Spalten eines Blocks mit
	// kleinen Werten (Betrag < 1, z. B. Fehlerraten) bekommen automatisch mehr Stellen, bis 4 signifikante
	// Stellen des groessten Betrags, hoechstens 6 (siehe scaleColumn).
	Digits int
	Logger *slog.Logger     // nil = keine Ausgabe
	Now    func() time.Time // nil = time.Now (Tests)
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
	Series         int           // bekannte Reihen
	Points         int           // Rohpunkte im Speicher (laufende und noch nicht gesicherte Stunden)
	Dropped        uint64        // verworfene Punkte insgesamt (Summe der vier folgenden Zaehler)
	DroppedInvalid uint64        // NaN/Inf, leerer Schluessel, Zeit <= 0, nach Close
	DroppedLate    uint64        // abgeschlossene Stunde, doppelter oder rueckwaerts laufender Zeitstempel
	DroppedFuture  uint64        // mehr als 10 Minuten in der Zukunft
	DroppedBacklog uint64        // nicht gesicherte Stunden ueber der Obergrenze (Sicherung scheitert dauerhaft)
	ClockResets    uint64        // Reihen, die nach zurueckgestellter Uhr neu begonnen haben
	LastFlush      time.Time     // letzte erfolgreiche Sicherung
	FlushDuration  time.Duration // Dauer der letzten Sicherung
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

	dropInvalid atomic.Uint64
	dropLate    atomic.Uint64
	dropFuture  atomic.Uint64
	dropBacklog atomic.Uint64
	resets      atomic.Uint64
	backlog     atomic.Int64 // Rohpunkte in abgeschlossenen, noch nicht gesicherten Stunden
	logReset    throttle
	logBacklog  throttle
	logFlush    throttle

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
	mu      sync.Mutex
	key     string
	id      int64 // 0 = noch nicht in der Datenbank
	floor   int64 // Ende der letzten abgeschlossenen Stunde; aeltere Punkte werden verworfen
	dbFloor int64 // floor in der Datenbank (series.sealed)
	start   int64 // Beginn der laufenden Stunde (gueltig, wenn len(off) > 0)
	off     []uint16
	val     []float64
	saved   int           // so viele Punkte des laufenden Blocks sind gesichert
	sealed  []sealedBlock // abgeschlossene Stunden, noch nicht geschrieben (aufsteigend nach seq)
	seq     uint64        // laufende Nummer der zuletzt abgeschlossenen Stunde
	gone    bool          // aus der Map entfernt (geloescht oder aufgeraeumt)
}

// sealedBlock ist eine abgeschlossene Stunde samt Verdichtung.
type sealedBlock struct {
	seq   uint64
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
	var ver, tables int
	if err := sdb.QueryRow(`PRAGMA user_version`).Scan(&ver); err != nil {
		sdb.Close()
		return nil, fmt.Errorf("file version: %w", err)
	}
	if err := sdb.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'blk_1h'`).Scan(&tables); err != nil {
		sdb.Close()
		return nil, fmt.Errorf("file version: %w", err)
	}
	if ver > fileVersion {
		sdb.Close()
		return nil, fmt.Errorf("tsdb: Dateiversion %d neuer als unterstuetzt (%d)", ver, fileVersion)
	}
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
	if ver < fileVersion {
		// vorhandene Datei aelterer Version (0 = vor der Versionierung, Stundenbloecke je 30 Tage)
		if err := db.migrate(tables > 0); err != nil {
			sdb.Close()
			return nil, err
		}
	}
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
		s.dbFloor = s.floor
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
			db.seal(s)
		}
		if start < nowHour {
			// Stunde vorbei, aber nie abgeschlossen (Absturz): beim naechsten Flush nachholen
			db.pushSealed(s, makeSealed(start, ts, vs, db.digits))
			s.floor = max(s.floor, start+hour)
			continue
		}
		if start > now+maxFuture {
			// Stunde in der Zukunft (Uhr zurueckgestellt): abschliessen statt als laufend laden, sonst nimmt
			// die Reihe bis zum Aufholen der Uhr nichts an; die Untergrenze setzt Append zurueck
			db.pushSealed(s, makeSealed(start, ts, vs, db.digits))
			db.log.Warn("monitor64: open block in the future, clock went back?", "series", s.key, "start", time.Unix(start, 0).UTC())
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
			if err := db.Flush(ctx); err != nil && !errors.Is(err, ErrClosed) && db.logFlush.ok(time.Hour) {
				db.log.Warn("monitor64: flush failed (repeated failures logged hourly)", "err", err)
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
// Liegt der Stand der Reihe weit vor der Uhr (Uhr zurueckgestellt), beginnt die Reihe neu.
func (db *DB) Append(key string, t time.Time, v float64) {
	ts := t.Unix()
	if db.closed.Load() || key == "" || !finite(v) || ts <= 0 {
		db.dropInvalid.Add(1)
		return
	}
	now := db.now().Unix()
	if ts > now+maxFuture {
		db.dropFuture.Add(1)
		return
	}
	for {
		s := db.get(key)
		s.mu.Lock()
		if s.gone {
			s.mu.Unlock()
			continue
		}
		ok, ahead := db.add(s, ts, now, v)
		s.mu.Unlock()
		if !ok {
			db.dropLate.Add(1)
		}
		if ahead > 0 {
			n := db.resets.Add(1)
			if db.logReset.ok(10 * time.Minute) {
				db.log.Warn("monitor64: clock went back, series restarted (logged every 10 min)",
					"series", key, "ahead", time.Duration(ahead)*time.Second, "resets", n)
			}
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

// add haengt einen Punkt an (s.mu gehalten). ahead > 0: der Stand der Reihe lag so viele Sekunden vor der
// Uhr und die Reihe beginnt neu (Uhr zurueckgestellt).
func (db *DB) add(s *series, ts, now int64, v float64) (ok bool, ahead int64) {
	h := ts - ts%hour
	if ts < s.floor || (len(s.off) > 0 && h < s.start) {
		// Stand der Reihe weit vor der Uhr: nicht verspaetet, sondern Uhr zurueckgestellt. Laufende Stunde
		// abschliessen (wird gesichert) und die Untergrenze auf die Stunde des Punkts setzen.
		top := s.floor
		if len(s.off) > 0 {
			top = max(top, s.start)
		}
		if top <= now+maxFuture {
			return false, 0
		}
		db.seal(s)
		s.floor = h
		ahead = top - now
	}
	if len(s.off) > 0 {
		switch {
		case h > s.start:
			db.seal(s)
		case uint16(ts-h) <= s.off[len(s.off)-1]:
			return false, ahead
		}
	}
	if len(s.off) == 0 {
		s.start = h
		s.saved = 0
	}
	s.off = append(s.off, uint16(ts-h))
	s.val = append(s.val, v)
	return true, ahead
}

// seal schliesst die laufende Stunde ab (s.mu gehalten).
func (db *DB) seal(s *series) {
	if len(s.off) == 0 {
		return
	}
	db.pushSealed(s, makeSealed(s.start, s.times(), s.val, db.digits))
	s.floor = max(s.floor, s.start+hour)
	s.off = s.off[:0]
	s.val = s.val[:0]
	s.saved = 0
}

// pushSealed merkt eine abgeschlossene Stunde zum Schreiben vor (s.mu gehalten). Ueber den Obergrenzen
// (je Reihe, insgesamt) fallen die aeltesten ungesicherten Stunden der Reihe weg; die neueste bleibt.
func (db *DB) pushSealed(s *series, b sealedBlock) {
	s.seq++
	b.seq = s.seq
	s.sealed = append(s.sealed, b)
	db.backlog.Add(int64(b.n))
	for len(s.sealed) > 1 && (len(s.sealed) > maxSealedHours || db.backlog.Load() > maxBacklogPoints) {
		old := s.sealed[0]
		s.sealed[0] = sealedBlock{} // Daten freigeben, solange das Feld noch im Array liegt
		s.sealed = s.sealed[1:]
		db.backlog.Add(-int64(old.n))
		n := db.dropBacklog.Add(uint64(old.n))
		if db.logBacklog.ok(time.Hour) {
			db.log.Error("monitor64: history not saved, dropping oldest unsaved hours (logged hourly)",
				"series", s.key, "start", time.Unix(old.start, 0).UTC(), "dropped", n)
		}
	}
}

// unqueue entfernt die geschriebenen Stunden bis seq (s.mu gehalten).
func (db *DB) unqueue(s *series, seq uint64) {
	k := 0
	for k < len(s.sealed) && s.sealed[k].seq <= seq {
		db.backlog.Add(-int64(s.sealed[k].n))
		k++
	}
	switch {
	case k == 0:
	case k == len(s.sealed):
		s.sealed = nil
	default:
		s.sealed = append([]sealedBlock(nil), s.sealed[k:]...)
	}
}

// throttle laesst eine Meldung hoechstens einmal je Zeitraum durch (Echtzeit, unabhaengig von Options.Now).
type throttle struct{ last atomic.Int64 }

func (t *throttle) ok(every time.Duration) bool {
	now := time.Now().UnixNano()
	last := t.last.Load()
	if last != 0 && now-last < int64(every) {
		return false
	}
	return t.last.CompareAndSwap(last, now)
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
	st := Stats{
		Series:         len(list),
		DroppedInvalid: db.dropInvalid.Load(),
		DroppedLate:    db.dropLate.Load(),
		DroppedFuture:  db.dropFuture.Load(),
		DroppedBacklog: db.dropBacklog.Load(),
		ClockResets:    db.resets.Load(),
		FlushDuration:  time.Duration(db.flushDur.Load()),
	}
	st.Dropped = st.DroppedInvalid + st.DroppedLate + st.DroppedFuture + st.DroppedBacklog
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
	w                int64 // Breite des Zeitfensters in Sekunden, nur bei Abfragen gesetzt (0 = Rohwert)
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
