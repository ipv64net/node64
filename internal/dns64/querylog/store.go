// Package querylog persists every DNS query in SQLite and answers the
// statistics queries for the web UI.
package querylog

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/store"
	_ "modernc.org/sqlite"
)

type Status int

const (
	StatusAllowed Status = iota // forwarded upstream
	StatusCached                // answered from cache
	StatusBlocked               // blocked by a list
	StatusLocal                 // local name, answered by router or NXDOMAIN
	StatusError                 // upstream failed
	StatusCustom                // own DNS record (settings)
)

var statusNames = [...]string{"allowed", "cached", "blocked", "local", "error", "custom"}

func (s Status) String() string {
	if int(s) < len(statusNames) {
		return statusNames[s]
	}
	return "unknown"
}

func ParseStatus(s string) (Status, bool) {
	for i, n := range statusNames {
		if n == s {
			return Status(i), true
		}
	}
	return 0, false
}

type Entry struct {
	Time     time.Time
	Client   string
	Domain   string
	QType    string
	Status   Status
	Reason   string // blocklist name or CNAME info
	Rcode    string
	Upstream string
	Duration time.Duration
	Proto    string // udp, tcp, doh, dot, doq
	Group    string // Geraetegruppe ("" = keine)
}

const schema = `
CREATE TABLE IF NOT EXISTS queries (
	id          INTEGER PRIMARY KEY,
	ts          INTEGER NOT NULL,
	client      TEXT    NOT NULL,
	domain      TEXT    NOT NULL,
	qtype       TEXT    NOT NULL,
	status      INTEGER NOT NULL,
	reason      TEXT    NOT NULL DEFAULT '',
	rcode       TEXT    NOT NULL DEFAULT '',
	upstream    TEXT    NOT NULL DEFAULT '',
	duration_us INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_queries_ts ON queries(ts);
`

// columns added later (ALTER TABLE, skipped when present)
var addColumns = []string{`ALTER TABLE queries ADD COLUMN proto TEXT NOT NULL DEFAULT ''`, `ALTER TABLE queries ADD COLUMN grp TEXT NOT NULL DEFAULT ''`}

type Store struct {
	db        *sql.DB
	ch        chan Entry
	retention time.Duration
	log       *slog.Logger
	dropped   atomic.Uint64
	done      chan struct{}

	cmu      sync.Mutex // Zaehler seit dem Start (Prometheus), auch fuer verworfene Eintraege
	counts   map[CountKey]uint64
	groups   map[GroupCountKey]uint64 // Anfragen je Geraetegruppe und Ergebnis
	durSum   time.Duration
	durCount uint64
}

// CountKey: Anfragen je Ergebnis und Protokoll.
type CountKey struct {
	Status Status
	Proto  string
}

// GroupCountKey: Anfragen je Geraetegruppe und Ergebnis.
type GroupCountKey struct {
	Group  string
	Status Status
}

// Counters sind die Zaehler seit dem Oeffnen des Logs.
type Counters struct {
	Queries  map[CountKey]uint64
	Groups   map[GroupCountKey]uint64
	Duration time.Duration // Summe der Antwortzeiten
	Answered uint64        // Anzahl in Duration
	Dropped  uint64        // nicht ins Log geschrieben (Puffer voll)
}

// Counters liefert eine Kopie der Zaehler.
func (s *Store) Counters() Counters {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	q := make(map[CountKey]uint64, len(s.counts))
	for k, v := range s.counts {
		q[k] = v
	}
	g := make(map[GroupCountKey]uint64, len(s.groups))
	for k, v := range s.groups {
		g[k] = v
	}
	return Counters{Queries: q, Groups: g, Duration: s.durSum, Answered: s.durCount, Dropped: s.dropped.Load()}
}

func Open(path string, retention time.Duration, log *slog.Logger) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=temp_store(MEMORY)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(schema + aggSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	store.PrivateFiles(path) // Abfrageprotokoll mit Geraeten und Domains: nur der Node-Benutzer
	for _, q := range addColumns {
		if _, err := db.Exec(q); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			db.Close()
			return nil, fmt.Errorf("update schema: %w", err)
		}
	}
	return &Store{
		db:        db,
		ch:        make(chan Entry, 8192),
		retention: retention,
		log:       log,
		done:      make(chan struct{}),
	}, nil
}

// Add queues an entry. It never blocks the DNS path: if the writer falls
// behind, entries are dropped and counted.
func (s *Store) Add(e Entry) {
	s.cmu.Lock()
	if s.counts == nil {
		s.counts = map[CountKey]uint64{}
	}
	s.counts[CountKey{e.Status, e.Proto}]++
	if e.Group != "" {
		if s.groups == nil {
			s.groups = map[GroupCountKey]uint64{}
		}
		s.groups[GroupCountKey{e.Group, e.Status}]++
	}
	s.durSum += e.Duration
	s.durCount++
	s.cmu.Unlock()
	select {
	case s.ch <- e:
	default:
		s.dropped.Add(1)
	}
}

// Run writes queued entries in batches and prunes old rows until ctx ends.
func (s *Store) Run(ctx context.Context) {
	defer close(s.done)
	s.backfillAgg()
	flush := time.NewTicker(time.Second)
	prune := time.NewTicker(time.Hour)
	defer flush.Stop()
	defer prune.Stop()
	// Aufraeumen in Stuecken: zwischen zwei Stuecken laufen Schreiben und Abfragen weiter
	pruneNext := time.After(0)
	var pruned int64

	batch := make([]Entry, 0, 1024)
	for {
		select {
		case e := <-s.ch:
			batch = append(batch, e)
			if len(batch) >= 1000 {
				s.write(batch)
				batch = batch[:0]
			}
		case <-flush.C:
			if len(batch) > 0 {
				s.write(batch)
				batch = batch[:0]
			}
		case <-prune.C:
			if pruneNext == nil {
				pruneNext = time.After(0)
			}
		case <-pruneNext:
			n, more := s.pruneStep()
			pruned += n
			pruneNext = nil
			if more {
				pruneNext = time.After(pruneGap)
			} else if pruned > 0 {
				s.log.Info("querylog pruned", "rows", pruned)
				s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
				pruned = 0
			}
		case <-ctx.Done():
			for {
				select {
				case e := <-s.ch:
					batch = append(batch, e)
					continue
				default:
				}
				break
			}
			if len(batch) > 0 {
				s.write(batch)
			}
			return
		}
	}
}

func (s *Store) Close() error {
	<-s.done
	return s.db.Close()
}

// CloseNow closes the database when Run was never started.
func (s *Store) CloseNow() error { return s.db.Close() }

func (s *Store) write(batch []Entry) {
	tx, err := s.db.Begin()
	if err != nil {
		s.log.Error("querylog begin", "err", err)
		return
	}
	stmt, err := tx.Prepare(`INSERT INTO queries (ts, client, domain, qtype, status, reason, rcode, upstream, duration_us, proto, grp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		s.log.Error("querylog prepare", "err", err)
		return
	}
	defer stmt.Close()
	for _, e := range batch {
		if _, err := stmt.Exec(e.Time.UnixMilli(), e.Client, e.Domain, e.QType, int(e.Status),
			e.Reason, e.Rcode, e.Upstream, e.Duration.Microseconds(), e.Proto, e.Group); err != nil {
			tx.Rollback()
			s.log.Error("querylog insert", "err", err)
			return
		}
	}
	if err := writeAgg(tx, batch); err != nil {
		tx.Rollback()
		s.log.Error("querylog aggregate", "err", err)
		return
	}
	if err := tx.Commit(); err != nil {
		s.log.Error("querylog commit", "err", err)
	}
}

// pruneBatch Zeilen je Stueck, pruneGap Pause dazwischen: ein grosser Rueckstand (z. B. nach kuerzerer
// Aufbewahrung) sperrt die Datenbank nicht am Stueck.
const (
	pruneBatch = 5000
	pruneGap   = 50 * time.Millisecond
)

// pruneStep loescht hoechstens pruneBatch abgelaufene Zeilen; more = es gibt vermutlich noch welche.
func (s *Store) pruneStep() (n int64, more bool) {
	cutoff := time.Now().Add(-s.retention).UnixMilli()
	s.pruneAgg(cutoff)
	res, err := s.db.Exec(`DELETE FROM queries WHERE rowid IN (SELECT rowid FROM queries WHERE ts < ? LIMIT ?)`, cutoff, pruneBatch)
	if err != nil {
		s.log.Error("querylog prune", "err", err)
		return 0, false
	}
	n, _ = res.RowsAffected()
	return n, n == pruneBatch
}

// ---- statistics ----

type Summary struct {
	Total        int64   `json:"total"`
	Blocked      int64   `json:"blocked"`
	Cached       int64   `json:"cached"`
	Clients      int64   `json:"clients"`
	AvgUpstreamM float64 `json:"avgUpstreamMs"`
	Dropped      uint64  `json:"droppedLogEntries"`
}

func (s *Store) Summary(ctx context.Context, since time.Time) (Summary, error) {
	var out Summary
	var avgUs sql.NullFloat64
	// aus den Minuten-Zaehlern (Clients aus den Stunden-Aggregaten), nicht aus den Einzelzeilen
	var upN, upUs int64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(total), 0), COALESCE(SUM(blocked), 0), COALESCE(SUM(cached), 0),
		COALESCE(SUM(up_n), 0), COALESCE(SUM(up_us), 0) FROM agg_min WHERE m >= ?`, since.UnixMilli()/60000,
	).Scan(&out.Total, &out.Blocked, &out.Cached, &upN, &upUs)
	if err == nil {
		err = s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT name) FROM agg_top WHERE kind = ? AND h >= ?`, topClient, since.UnixMilli()/3600000).Scan(&out.Clients)
	}
	if upN > 0 {
		avgUs = sql.NullFloat64{Float64: float64(upUs) / float64(upN), Valid: true}
	}
	out.AvgUpstreamM = avgUs.Float64 / 1000
	out.Dropped = s.dropped.Load()
	return out, err
}

type Bucket struct {
	Start   int64 `json:"t"` // unix ms
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"`
}

// Timeline returns one bucket per step from since until now, including
// empty buckets so the chart has a continuous x axis.
func (s *Store) Timeline(ctx context.Context, since time.Time, step time.Duration) ([]Bucket, error) {
	stepMs := step.Milliseconds()
	from := since.UnixMilli() / stepMs * stepMs
	rows, err := s.db.QueryContext(ctx, `
		SELECT (m * 60000 / ?) * ? AS b, SUM(total), SUM(blocked)
		FROM agg_min WHERE m >= ? GROUP BY b ORDER BY b`,
		stepMs, stepMs, from/60000)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	got := map[int64]Bucket{}
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.Start, &b.Total, &b.Blocked); err != nil {
			return nil, err
		}
		got[b.Start] = b
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	now := time.Now().UnixMilli()
	var out []Bucket
	for t := from; t <= now; t += stepMs {
		b := got[t]
		b.Start = t
		out = append(out, b)
	}
	return out, nil
}

type TopItem struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname,omitempty"` // clients only
	Count    int64  `json:"count"`
	Blocked  int64  `json:"blocked"`
}

// Top returns the most frequent domains or clients. kind is one of
// "blocked", "allowed" or "clients".
func (s *Store) Top(ctx context.Context, kind string, since time.Time, limit int) ([]TopItem, error) {
	k, ok := map[string]int{"blocked": topBlocked, "allowed": topAllowed, "clients": topClient}[kind]
	if !ok {
		return nil, fmt.Errorf("unknown kind %q", kind)
	}
	// aus den Stunden-Aggregaten (die angefangene erste Stunde zaehlt ganz mit)
	rows, err := s.db.QueryContext(ctx, `SELECT name, SUM(n) AS c, SUM(blocked) FROM agg_top WHERE kind = ? AND h >= ?
		GROUP BY name ORDER BY c DESC LIMIT ?`, k, since.UnixMilli()/3600000, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TopItem{}
	for rows.Next() {
		var it TopItem
		if err := rows.Scan(&it.Name, &it.Count, &it.Blocked); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

type LogRow struct {
	Time       int64   `json:"t"`
	Client     string  `json:"client"`
	ClientName string  `json:"clientName,omitempty"`
	Domain     string  `json:"domain"`
	QType      string  `json:"qtype"`
	Status     string  `json:"status"`
	Reason     string  `json:"reason,omitempty"`
	Rcode      string  `json:"rcode,omitempty"`
	Upstream   string  `json:"upstream,omitempty"`
	DurationMs float64 `json:"ms"`
	Proto      string  `json:"proto,omitempty"`
	Group      string  `json:"group,omitempty"`
}

type LogFilter struct {
	Status *Status
	Search string  // substring of domain or client
	Group  *string // exactly this device group ("" = without group)
	Limit  int
	Offset int
}

// Recent returns one page of the log, newest first, and the number of rows
// matching the filter.
func (s *Store) Recent(ctx context.Context, f LogFilter) ([]LogRow, int64, error) {
	var where []string
	var args []any
	if f.Status != nil {
		where = append(where, "status = ?")
		args = append(args, int(*f.Status))
	}
	if f.Group != nil {
		where = append(where, "grp = ?")
		args = append(args, *f.Group)
	}
	if f.Search != "" {
		like := "%" + escapeLike(strings.ToLower(f.Search)) + "%"
		where = append(where, `(domain LIKE ? ESCAPE '\' OR client LIKE ? ESCAPE '\')`)
		args = append(args, like, like)
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	total, err := s.cappedCount(ctx, cond, args)
	if err != nil {
		return nil, 0, err
	}

	q := `SELECT ts, client, domain, qtype, status, reason, rcode, upstream, duration_us, proto, grp FROM queries` +
		cond + " ORDER BY id DESC LIMIT ? OFFSET ?"
	rows, err := s.db.QueryContext(ctx, q, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, total, err
	}
	defer rows.Close()
	out := []LogRow{}
	for rows.Next() {
		var r LogRow
		var st int
		var us int64
		if err := rows.Scan(&r.Time, &r.Client, &r.Domain, &r.QType, &st, &r.Reason, &r.Rcode, &r.Upstream, &us, &r.Proto, &r.Group); err != nil {
			return nil, 0, err
		}
		r.Status = Status(st).String()
		r.DurationMs = float64(us) / 1000
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// ClientRow ist ein Client der letzten Zeit (Seite Gruppen: Geraete zum Zuordnen).
type ClientRow struct {
	Client   string `json:"client"`
	Queries  int64  `json:"queries"`
	LastSeen int64  `json:"last"` // Unix-ms
	Group    string `json:"group,omitempty"`
}

// RecentClients liefert die Clients seit since, die mit den meisten Anfragen zuerst (hoechstens limit).
func (s *Store) RecentClients(ctx context.Context, since time.Time, limit int) ([]ClientRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, SUM(n) AS c, MAX(last), MAX(grp) FROM agg_top WHERE kind = ? AND h >= ? AND name != ''
		GROUP BY name ORDER BY c DESC LIMIT ?`, topClient, since.UnixMilli()/3600000, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClientRow{}
	for rows.Next() {
		var c ClientRow
		if err := rows.Scan(&c.Client, &c.Queries, &c.LastSeen, &c.Group); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
