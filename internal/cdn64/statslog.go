package cdn64

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/store"
	_ "modernc.org/sqlite" // Treiber (registriert "sqlite")
)

// Statistik und Zugriffs-Log in einer eigenen Datei cdn64.db (viele Schreibvorgaenge; node64.db bleibt klein,
// Backups schnell). Zaehler je Host und Stunde immer (90 Tage), Einzel-Log nur fuer Hosts, die es eingeschaltet
// haben (Standard 7 Tage). Geschrieben wird gebuendelt im Hintergrund; laeuft der Schreiber hinterher, gehen
// Eintraege verloren statt Anfragen aufzuhalten.

const (
	setLogDays   = "cdn64.log_days"
	setAnonymize = "cdn64.log_anonymize" // off | mask
	hourlyKeep   = 90 * 24 * time.Hour
)

const statsSchema = `
CREATE TABLE IF NOT EXISTS hourly (host_id INTEGER NOT NULL, hour TEXT NOT NULL, requests INTEGER NOT NULL DEFAULT 0, s2 INTEGER NOT NULL DEFAULT 0,
	s3 INTEGER NOT NULL DEFAULT 0, s4 INTEGER NOT NULL DEFAULT 0, s5 INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (host_id, hour));
CREATE TABLE IF NOT EXISTS access (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, host_id INTEGER NOT NULL, client TEXT NOT NULL,
	method TEXT NOT NULL, host TEXT NOT NULL, path TEXT NOT NULL, status INTEGER NOT NULL, bytes INTEGER NOT NULL, ms INTEGER NOT NULL, ua TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS access_time ON access(time);
CREATE INDEX IF NOT EXISTS access_host ON access(host_id, time);
`

// statsColumns: spaeter dazugekommene Spalten (fehlen in aelteren cdn64.db).
var statsColumns = []struct{ table, col, def string }{
	{"hourly", "blocked", "INTEGER NOT NULL DEFAULT 0"},  // abgewiesen (Blocklisten, Limits, Sperren, Zugriffslisten, Exploits)
	{"access", "reason", "TEXT NOT NULL DEFAULT ''"},     // Grund der Abweisung ("" = normal beantwortet)
	{"hourly", "decoy", "INTEGER NOT NULL DEFAULT 0"},    // an den Honeypot-Koeder gegeben statt abgewiesen
	{"hourly", "bytes_in", "INTEGER NOT NULL DEFAULT 0"}, // Upload: vom Besucher zum Ziel (bytes = Download, vom Ziel zum Besucher)
}

// rejectLogEvery: je Adresse, Grund und Host hoechstens ein Log-Eintrag in diesem Abstand (Flut bleibt lesbar,
// gezaehlt wird jede Abweisung); dazu hoechstens rejectLogMax Eintraege je Minute insgesamt.
const (
	rejectLogEvery = 10 * time.Second
	rejectLogMax   = 600
)

// debug: Log-Level Debug (fuer alle Module oder nur PROXY64) - dann kommt alles ungebremst ins Zugriffs-Log, auch
// ohne Einzel-Log des Hosts, dazu unbekannte Namen, TLS-Fehler, durchgereichtes TLS und Stream-Verbindungen.
func (m *Module) debug() bool { return m.log.Enabled(context.Background(), slog.LevelDebug) }

// watchEdge: Debug-Beobachter des Eingangs (edge.SetWatch) - nur ins Log, nicht in die Zaehler.
func (m *Module) watchEdge(ip netip.Addr, host, method, path string, status int, kind string) {
	if !m.debug() {
		return
	}
	if sdb := m.stats2.Load(); sdb != nil {
		sdb.add(hit{time: time.Now(), client: ip.Unmap(), method: method, host: host, path: trunc(path, 500), status: status, reason: kind,
			conn: status == 0, all: true, only: true})
	}
}

// countHit zaehlt eine Anfrage bzw. Abweisung in die Stunde ihres Hosts.
func countHit(agg map[hourKey]*hourAgg, h hit) {
	k := hourKey{h.hostID, h.time.UTC().Truncate(time.Hour).Format(time.RFC3339)}
	a := agg[k]
	if a == nil {
		a = &hourAgg{}
		agg[k] = a
	}
	switch {
	case h.decoy:
		a.decoy++
	case h.reason == rejMaintenance: // Wartungsseite: weder abgewiesen noch Fehler des Ziels
	case h.reason != "":
		a.blocked++
	}
	if !h.conn {
		a.requests++
		a.bytes += h.bytes
		a.in += h.in
	}
	if !h.conn && !h.decoy && h.reason == "" { // Statusklassen nur fuer Antworten des Ziels
		switch h.status / 100 {
		case 1, 2:
			a.s2++
		case 3:
			a.s3++
		case 4:
			a.s4++
		default:
			a.s5++
		}
	}
}

// hit ist eine beantwortete Anfrage.
type hit struct {
	time   time.Time
	hostID int64
	client netip.Addr
	method string
	host   string
	path   string
	status int
	bytes  int64 // Download: vom Ziel zum Besucher (Antwort, bei WebSockets alles in diese Richtung)
	in     int64 // Upload: vom Besucher zum Ziel (Request-Body, bei WebSockets alles in diese Richtung)
	ms     int64
	ua     string
	log    bool   // ins Einzel-Log
	reason string // abgewiesen: Grund (immer ins Log, gebremst)
	conn   bool   // Verbindung vor der ersten Anfrage abgewiesen (zaehlt nicht als Anfrage)
	decoy  bool   // statt abzuweisen an den Koeder von Honeypot64 gegeben (reason = Art, Host 0 = unbekannter Name)
	all    bool   // Log-Level Debug: ungebremst ins Log (m.debug)
	only   bool   // nur ins Log, nicht in die Zaehler (Debug: unbekannte Namen, TLS-Fehler, Streams)
}

type hourKey struct {
	host int64
	hour string
}

// hourAgg: Zahlen einer Stunde. s2..s5 nur fuer Antworten des Ziels (nicht abgewiesen, nicht an den Koeder);
// blocked = abgewiesen, decoy = an den Honeypot-Koeder gegeben.
type hourAgg struct{ requests, s2, s3, s4, s5, bytes, in, blocked, decoy int64 }

// statsDB ist die Datei cdn64.db mit Schreiber.
type statsDB struct {
	db      *sql.DB
	log     *slog.Logger
	ch      chan hit
	dropped atomic.Int64
	done    chan struct{}
	wg      sync.WaitGroup
	days    func() int
	anon    func() bool
}

func openStats(dir string, log *slog.Logger, days func() int, anon func() bool) (*statsDB, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "cdn64.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=temp_store(MEMORY)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(statsSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("cdn64.db: %w", err)
	}
	store.PrivateFiles(path) // Zugriffs-Statistik mit IPs: nur der Node-Benutzer
	for _, c := range statsColumns {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, c.table, c.col).Scan(&n); err != nil {
			db.Close()
			return nil, fmt.Errorf("cdn64.db: %w", err)
		}
		if n == 0 {
			if _, err := db.Exec(`ALTER TABLE ` + c.table + ` ADD COLUMN ` + c.col + ` ` + c.def); err != nil {
				db.Close()
				return nil, fmt.Errorf("cdn64.db: %w", err)
			}
		}
	}
	s := &statsDB{db: db, log: log, ch: make(chan hit, 8192), done: make(chan struct{}), days: days, anon: anon}
	s.wg.Add(1)
	go s.writer()
	return s, nil
}

// add nimmt eine Anfrage auf (blockiert nie).
func (s *statsDB) add(h hit) {
	select {
	case s.ch <- h:
	default:
		s.dropped.Add(1)
	}
}

func (s *statsDB) close() {
	close(s.done)
	s.wg.Wait()
	_ = s.db.Close()
}

func (s *statsDB) writer() {
	defer s.wg.Done()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	agg := map[hourKey]*hourAgg{}
	var logs []hit
	lastRej := map[string]time.Time{} // Bremse fuer abgewiesene im Log
	var rejMinute time.Time
	rejN := 0
	flush := func() {
		if len(agg) == 0 && len(logs) == 0 {
			return
		}
		if err := s.write(agg, logs); err != nil {
			s.log.Warn("cdn64 stats not written", "err", err)
		}
		agg, logs = map[hourKey]*hourAgg{}, logs[:0]
	}
	addHit := func(h hit) {
		if !h.only {
			countHit(agg, h)
		}
		if h.all { // Debug: alles, ungebremst
			logs = append(logs, h)
		} else if h.reason != "" { // immer ins Log, aber gebremst
			key := h.client.String() + "|" + h.reason + "|" + strconv.FormatInt(h.hostID, 10)
			if m := h.time.Truncate(time.Minute); !m.Equal(rejMinute) {
				rejMinute, rejN = m, 0
				if len(lastRej) > 10000 {
					lastRej = map[string]time.Time{}
				}
			}
			if h.time.Sub(lastRej[key]) >= rejectLogEvery && rejN < rejectLogMax {
				lastRej[key] = h.time
				rejN++
				logs = append(logs, h)
			}
		} else if h.log {
			logs = append(logs, h)
		}
		if len(logs) >= 500 {
			flush()
		}
	}
	s.pruneOld()
	for {
		select {
		case h := <-s.ch:
			addHit(h)
		case <-t.C:
			flush()
		case <-prune.C:
			s.pruneOld()
		case <-s.done:
			for { // Rest noch aufnehmen, dann schreiben
				select {
				case h := <-s.ch:
					addHit(h)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (s *statsDB) write(agg map[hourKey]*hourAgg, logs []hit) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for k, a := range agg {
		if _, err := tx.ExecContext(ctx, `INSERT INTO hourly (host_id, hour, requests, s2, s3, s4, s5, bytes, bytes_in, blocked, decoy) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(host_id, hour) DO UPDATE SET requests = requests + excluded.requests, s2 = s2 + excluded.s2, s3 = s3 + excluded.s3,
			s4 = s4 + excluded.s4, s5 = s5 + excluded.s5, bytes = bytes + excluded.bytes, bytes_in = bytes_in + excluded.bytes_in,
			blocked = blocked + excluded.blocked, decoy = decoy + excluded.decoy`,
			k.host, k.hour, a.requests, a.s2, a.s3, a.s4, a.s5, a.bytes, a.in, a.blocked, a.decoy); err != nil {
			return err
		}
	}
	anon := s.anon()
	for _, h := range logs {
		if h.decoy { // im Log: Art mit Kennzeichen "an den Koeder"
			h.reason = decoyPrefix + h.reason
		}
		client := h.client.String()
		if anon {
			client = maskIP(h.client)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO access (time, host_id, client, method, host, path, status, bytes, ms, ua, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			h.time.UTC().Format(time.RFC3339Nano), h.hostID, client, h.method, h.host, h.path, h.status, h.bytes, h.ms, h.ua, h.reason); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *statsDB) pruneOld() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, _ = s.db.ExecContext(ctx, `DELETE FROM hourly WHERE hour < ?`, time.Now().Add(-hourlyKeep).UTC().Format(time.RFC3339))
	_, _ = s.db.ExecContext(ctx, `DELETE FROM access WHERE time < ?`, time.Now().AddDate(0, 0, -s.days()).UTC().Format(time.RFC3339Nano))
}

// maskIP kuerzt eine Adresse (IPv4 /24, IPv6 /48) wie in DNS64.
func maskIP(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	bits := 48
	if ip.Is4() {
		bits = 24
	}
	p, _ := ip.Prefix(bits)
	return p.String()
}

// ---------------------------------------------------------------- Abfragen

// HostStat sind die Zahlen eines Hosts in einem Zeitraum.
type HostStat struct {
	Requests int64 `json:"requests"`
	S2       int64 `json:"2xx"`
	S3       int64 `json:"3xx"`
	S4       int64 `json:"4xx"`
	S5       int64 `json:"5xx"`
	Bytes    int64 `json:"bytes"`    // Download: vom Ziel zum Besucher
	BytesIn  int64 `json:"bytes_in"` // Upload: vom Besucher zum Ziel
	Blocked  int64 `json:"blocked"`  // abgewiesen; bei Host 0 Verbindungen vor der ersten Anfrage
	Decoy    int64 `json:"decoy"`    // an den Honeypot-Koeder gegeben (statt abgewiesen); Host 0 = unbekannte Namen
}

// Errors: echte Fehler - 5xx des Ziels und "Ziel nicht erreichbar" (502). 4xx sind Antworten des Ziels (nicht
// gefunden, nicht angemeldet) und stehen getrennt; Abgewiesenes und an den Koeder Gegebenes zaehlt nie dazu.
func (h HostStat) Errors() int64 { return h.S5 }

// decoyPrefix kennzeichnet im Zugriffs-Log Anfragen, die an den Koeder gingen ("decoy:<Art>").
const decoyPrefix = "decoy:"

// bucketFrom: erster Stunden-Eimer ab since. Die angebrochene Stunde von since zaehlt nicht mehr mit, die laufende
// Stunde schon: since = jetzt - N Std. ergibt genau N Eimer (sonst waeren "24 Std." bis zu 25 Stunden). sums und
// hours nutzen beide diesen Anfang, damit die Summen dem Verlauf entsprechen.
func bucketFrom(since time.Time) string {
	return since.UTC().Truncate(time.Hour).Add(time.Hour).Format(time.RFC3339)
}

// sums: Zahlen je Host seit since, in vollen Stunden-Eimern (bucketFrom).
func (s *statsDB) sums(ctx context.Context, since time.Time) (map[int64]HostStat, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host_id, SUM(requests), SUM(s2), SUM(s3), SUM(s4), SUM(s5), SUM(bytes), SUM(bytes_in), SUM(blocked), SUM(decoy) FROM hourly WHERE hour >= ? GROUP BY host_id`,
		bucketFrom(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]HostStat{}
	for rows.Next() {
		var id int64
		var h HostStat
		if err := rows.Scan(&id, &h.Requests, &h.S2, &h.S3, &h.S4, &h.S5, &h.Bytes, &h.BytesIn, &h.Blocked, &h.Decoy); err != nil {
			return nil, err
		}
		out[id] = h
	}
	return out, rows.Err()
}

// HourPoint ist eine Stunde im Verlauf.
type HourPoint struct {
	Hour time.Time `json:"hour"`
	HostStat
	ConnBlocked int64 `json:"conn_blocked"` // davon Verbindungen vor der ersten Anfrage (nicht in requests)
}

// hours: Verlauf je Stunde (alle Hosts oder einer), ab bucketFrom(since) wie sums.
func (s *statsDB) hours(ctx context.Context, hostID int64, since time.Time) ([]HourPoint, error) {
	q := `SELECT hour, SUM(requests), SUM(s2), SUM(s3), SUM(s4), SUM(s5), SUM(bytes), SUM(bytes_in), SUM(blocked), SUM(decoy),
		SUM(CASE WHEN host_id = 0 THEN blocked ELSE 0 END) FROM hourly WHERE hour >= ?`
	args := []any{bucketFrom(since)}
	if hostID > 0 {
		q += ` AND host_id = ?`
		args = append(args, hostID)
	}
	rows, err := s.db.QueryContext(ctx, q+` GROUP BY hour ORDER BY hour`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HourPoint
	for rows.Next() {
		var p HourPoint
		var hour string
		if err := rows.Scan(&hour, &p.Requests, &p.S2, &p.S3, &p.S4, &p.S5, &p.Bytes, &p.BytesIn, &p.Blocked, &p.Decoy, &p.ConnBlocked); err != nil {
			return nil, err
		}
		p.Hour, _ = time.Parse(time.RFC3339, hour)
		out = append(out, p)
	}
	return out, rows.Err()
}

// LogEntry ist ein Eintrag im Zugriffs-Log.
type LogEntry struct {
	ID     int64     `json:"id"`
	Time   time.Time `json:"time"`
	HostID int64     `json:"host_id"`
	Client string    `json:"client"`
	Method string    `json:"method"`
	Host   string    `json:"host"`
	Path   string    `json:"path"`
	Status int       `json:"status"`
	Bytes  int64     `json:"bytes"`
	Ms     int64     `json:"ms"`
	UA     string    `json:"user_agent"`
	Reason string    `json:"reason,omitempty"` // abgewiesen: blocklist, ban, conns, conn_rate, max_conns, req_rate, target, exploit, acl
	Decoy  bool      `json:"decoy,omitempty"`  // an den Honeypot-Koeder gegeben (Reason = Art)
}

// LogFilter waehlt Eintraege aus.
type LogFilter struct {
	HostID   int64
	Status   int    // 2, 3, 4, 5 = Klasse, 0 = alle
	Rejected bool   // nur abgewiesene (ohne die an den Koeder gegebenen)
	Decoy    bool   // nur an den Honeypot-Koeder gegebene
	Query    string // in Pfad, Client oder User-Agent
	Before   int64  // Seiten: Eintraege mit kleinerer ID
	Limit    int
}

func (s *statsDB) entries(ctx context.Context, f LogFilter) ([]LogEntry, error) {
	q := `SELECT id, time, host_id, client, method, host, path, status, bytes, ms, ua, reason FROM access WHERE 1 = 1`
	var args []any
	if f.HostID > 0 {
		q += ` AND host_id = ?`
		args = append(args, f.HostID)
	}
	if f.Rejected {
		q += ` AND reason <> '' AND reason NOT LIKE '` + decoyPrefix + `%' AND reason NOT IN ('` + rejStream + `', '` + edge.WatchPassthrough + `')` // Debug: keine Abweisungen
	}
	if f.Decoy {
		q += ` AND reason LIKE '` + decoyPrefix + `%'`
	}
	if f.Status >= 1 && f.Status <= 5 {
		q += ` AND status >= ? AND status < ?`
		args = append(args, f.Status*100, f.Status*100+100)
	}
	if v := strings.TrimSpace(f.Query); v != "" {
		like := "%" + strings.NewReplacer("%", `\%`, "_", `\_`).Replace(v) + "%"
		q += ` AND (path LIKE ? ESCAPE '\' OR client LIKE ? ESCAPE '\' OR ua LIKE ? ESCAPE '\')`
		args = append(args, like, like, like)
	}
	if f.Before > 0 {
		q += ` AND id < ?`
		args = append(args, f.Before)
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	q += ` ORDER BY id DESC LIMIT ` + strconv.Itoa(f.Limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogEntry
	for rows.Next() {
		var e LogEntry
		var t string
		if err := rows.Scan(&e.ID, &t, &e.HostID, &e.Client, &e.Method, &e.Host, &e.Path, &e.Status, &e.Bytes, &e.Ms, &e.UA, &e.Reason); err != nil {
			return nil, err
		}
		e.Time, _ = time.Parse(time.RFC3339Nano, t)
		if r, ok := strings.CutPrefix(e.Reason, decoyPrefix); ok {
			e.Reason, e.Decoy = r, true
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
