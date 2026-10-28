package honeypot

import (
	"context"
	"database/sql"
	"embed"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/store"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migrations liefert die eingebetteten Migrationen des Moduls (Scope Name).
func Migrations() []store.Migration {
	ms, err := store.ReadMigrations(migrationFS, "migrations")
	if err != nil {
		panic(err)
	}
	return ms
}

// Speicher-Grenzen (Plan Abschnitt 2 „Ressourcen“): lokal 7 Tage mit fester Obergrenze.
const (
	DefaultRetention = 7 * 24 * time.Hour
	DefaultMaxRows   = 200000 // Obergrenze der gespeicherten Ereignisse (aelteste fallen zuerst weg)

	sinkBuffer   = 4096             // Puffer der Sink; voll = verwerfen und zaehlen
	flushBatch   = 500              // hoechstens so viele Ereignisse je Transaktion; ab dieser Menge sofort schreiben
	flushEvery   = 2 * time.Second  // spaetestens so oft schreiben
	purgeEvery   = 10 * time.Minute // Obergrenze eng halten (Speicherplatz), die Zahlen kommen aus hp_minutes/hp_srcs
	purgeChunk   = 5000             // Loeschen in Stuecken, damit der Schreiber nicht lange blockiert
	retryMax     = 3                // so oft wird ein fehlgeschlagener Stapel wiederholt, dann verworfen (blockiert sonst alles danach)
	defaultTop   = 10
	dbTimeFormat = "2006-01-02T15:04:05.000Z" // feste Breite: Zeichenkettenvergleich = Zeitreihenfolge
)

// Store speichert die Ereignisse der Fallen-Dienste in der Datenbank der Node und liefert die Statistik.
type Store struct {
	st   *store.Store
	log  *slog.Logger
	ch   chan Event
	kick chan struct{}

	mu    sync.Mutex // ein Flush gleichzeitig
	retry []Event    // Stapel, dessen Schreiben fehlschlug (hoechstens flushBatch), beim naechsten Flush zuerst
	fails int        // Fehlversuche des Stapels in retry; ab retryMax wird er verworfen

	dropped   atomic.Int64
	retention atomic.Int64 // time.Duration
	maxRows   atomic.Int64
}

// NewStore legt den Speicher an. Die Migrationen (Migrations, Scope Name) muss der Aufrufer vorher anwenden.
func NewStore(st *store.Store, log *slog.Logger) *Store {
	if log == nil {
		log = slog.Default()
	}
	s := &Store{st: st, log: log.With("module", Name), ch: make(chan Event, sinkBuffer), kick: make(chan struct{}, 1)}
	s.retention.Store(int64(DefaultRetention))
	s.maxRows.Store(DefaultMaxRows)
	return s
}

// SetLimits aendert Aufbewahrung und Obergrenze (0 = Standard). Wirkt beim naechsten Aufraeumen.
func (s *Store) SetLimits(retention time.Duration, maxRows int64) {
	if retention <= 0 {
		retention = DefaultRetention
	}
	if maxRows <= 0 {
		maxRows = DefaultMaxRows
	}
	s.retention.Store(int64(retention))
	s.maxRows.Store(maxRows)
}

// Sink liefert die Annahme fuer die Sensoren: kehrt sofort zurueck, ist der Puffer voll, wird verworfen und gezaehlt.
// Texte und Payload werden hier gekuerzt (Payload kopiert, der Sensor darf seinen Puffer wiederverwenden).
func (s *Store) Sink() Sink {
	return func(e Event) {
		e = storeSanitize(e)
		select {
		case s.ch <- e:
		default:
			s.dropped.Add(1)
			return
		}
		if len(s.ch) >= flushBatch {
			select {
			case s.kick <- struct{}{}:
			default:
			}
		}
	}
}

// Dropped liefert die Zahl der verworfenen Ereignisse seit dem Start.
func (s *Store) Dropped() int64 { return s.dropped.Load() }

// Buffered liefert die Zahl der Ereignisse, die noch auf das Schreiben warten.
func (s *Store) Buffered() int { return len(s.ch) }

// Run schreibt den Puffer in Stapeln (alle 2 s oder ab 500 Stueck, je Stapel eine Transaktion) und raeumt stuendlich
// auf (auch gleich beim Start). Endet mit ctx und schreibt dann den Rest.
func (s *Store) Run(ctx context.Context) {
	tick := time.NewTicker(flushEvery)
	defer tick.Stop()
	clean := time.NewTicker(purgeEvery)
	defer clean.Stop()
	s.purgeLogged(ctx)
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := s.Flush(fctx); err != nil {
				s.log.Warn("honeypot: write remaining events", "err", err)
			}
			cancel()
			return
		case <-tick.C:
			s.flushLogged(ctx)
		case <-s.kick:
			s.flushLogged(ctx)
		case <-clean.C:
			s.purgeLogged(ctx)
		}
	}
}

func (s *Store) flushLogged(ctx context.Context) {
	if err := s.Flush(ctx); err != nil && ctx.Err() == nil {
		s.log.Warn("honeypot: write events", "err", err)
	}
}

func (s *Store) purgeLogged(ctx context.Context) {
	if n, err := s.Purge(ctx); err != nil && ctx.Err() == nil {
		s.log.Warn("honeypot: purge events", "err", err)
	} else if n > 0 {
		s.log.Debug("honeypot: purged events", "count", n)
	}
}

// Flush schreibt alle Ereignisse, die beim Aufruf im Puffer liegen (in Stapeln zu hoechstens 500). Schlaegt ein
// Stapel fehl, bleibt er fuer den naechsten Flush liegen; nach retryMax Fehlversuchen wird er verworfen und gezaehlt.
func (s *Store) Flush(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.ch) + len(s.retry)
	for n > 0 {
		batch := s.retry
		s.retry = nil
	fill:
		for len(batch) < flushBatch && len(batch) < n {
			select {
			case e := <-s.ch:
				batch = append(batch, e)
			default:
				break fill
			}
		}
		if len(batch) == 0 {
			return nil
		}
		if err := s.write(ctx, batch); err != nil {
			if s.fails++; s.fails >= retryMax && ctx.Err() == nil {
				s.dropped.Add(int64(len(batch)))
				s.log.Warn("honeypot: batch dropped after repeated write errors", "events", len(batch), "err", err)
				s.fails = 0
				return err
			}
			s.retry = batch
			return err
		}
		s.fails = 0
		n -= len(batch)
	}
	return nil
}

const storeInsertSQL = `INSERT INTO hp_events (ts, service, port, kind, src, src_port, login, username, password,
	method, path, host, ua, client, page, payload, detail, source, rule, fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

func (s *Store) write(ctx context.Context, batch []Event) error {
	tx, err := s.st.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, storeInsertSQL)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range batch {
		var payload any
		if len(e.Payload) > 0 {
			payload = e.Payload
		}
		if _, err := stmt.ExecContext(ctx, storeTime(e.Time), e.Service, e.Port, e.Kind, storeSrc(e.Src), e.SrcPort, storeBool(storeIsLogin(e)),
			e.Username, e.Password, e.Method, e.Path, e.Host, e.UA, e.Client, e.Page, payload, e.Detail, storeSource(e.Source), e.Rule, e.Fingerprint); err != nil {
			return err
		}
	}
	// Zaehler je Minute und letzte Sichtung je Quell-IP: bleiben, wenn die Obergrenze einzelne Ereignisse loescht
	mins := map[string][2]int64{}
	srcs := map[string]string{}
	for _, e := range batch {
		ts := storeTime(e.Time)
		c := mins[ts[:16]]
		c[0]++
		if storeIsLogin(e) {
			c[1]++
		}
		mins[ts[:16]] = c
		if src := storeSrc(e.Src); src != "" && ts > srcs[src] {
			srcs[src] = ts
		}
	}
	for k, c := range mins {
		if _, err := tx.ExecContext(ctx, `INSERT INTO hp_minutes (minute, events, logins) VALUES (?, ?, ?)
			ON CONFLICT(minute) DO UPDATE SET events = events + excluded.events, logins = logins + excluded.logins`, k, c[0], c[1]); err != nil {
			return err
		}
	}
	for src, ts := range srcs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO hp_srcs (src, last) VALUES (?, ?) ON CONFLICT(src) DO UPDATE SET last = MAX(last, excluded.last)`,
			src, ts); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Purge loescht Ereignisse aelter als die Aufbewahrung und alles ueber der Obergrenze (aelteste zuerst).
// Liefert die Zahl der geloeschten Ereignisse.
func (s *Store) Purge(ctx context.Context) (int64, error) {
	w := s.st.Writer()
	cut := storeTime(time.Now().Add(-time.Duration(s.retention.Load())))
	var total int64
	for {
		res, err := w.ExecContext(ctx, `DELETE FROM hp_events WHERE id IN (SELECT id FROM hp_events WHERE ts < ? LIMIT ?)`, cut, purgeChunk)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		if n < purgeChunk {
			break
		}
	}
	// Zaehler nur nach der Aufbewahrung (klein: eine Zeile je Minute bzw. Quell-IP)
	if _, err := w.ExecContext(ctx, `DELETE FROM hp_minutes WHERE minute < ?`, cut[:16]); err != nil {
		return total, err
	}
	if _, err := w.ExecContext(ctx, `DELETE FROM hp_srcs WHERE last < ?`, cut); err != nil {
		return total, err
	}
	// Obergrenze: alles bis einschliesslich der (maxRows+1)-neuesten ID weg (IDs steigen mit dem Eingang).
	var limitID sql.NullInt64
	err := s.st.Reader().QueryRowContext(ctx, `SELECT id FROM hp_events ORDER BY id DESC LIMIT 1 OFFSET ?`, s.maxRows.Load()).Scan(&limitID)
	if err != nil && err != sql.ErrNoRows {
		return total, err
	}
	if limitID.Valid {
		for {
			res, err := w.ExecContext(ctx, `DELETE FROM hp_events WHERE id IN (SELECT id FROM hp_events WHERE id <= ? LIMIT ?)`, limitID.Int64, purgeChunk)
			if err != nil {
				return total, err
			}
			n, _ := res.RowsAffected()
			total += n
			if n < purgeChunk {
				break
			}
		}
	}
	return total, nil
}

// Totals liefert Ereignisse, Quell-IPs und Login-Versuche ab since aus den Zaehlern (unabhaengig von der Obergrenze).
// Ereignisse zaehlen ab der angefangenen Minute, Quell-IPs genau.
func (s *Store) Totals(ctx context.Context, since time.Time) (events, sources, logins int64, err error) {
	from := storeTime(since)
	r := s.st.Reader()
	if err = r.QueryRowContext(ctx, `SELECT COALESCE(SUM(events), 0), COALESCE(SUM(logins), 0) FROM hp_minutes WHERE minute >= ?`, from[:16]).
		Scan(&events, &logins); err != nil {
		return
	}
	err = r.QueryRowContext(ctx, `SELECT COUNT(*) FROM hp_srcs WHERE last >= ?`, from).Scan(&sources)
	return
}

// CountBetween zaehlt die Ereignisse in [from, to) aus den Zaehlern (je Minute).
func (s *Store) CountBetween(ctx context.Context, from, to time.Time) (int64, error) {
	var n int64
	err := s.st.Reader().QueryRowContext(ctx, `SELECT COALESCE(SUM(events), 0) FROM hp_minutes WHERE minute >= ? AND minute < ?`,
		storeTime(from)[:16], storeTime(to)[:16]).Scan(&n)
	return n, err
}

// Capped: Die Obergrenze ist erreicht und hat Ereignisse nach since schon geloescht. oldest ist das aelteste noch
// gespeicherte Ereignis (Ranglisten und Ereignisliste reichen nur bis dahin, die Zahlen sind vollstaendig).
func (s *Store) Capped(ctx context.Context, since time.Time) (oldest time.Time, capped bool, err error) {
	// nur was die Obergrenze geloescht hat, nicht die Aufbewahrung (die raeumt alle purgeEvery auf)
	if lim := time.Now().Add(-time.Duration(s.retention.Load()) + 2*purgeEvery); since.Before(lim) {
		since = lim
	}
	r := s.st.Reader()
	var x int64
	switch err = r.QueryRowContext(ctx, `SELECT id FROM hp_events ORDER BY id DESC LIMIT 1 OFFSET ?`, s.maxRows.Load()-1).Scan(&x); {
	case err == sql.ErrNoRows:
		return time.Time{}, false, nil
	case err != nil:
		return
	}
	var ts string
	if err = r.QueryRowContext(ctx, `SELECT ts FROM hp_events ORDER BY id LIMIT 1`).Scan(&ts); err != nil {
		return
	}
	oldest = storeParseTime(ts)
	return oldest, oldest.After(since), nil
}

// Stats liefert die Auswertung ab since (Null oder aelter als die Aufbewahrung = ganze Aufbewahrung). top begrenzt
// die Ranglisten (<= 0 = 10); ByService, ByPort und ByKind sind vollstaendig. Der Verlauf ist je Stunde, wenn der
// Zeitraum hoechstens 48 Stunden umfasst, sonst je Tag (UTC), luckenlos mit Nullwerten.
func (s *Store) Stats(ctx context.Context, since time.Time, top int) (*Stats, error) {
	now := time.Now().UTC()
	if oldest := now.Add(-time.Duration(s.retention.Load())); since.IsZero() || since.Before(oldest) {
		since = oldest
	}
	since = since.UTC()
	if top <= 0 {
		top = defaultTop
	}
	from := storeTime(since)
	out := &Stats{Since: since}
	var err error
	if out.Events, out.Sources, out.Logins, err = s.Totals(ctx, since); err != nil {
		return nil, err
	}
	lists := []struct {
		dst   *[]Count
		expr  string
		where string
		limit int
	}{
		{&out.ByService, `service`, ``, -1},
		{&out.ByPort, `CAST(port AS TEXT)`, ``, -1},
		{&out.ByKind, `kind`, ``, -1},
		{&out.BySource, `source`, ``, -1},
		{&out.TopSources, `src`, ` AND src <> ''`, top},
		{&out.TopUsers, `username`, ` AND username <> ''`, top},
		{&out.TopPass, `password`, ` AND password <> ''`, top},
		{&out.TopCreds, `username || ':' || password`, ` AND password <> ''`, top},
		{&out.TopPaths, `path`, ` AND path <> ''`, top},
		{&out.TopUAs, `ua`, ` AND ua <> ''`, top},
		{&out.TopFingerprints, `fingerprint`, ` AND fingerprint <> ''`, top},
	}
	for _, l := range lists {
		cs, err := s.counts(ctx, `SELECT `+l.expr+` AS k, COUNT(*) AS n, MAX(ts) FROM hp_events WHERE ts >= ?`+l.where+
			` GROUP BY k ORDER BY n DESC, k LIMIT ?`, from, l.limit)
		if err != nil {
			return nil, err
		}
		*l.dst = cs
	}
	for i := range out.TopSources {
		out.TopSources[i].Country = countryOf(out.TopSources[i].Key)
	}
	if out.ByCountry, out.CountryUnknown, err = s.byCountry(ctx, from); err != nil {
		return nil, err
	}
	if out.ByDecoy, err = s.byDecoy(ctx, from, top); err != nil {
		return nil, err
	}
	tl, err := s.timeline(ctx, since, now)
	if err != nil {
		return nil, err
	}
	out.Timeline = tl
	return out, nil
}

func (s *Store) counts(ctx context.Context, q string, args ...any) ([]Count, error) {
	rows, err := s.st.Reader().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Count{}
	for rows.Next() {
		var c Count
		var last string
		if err := rows.Scan(&c.Key, &c.Count, &last); err != nil {
			return nil, err
		}
		c.Last = storeParseTime(last)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) timeline(ctx context.Context, since, now time.Time) ([]TimePoint, error) {
	step, width := time.Hour, 13 // "2006-01-02T15" (Zaehler je Minute, hp_minutes)
	start := since.Truncate(time.Hour)
	layout := "2006-01-02T15"
	if now.Sub(since) > 48*time.Hour {
		step, width, layout = 24*time.Hour, 10, "2006-01-02"
		start = time.Date(since.Year(), since.Month(), since.Day(), 0, 0, 0, 0, time.UTC)
	}
	rows, err := s.st.Reader().QueryContext(ctx, `SELECT substr(minute, 1, ?) AS b, SUM(events) FROM hp_minutes WHERE minute >= ? GROUP BY b`, width, storeTime(since)[:16])
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byBucket := map[string]int64{}
	for rows.Next() {
		var b string
		var n int64
		if err := rows.Scan(&b, &n); err != nil {
			return nil, err
		}
		byBucket[b] = n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := []TimePoint{}
	for t := start; !t.After(now); t = t.Add(step) {
		out = append(out, TimePoint{Time: t, Events: byBucket[t.Format(layout)]})
	}
	return out, nil
}

// Recent liefert die letzten Ereignisse, neueste zuerst (limit <= 0 = 50, hoechstens 1000).
func (s *Store) Recent(ctx context.Context, limit int) ([]Event, error) {
	return s.RecentBy(ctx, limit, "")
}

// RecentBy wie Recent, nur Ereignisse einer Quelle (SrcHoneypot, SrcLog, SrcSyslog; "" = alle).
func (s *Store) RecentBy(ctx context.Context, limit int, source string) ([]Event, error) {
	return s.RecentIn(ctx, limit, source, "")
}

// RecentIn wie RecentBy, dazu nur Ereignisse aus einem Land (ISO 3166 alpha-2, "" = alle; geomap.go).
func (s *Store) RecentIn(ctx context.Context, limit int, source, country string) ([]Event, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	var conds []string
	var args []any
	if source != "" {
		conds, args = append(conds, `source = ?`), append(args, source)
	}
	if country != "" {
		cond, arg, none, err := s.countryWhere(ctx, country)
		if err != nil {
			return nil, err
		}
		if none {
			return []Event{}, nil
		}
		conds, args = append(conds, cond), append(args, arg)
	}
	where := ``
	if len(conds) > 0 {
		where = ` WHERE ` + strings.Join(conds, ` AND `)
	}
	args = append(args, limit)
	rows, err := s.st.Reader().QueryContext(ctx, `SELECT ts, service, port, kind, src, src_port, username, password, method, path,
		host, ua, client, page, payload, detail, source, rule, fingerprint FROM hp_events`+where+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var ts, src string
		if err := rows.Scan(&ts, &e.Service, &e.Port, &e.Kind, &src, &e.SrcPort, &e.Username, &e.Password, &e.Method, &e.Path,
			&e.Host, &e.UA, &e.Client, &e.Page, &e.Payload, &e.Detail, &e.Source, &e.Rule, &e.Fingerprint); err != nil {
			return nil, err
		}
		e.Time = storeParseTime(ts)
		e.Src, _ = netip.ParseAddr(src)
		out = append(out, e)
	}
	return out, rows.Err()
}

// NewSources liefert Quell-IPs, die seit since auftauchen und vorher (innerhalb der Aufbewahrung) nie gesehen wurden,
// in der Reihenfolge ihres ersten Auftretens (fuer die Benachrichtigung bei neuen Angreifern; limit <= 0 = 100).
func (s *Store) NewSources(ctx context.Context, since time.Time, limit int) ([]Count, error) {
	if limit <= 0 {
		limit = 100
	}
	from := storeTime(since)
	return s.counts(ctx, `SELECT e.src, COUNT(*), MAX(e.ts) FROM hp_events e WHERE e.ts >= ? AND e.src <> ''
		AND NOT EXISTS (SELECT 1 FROM hp_events o WHERE o.src = e.src AND o.ts < ?)
		GROUP BY e.src ORDER BY MIN(e.ts), e.src LIMIT ?`, from, from, limit)
}

// storeSanitize setzt fehlende Zeit, kuerzt Texte auf gueltiges UTF-8 der erlaubten Laenge und kopiert die Payload.
// Ereignisse aus echten Logs (Quelle log/syslog) behalten keine Inhalte: Benutzernamen, Passwoerter, HTTP-Felder,
// Client, Koeder und Payload werden geleert (Plan Abschnitt 1b/13) – auch wenn eine Regel sie faelschlich setzt.
func storeSanitize(e Event) Event {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Source = storeSource(e.Source)
	if e.Source != SrcHoneypot {
		e.Username, e.Password, e.Method, e.Path, e.Host, e.UA, e.Client, e.Page, e.Payload = "", "", "", "", "", "", "", "", nil
		e.Fingerprint = ""
	}
	e.Rule = storeClip(e.Rule, MaxText)
	e.Service = storeClip(e.Service, MaxText)
	e.Kind = storeClip(e.Kind, MaxText)
	e.Username = storeClip(e.Username, MaxText)
	e.Password = storeClip(e.Password, MaxText)
	e.Method = storeClip(e.Method, MaxText)
	e.Path = storeClip(e.Path, MaxPath)
	e.Host = storeClip(e.Host, MaxText)
	e.UA = storeClip(e.UA, MaxText)
	e.Client = storeClip(e.Client, MaxText)
	e.Page = storeClip(e.Page, MaxText)
	e.Detail = storeClip(e.Detail, MaxText)
	e.Fingerprint = storeClip(e.Fingerprint, MaxText)
	if len(e.Payload) > 0 {
		p := e.Payload
		if len(p) > MaxPayload {
			p = p[:MaxPayload]
		}
		e.Payload = append([]byte(nil), p...)
	} else {
		e.Payload = nil
	}
	return e
}

// storeClip macht s zu gueltigem UTF-8 und kuerzt auf hoechstens n Bytes an einer Zeichengrenze.
func storeClip(s string, n int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func storeIsLogin(e Event) bool {
	switch e.Kind {
	case KindSSHBrute, KindTelnetBrute, KindHTTPBrute:
		return true
	}
	return e.Username != "" || e.Password != ""
}

// storeSource: leere Quelle gilt als Honeypot; sonst gekuerzt (bekannt sind SrcHoneypot, SrcLog, SrcSyslog).
func storeSource(s string) string {
	if s == "" {
		return SrcHoneypot
	}
	return storeClip(s, 16)
}

func storeSrc(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.Unmap().WithZone("").String()
}

func storeBool(b bool) int {
	if b {
		return 1
	}
	return 0
}

func storeTime(t time.Time) string { return t.UTC().Format(dbTimeFormat) }

func storeParseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(dbTimeFormat, s)
	if err != nil {
		return store.ParseTime(s)
	}
	return t
}
