package healthchecks

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/scheduler"
	"github.com/ipv64net/node64/internal/store"
)

// TimeFormat hat feste Breite, damit Zeichenketten in Zeitreihenfolge sortieren.
const TimeFormat = "2006-01-02T15:04:05.000Z"

func ft(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(TimeFormat)
}

func pt(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(TimeFormat, s)
	if err != nil {
		return store.ParseTime(s)
	}
	return t
}

const (
	FlagMaintenance = 1
	FlagDependent   = 2
	FlagSilent      = 2 // bei Events
	RawRetention    = 30 * 24 * time.Hour
	HourlyRetention = 365 * 24 * time.Hour
)

// Check ist ein Check mit Konfiguration und Laufzeitzustand.
type Check struct {
	Token          string
	Type           checks.Type
	Name           string
	Target         string
	Params         json.RawMessage
	Interval       time.Duration
	RetryInterval  time.Duration
	Retries        int
	ConnectTimeout time.Duration
	TotalTimeout   time.Duration
	Invert         bool
	Stabilize      int
	IPMode         checks.IPMode
	Tags           []string
	Group          string // frei benannte Gruppe
	Description    string
	Paused         bool
	Parent         string
	Critical       bool
	Execution      string   // local | online | both (online/both nur verknuepft)
	Policy         string   // all | any | majority (Gesamtzustand aus mehreren Messstellen)
	Locations      []string // Online-Standorte, leer = Vorgabe des Servers
	NotifyDegraded bool     // auch bei "teilweise gestoert" benachrichtigen
	Owner          string   // self (hier gemessen), online (nur bei ipv64), other (andere Node)
	Nodes          []string // messende Nodes (verknuepft, local/both); leer = nur der Besitzer
	NotifyDown     bool
	NotifyUp       bool
	Channels       []int64
	RepeatMinutes  int
	Revision       int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
	UpdatedBy      string
	Runtime        scheduler.Runtime
}

// Definition liefert die Check-Bot-Definition.
func (c *Check) Definition() checks.Definition {
	return checks.Definition{Token: c.Token, Type: c.Type, Target: c.Target, Params: c.Params,
		Timeouts: checks.Timeouts{Connect: c.ConnectTimeout, Total: c.TotalTimeout}, IPMode: c.IPMode}
}

// SchedulerCheck liefert die Sicht des Schedulers.
func (c *Check) SchedulerCheck() scheduler.Check {
	return scheduler.Check{Token: c.Token, Name: c.Name, Def: c.Definition(), Interval: c.Interval, RetryInterval: c.RetryInterval,
		Retries: c.Retries, Invert: c.Invert, Stabilize: c.Stabilize, Paused: c.Paused, Parent: c.Parent}
}

// Store ist die Datenhaltung des Moduls auf Basis des Kern-Stores.
type Store struct {
	w, r  *sql.DB
	mu    sync.RWMutex
	maint []Maintenance // Cache der Wartungsfenster
	// Aufbewahrung (Einstellung der Node); 0 = Standard, hourlyRet < 0 = unbegrenzt
	rawRet, hourlyRet time.Duration

	// Sync-Hooks (nil = standalone). OnChange nach jeder lokalen Konfigurations-
	// aenderung (nicht bei Aenderungen, die vom Server kommen: WithRemote);
	// OnRuntime nach jedem gespeicherten Laufzeitzustand.
	OnChange  func(ctx context.Context, entity, id, op string)
	OnRuntime func(token string, rt scheduler.Runtime)
	// OnAnyChange nach jeder Konfigurationsaenderung, auch vom hub oder von anderen Nodes (lokale Gruppe)
	OnAnyChange func(ctx context.Context, entity, id, op string)

	OnStatusChange func() // Statusseiten geaendert (zwischengespeicherte Ansichten verwerfen)
	// OnStatusCluster nach jeder Aenderung einer Statusseite (Kennung; auch Ankuendigungen und Logo) fuer den Cluster
	OnStatusCluster func(ctx context.Context, uid string, deleted bool)
	// Location liefert die Zeitzone der Node fuer wiederkehrende Wartungsfenster (nil = Zeitzone des Containers)
	Location func() *time.Location
}

type remoteKey struct{}

// WithRemote markiert einen Kontext als "Aenderung kommt vom Server" (kein Outbox-Eintrag).
func WithRemote(ctx context.Context) context.Context {
	return context.WithValue(ctx, remoteKey{}, true)
}

// IsRemote sagt, ob der Kontext vom Server stammt.
func IsRemote(ctx context.Context) bool { v, _ := ctx.Value(remoteKey{}).(bool); return v }

func (s *Store) changed(ctx context.Context, entity, id, op string) {
	if s.OnChange != nil && !IsRemote(ctx) {
		s.OnChange(ctx, entity, id, op)
	}
	if s.OnAnyChange != nil {
		s.OnAnyChange(ctx, entity, id, op)
	}
}

func NewStore(core *store.Store) *Store { return &Store{w: core.Writer(), r: core.Reader()} }

// NewToken erzeugt 32 Zeichen a-z A-Z 0-9 wie bei ipv64.
func NewToken() string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

const checkCols = `token, type, name, target, params, interval_sec, retry_interval_sec, retries, connect_timeout_ms, total_timeout_ms,
	invert, stabilize, ip_mode, tags, description, paused, parent_token, critical, execution, notify_down, notify_up, channels, repeat_minutes,
	policy, locations, notify_degraded, owner,
	revision, created_at, updated_at, updated_by,
	state, state_since, last_check_at, next_check_at, consecutive_fail, consecutive_ok, last_status, last_latency_ms, last_reason, last_message,
	last_push_at, down_since, flap_since, transitions, incident_id, group_name, nodes`

func scanCheck(row interface{ Scan(...any) error }) (*Check, error) {
	var c Check
	var params, tags, channels, created, updated, locations, nodes string
	var iv, riv, cto, tto int64
	var invert, paused, critical, nd, nu, ndeg int
	var state, since, last, next, lastStatus, lastPush, downSince, flapSince, transitions string
	var lastLat float64
	var lastReason, lastMsg string
	if err := row.Scan(&c.Token, &c.Type, &c.Name, &c.Target, &params, &iv, &riv, &c.Retries, &cto, &tto,
		&invert, &c.Stabilize, &c.IPMode, &tags, &c.Description, &paused, &c.Parent, &critical, &c.Execution, &nd, &nu, &channels, &c.RepeatMinutes,
		&c.Policy, &locations, &ndeg, &c.Owner,
		&c.Revision, &created, &updated, &c.UpdatedBy,
		&state, &since, &last, &next, &c.Runtime.ConsecutiveFail, &c.Runtime.ConsecutiveOK, &lastStatus, &lastLat, &lastReason, &lastMsg,
		&lastPush, &downSince, &flapSince, &transitions, &c.Runtime.Incident, &c.Group, &nodes); err != nil {
		return nil, err
	}
	c.Params = json.RawMessage(params)
	if len(c.Params) == 0 {
		c.Params = json.RawMessage("{}")
	}
	c.Interval, c.RetryInterval = time.Duration(iv)*time.Second, time.Duration(riv)*time.Second
	c.ConnectTimeout, c.TotalTimeout = time.Duration(cto)*time.Millisecond, time.Duration(tto)*time.Millisecond
	c.Invert, c.Paused, c.Critical, c.NotifyDown, c.NotifyUp = invert == 1, paused == 1, critical == 1, nd == 1, nu == 1
	c.NotifyDegraded = ndeg == 1
	c.Tags, c.Locations, c.Nodes = splitList(tags), splitList(locations), splitList(nodes)
	for _, ch := range splitList(channels) {
		var id int64
		if _, err := fmt.Sscan(ch, &id); err == nil {
			c.Channels = append(c.Channels, id)
		}
	}
	c.CreatedAt, c.UpdatedAt = pt(created), pt(updated)
	rt := &c.Runtime
	rt.State = scheduler.State(state)
	rt.Since, rt.LastCheck, rt.NextCheck = pt(since), pt(last), pt(next)
	rt.LastStatus = checks.Status(lastStatus)
	rt.LastLatency = time.Duration(lastLat * float64(time.Millisecond))
	rt.LastReason, rt.LastMessage = checks.Reason(lastReason), lastMsg
	rt.LastPush, rt.DownSince, rt.FlapSince = pt(lastPush), pt(downSince), pt(flapSince)
	for _, t := range splitList(transitions) {
		if x := pt(t); !x.IsZero() {
			rt.Transitions = append(rt.Transitions, x)
		}
	}
	return &c, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func joinInts(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprint(id))
	}
	return strings.Join(parts, ",")
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Checks liefert alle Checks sortiert nach Name.
func (s *Store) Checks(ctx context.Context) ([]*Check, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+checkCols+` FROM hc_checks ORDER BY name COLLATE NOCASE, token`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Check
	for rows.Next() {
		c, err := scanCheck(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Check liefert einen Check oder nil.
func (s *Store) Check(ctx context.Context, token string) (*Check, error) {
	c, err := scanCheck(s.r.QueryRowContext(ctx, `SELECT `+checkCols+` FROM hc_checks WHERE token = ?`, token))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

// Insert legt einen Check an (Token muss gesetzt sein).
func (s *Store) Insert(ctx context.Context, c *Check) error {
	now := ft(time.Now())
	c.CreatedAt, c.UpdatedAt = pt(now), pt(now)
	if c.Revision == 0 {
		c.Revision = 1
	}
	if c.Execution == "" {
		c.Execution = "local"
	}
	if c.Policy == "" {
		c.Policy = "all"
	}
	if c.Owner == "" {
		c.Owner = "self"
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO hc_checks (`+checkCols+`) VALUES (`+strings.TrimSuffix(strings.Repeat("?,", 48), ",")+`)`,
		c.Token, string(c.Type), c.Name, c.Target, string(c.Params), int64(c.Interval.Seconds()), int64(c.RetryInterval.Seconds()), c.Retries,
		c.ConnectTimeout.Milliseconds(), c.TotalTimeout.Milliseconds(), b2i(c.Invert), c.Stabilize, string(c.IPMode), strings.Join(c.Tags, ","), c.Description,
		b2i(c.Paused), c.Parent, b2i(c.Critical), c.Execution, b2i(c.NotifyDown), b2i(c.NotifyUp), joinInts(c.Channels), c.RepeatMinutes,
		c.Policy, strings.Join(c.Locations, ","), b2i(c.NotifyDegraded), c.Owner,
		c.Revision, now, now, c.UpdatedBy,
		"pending", now, "", "", 0, 0, "", 0.0, "", "", "", "", "", "", 0, c.Group, strings.Join(c.Nodes, ","))
	if err == nil {
		s.changed(ctx, "check", c.Token, "upsert")
	}
	return err
}

// Update schreibt die Konfiguration (nicht den Laufzeitzustand) und erhoeht die Revision.
func (s *Store) Update(ctx context.Context, c *Check) error {
	now := ft(time.Now())
	c.UpdatedAt = pt(now)
	c.Revision++
	_, err := s.w.ExecContext(ctx, `UPDATE hc_checks SET type=?, name=?, target=?, params=?, interval_sec=?, retry_interval_sec=?, retries=?,
		connect_timeout_ms=?, total_timeout_ms=?, invert=?, stabilize=?, ip_mode=?, tags=?, description=?, paused=?, parent_token=?, critical=?,
		execution=?, notify_down=?, notify_up=?, channels=?, repeat_minutes=?, policy=?, locations=?, notify_degraded=?, owner=?,
		revision=?, updated_at=?, updated_by=?, group_name=?, nodes=? WHERE token=?`,
		string(c.Type), c.Name, c.Target, string(c.Params), int64(c.Interval.Seconds()), int64(c.RetryInterval.Seconds()), c.Retries,
		c.ConnectTimeout.Milliseconds(), c.TotalTimeout.Milliseconds(), b2i(c.Invert), c.Stabilize, string(c.IPMode), strings.Join(c.Tags, ","), c.Description,
		b2i(c.Paused), c.Parent, b2i(c.Critical), c.Execution, b2i(c.NotifyDown), b2i(c.NotifyUp), joinInts(c.Channels), c.RepeatMinutes,
		c.Policy, strings.Join(c.Locations, ","), b2i(c.NotifyDegraded), orSelf(c.Owner),
		c.Revision, now, c.UpdatedBy, c.Group, strings.Join(c.Nodes, ","), c.Token)
	if err == nil {
		s.changed(ctx, "check", c.Token, "upsert")
	}
	return err
}

func orSelf(o string) string {
	if o == "" {
		return "self"
	}
	return o
}

// SetRevision setzt die vom Server vergebene Revision (ohne Hook).
func (s *Store) SetRevision(ctx context.Context, token string, rev int64) error {
	_, err := s.w.ExecContext(ctx, `UPDATE hc_checks SET revision=? WHERE token=?`, rev, token)
	return err
}

// SetPaused setzt nur das Pausiert-Flag.
func (s *Store) SetPaused(ctx context.Context, token string, paused bool, by string) error {
	st := "pending"
	if paused {
		st = "paused"
	}
	_, err := s.w.ExecContext(ctx, `UPDATE hc_checks SET paused=?, state=?, state_since=?, updated_at=?, updated_by=?, revision=revision+1 WHERE token=?`,
		b2i(paused), st, ft(time.Now()), ft(time.Now()), by, token)
	if err == nil {
		s.changed(ctx, "check", token, "upsert")
	}
	return err
}

// Delete entfernt einen Check mit allen Daten und hinterlaesst einen Tombstone.
func (s *Store) Delete(ctx context.Context, token string) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var rev int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM hc_checks WHERE token = ?`, token).Scan(&rev); err != nil {
		return err
	}
	for _, q := range []string{
		`DELETE FROM hc_checks WHERE token = ?`, `DELETE FROM hc_measurements WHERE token = ?`, `DELETE FROM hc_events WHERE token = ?`,
		`DELETE FROM hc_incidents WHERE token = ?`, `DELETE FROM hc_sources WHERE token = ?`, `DELETE FROM hc_source_points WHERE token = ?`, `DELETE FROM hc_source_hourly WHERE token = ?`, `DELETE FROM hc_hourly WHERE token = ?`, `DELETE FROM hc_daily WHERE token = ?`,
		`DELETE FROM hc_status_items WHERE token = ?`, // auch von allen Statusseiten
	} {
		if _, err := tx.ExecContext(ctx, q, token); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE hc_checks SET parent_token = '' WHERE parent_token = ?`, token); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO hc_tombstones (token, revision, deleted_at) VALUES (?, ?, ?)`, token, rev, ft(time.Now())); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.statusChanged()
	s.changed(ctx, "check", token, "delete")
	return nil
}

// ---------------------------------------------------------------- scheduler.Store

func (s *Store) SaveMeasurement(ctx context.Context, m scheduler.Measurement) error {
	details := ""
	if len(m.Details) > 0 {
		if b, err := json.Marshal(m.Details); err == nil {
			details = string(b)
		}
	}
	flags := 0
	if m.Maintenance {
		flags |= FlagMaintenance
	}
	if m.Dependent {
		flags |= FlagDependent
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO hc_measurements (token, time, status, latency_ms, reason, message, family, details, flags) VALUES (?,?,?,?,?,?,?,?,?)`,
		m.Token, ft(m.Time), b2i(m.Status == checks.Up), msf(m.Latency), string(m.Reason), m.Message, m.Family, details, flags)
	return err
}

func msf(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func (s *Store) SaveRuntime(ctx context.Context, token string, rt scheduler.Runtime) error {
	tr := make([]string, 0, len(rt.Transitions))
	for _, t := range rt.Transitions {
		tr = append(tr, ft(t))
	}
	_, err := s.w.ExecContext(ctx, `UPDATE hc_checks SET state=?, state_since=?, last_check_at=?, next_check_at=?, consecutive_fail=?, consecutive_ok=?,
		last_status=?, last_latency_ms=?, last_reason=?, last_message=?, last_push_at=?, down_since=?, flap_since=?, transitions=?, incident_id=? WHERE token=?`,
		string(rt.State), ft(rt.Since), ft(rt.LastCheck), ft(rt.NextCheck), rt.ConsecutiveFail, rt.ConsecutiveOK,
		string(rt.LastStatus), msf(rt.LastLatency), string(rt.LastReason), rt.LastMessage, ft(rt.LastPush), ft(rt.DownSince), ft(rt.FlapSince), strings.Join(tr, ","), rt.Incident, token)
	if err == nil && s.OnRuntime != nil {
		s.OnRuntime(token, rt)
	}
	return err
}

// OpenIncident legt eine Stoerung an; ist fuer den Check schon eine offen, wird sie weitergefuehrt (nie zwei offene).
func (s *Store) OpenIncident(ctx context.Context, token string, at time.Time, reason checks.Reason, message string) (int64, error) {
	if id := s.openIncidentID(ctx, token); id != 0 {
		return id, nil
	}
	res, err := s.w.ExecContext(ctx, `INSERT INTO hc_incidents (token, started_at, reason, message) VALUES (?,?,?,?)`, token, ft(at), string(reason), message)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// openIncidentID liefert die offene Stoerung eines Checks (0 = keine).
func (s *Store) openIncidentID(ctx context.Context, token string) int64 {
	var id int64
	_ = s.w.QueryRowContext(ctx, `SELECT id FROM hc_incidents WHERE token = ? AND ended_at = '' ORDER BY id DESC LIMIT 1`, token).Scan(&id)
	return id
}

func (s *Store) CloseIncident(ctx context.Context, id int64, at time.Time) error {
	_, err := s.w.ExecContext(ctx, `UPDATE hc_incidents SET ended_at = ? WHERE id = ? AND ended_at = ''`, ft(at), id)
	return err
}

func (s *Store) SaveEvent(ctx context.Context, e scheduler.Event) error {
	flags := 0
	if e.Maintenance {
		flags |= FlagMaintenance
	}
	if e.Silent {
		flags |= FlagSilent
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO hc_events (event_id, token, kind, time, from_state, to_state, reason, message, duration_sec, flaps, flags, incident_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.Token, string(e.Kind), ft(e.Time), string(e.From), string(e.To), string(e.Reason), e.Message, int64(e.Duration.Seconds()), e.Flaps, flags, e.Incident)
	return err
}

// ---------------------------------------------------------------- Messpunkte, Events, Stoerungen

type Measurement struct {
	Seq         int64          `json:"seq"`
	Time        time.Time      `json:"time"`
	Status      string         `json:"status"`
	LatencyMS   float64        `json:"latency_ms"`
	Reason      string         `json:"reason"`
	Message     string         `json:"message"`
	Family      string         `json:"family,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
	Maintenance bool           `json:"maintenance"`
	Dependent   bool           `json:"dependent"`
}

// Measurements liefert Messpunkte eines Checks, neueste zuerst.
func (s *Store) Measurements(ctx context.Context, token string, from, to time.Time, limit int, before int64) ([]Measurement, error) {
	if limit <= 0 || limit > 5000 {
		limit = 100
	}
	q := `SELECT node_seq, time, status, latency_ms, reason, message, family, details, flags FROM hc_measurements WHERE token = ?`
	args := []any{token}
	if !from.IsZero() {
		q += ` AND time >= ?`
		args = append(args, ft(from))
	}
	if !to.IsZero() {
		q += ` AND time < ?`
		args = append(args, ft(to))
	}
	if before > 0 {
		q += ` AND node_seq < ?`
		args = append(args, before)
	}
	q += ` ORDER BY node_seq DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Measurement
	for rows.Next() {
		var m Measurement
		var t, details string
		var status, flags int
		if err := rows.Scan(&m.Seq, &t, &status, &m.LatencyMS, &m.Reason, &m.Message, &m.Family, &details, &flags); err != nil {
			return nil, err
		}
		m.Time = pt(t)
		m.Status = map[int]string{1: "up", 0: "down"}[status]
		m.Maintenance, m.Dependent = flags&FlagMaintenance != 0, flags&FlagDependent != 0
		if details != "" {
			_ = json.Unmarshal([]byte(details), &m.Details)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

type Event struct {
	ID          int64     `json:"id"`
	EventID     string    `json:"event_id"`
	Token       string    `json:"token"`
	Kind        string    `json:"kind"`
	Time        time.Time `json:"time"`
	From        string    `json:"from"`
	To          string    `json:"to"`
	Reason      string    `json:"reason"`
	Message     string    `json:"message"`
	DurationSec int64     `json:"duration_seconds"`
	Flaps       int       `json:"flaps,omitempty"`
	Maintenance bool      `json:"maintenance"`
	Silent      bool      `json:"silent"`
	IncidentID  int64     `json:"incident_id,omitempty"`
	Hub         bool      `json:"hub,omitempty"` // von ipv64 bewertet (nur Anzeige, nicht gespeichert)
}

// Badge ist eine farbige Kennzeichnung in Tabellen (Bootstrap-Klasse).
type Badge struct{ Text, Class string }

var httpCodeRe = regexp.MustCompile(`\bHTTP (\d{3})\b`)

// HTTPBadges: die HTTP-Codes aus der Meldung (ipv4 und ipv6 je einmal), farbig nach Klasse.
func (e Event) HTTPBadges() []Badge {
	var out []Badge
	seen := map[string]bool{}
	for _, m := range httpCodeRe.FindAllStringSubmatch(e.Message, -1) {
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		class := map[byte]string{'2': "text-bg-success", '3': "text-bg-info", '4': "text-bg-warning", '5': "text-bg-danger"}[m[1][0]]
		if class == "" {
			class = "text-bg-secondary"
		}
		out = append(out, Badge{Text: m[1], Class: class})
	}
	return out
}

// ReasonClass: Farbe des Grund-Badges (OK gruen, Warnungen gelb, Fehler rot).
// KindClass: Farbe des Ereignisses (wie im Portal).
func (e Event) KindClass() string {
	switch e.Kind {
	case "down":
		return "text-bg-danger"
	case "up", "degraded_end", "flapping_end", "rechecked", "resumed":
		return "text-bg-success"
	case "degraded", "flapping_start", "unchecked", "unstable", "dependent":
		return "text-bg-warning"
	}
	return "text-bg-secondary"
}

// Length: Dauer als time.Duration (Anzeige ueber die Uebersetzung).
func (e Event) Length() time.Duration { return time.Duration(e.DurationSec) * time.Second }

func (e Event) ReasonClass() string {
	switch e.Reason {
	case "", "ok":
		return "text-bg-success"
	case "cert_expiring", "latency_high", "packet_loss", "dependency_down", "container_restarting", "container_paused":
		return "text-bg-warning"
	}
	return "text-bg-danger"
}

// Events liefert Ereignisse, neueste zuerst; token leer = alle.
func (s *Store) Events(ctx context.Context, token string, limit int, before int64) ([]Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := `SELECT id, event_id, token, kind, time, from_state, to_state, reason, message, duration_sec, flaps, flags, incident_id FROM hc_events WHERE 1=1`
	args := []any{}
	if token != "" {
		q += ` AND token = ?`
		args = append(args, token)
	}
	if before > 0 {
		q += ` AND id < ?`
		args = append(args, before)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var t string
		var flags int
		if err := rows.Scan(&e.ID, &e.EventID, &e.Token, &e.Kind, &t, &e.From, &e.To, &e.Reason, &e.Message, &e.DurationSec, &e.Flaps, &flags, &e.IncidentID); err != nil {
			return nil, err
		}
		e.Time = pt(t)
		e.Maintenance, e.Silent = flags&FlagMaintenance != 0, flags&FlagSilent != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

type Incident struct {
	ID        int64     `json:"id"`
	Token     string    `json:"token"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	Open      bool      `json:"open"`
	Reason    string    `json:"reason"`
	Message   string    `json:"message"`
}

// Length: Dauer der Stoerung (offen: bis jetzt).
func (i Incident) Length() time.Duration {
	end := i.EndedAt
	if i.Open || end.IsZero() {
		end = time.Now()
	}
	return end.Sub(i.StartedAt)
}

// Incidents liefert Stoerungen, neueste zuerst; token leer = alle.
func (s *Store) Incidents(ctx context.Context, token string, limit int) ([]Incident, error) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	q := `SELECT id, token, started_at, ended_at, reason, message FROM hc_incidents`
	args := []any{}
	if token != "" {
		q += ` WHERE token = ?`
		args = append(args, token)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		var i Incident
		var st, en string
		if err := rows.Scan(&i.ID, &i.Token, &st, &en, &i.Reason, &i.Message); err != nil {
			return nil, err
		}
		i.StartedAt, i.EndedAt = pt(st), pt(en)
		i.Open = en == ""
		out = append(out, i)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- Statistik

type Bucket struct {
	Time      time.Time `json:"time"`
	Count     int       `json:"count"`
	UpCount   int       `json:"up_count"`
	AvgMS     float64   `json:"avg_ms"`
	MinMS     float64   `json:"min_ms"`
	MaxMS     float64   `json:"max_ms"`
	UpPercent float64   `json:"up_percent"`
}

type Stats struct {
	Range      string    `json:"range"`
	From       time.Time `json:"from"`
	To         time.Time `json:"to"`
	Count      int       `json:"count"`
	UpCount    int       `json:"up_count"`
	UpPercent  float64   `json:"up_percent"`
	AvgMS      float64   `json:"avg_ms"`
	MinMS      float64   `json:"min_ms"`
	MaxMS      float64   `json:"max_ms"`
	BucketSecs int       `json:"bucket_seconds"`
	Series     []Bucket  `json:"series"`
}

var ranges = map[string]struct {
	span   time.Duration
	bucket time.Duration
}{
	"1h": {time.Hour, time.Minute}, "24h": {24 * time.Hour, 15 * time.Minute}, "7d": {7 * 24 * time.Hour, 2 * time.Hour},
	"30d": {30 * 24 * time.Hour, 6 * time.Hour}, "1y": {365 * 24 * time.Hour, 24 * time.Hour},
}

// Stats berechnet Verfuegbarkeit und Latenz. Bis 30 Tage aus Rohpunkten,
// fuer 1 Jahr aus Tageswerten plus den Rohpunkten der letzten Tage.
// Punkte in Wartung oder abhaengig gestoert zaehlen nicht gegen die Verfuegbarkeit.
func (s *Store) Stats(ctx context.Context, token, rng string, now time.Time) (*Stats, error) {
	r, ok := ranges[rng]
	if !ok {
		return nil, fmt.Errorf("unknown range %q", rng)
	}
	from := now.Add(-r.span)
	st := &Stats{Range: rng, From: from, To: now, BucketSecs: int(r.bucket.Seconds())}
	buckets := map[int64]*Bucket{}
	add := func(t time.Time, count, up int, minMS, avgMS, maxMS float64) {
		k := t.Unix() / int64(r.bucket.Seconds())
		b := buckets[k]
		if b == nil {
			b = &Bucket{Time: time.Unix(k*int64(r.bucket.Seconds()), 0).UTC(), MinMS: minMS}
			buckets[k] = b
		}
		if count == 0 {
			return
		}
		b.AvgMS = (b.AvgMS*float64(b.Count) + avgMS*float64(count)) / float64(b.Count+count)
		b.Count += count
		b.UpCount += up
		if minMS > 0 && (b.MinMS == 0 || minMS < b.MinMS) {
			b.MinMS = minMS
		}
		if maxMS > b.MaxMS {
			b.MaxMS = maxMS
		}
	}
	if rng == "1y" {
		rows, err := s.r.QueryContext(ctx, `SELECT day, count, up_count, min_ms, avg_ms, max_ms FROM hc_daily WHERE token = ? AND day >= ? ORDER BY day`, token, from.UTC().Format("2006-01-02"))
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var day string
			var count, up int
			var mn, av, mx float64
			if err := rows.Scan(&day, &count, &up, &mn, &av, &mx); err != nil {
				rows.Close()
				return nil, err
			}
			t, _ := time.Parse("2006-01-02", day)
			add(t, count, up, mn, av, mx)
		}
		rows.Close()
		// Rohpunkte der Tage, fuer die es noch keinen Tageswert gibt (heute, gestern)
		from = now.Truncate(24 * time.Hour).Add(-24 * time.Hour)
	}
	rows, err := s.r.QueryContext(ctx, `SELECT time, status, latency_ms, flags FROM hc_measurements WHERE token = ? AND time >= ? AND time <= ? ORDER BY time`, token, ft(from), ft(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		var status, flags int
		var lat float64
		if err := rows.Scan(&t, &status, &lat, &flags); err != nil {
			return nil, err
		}
		if flags&(FlagMaintenance|FlagDependent) != 0 {
			continue
		}
		add(pt(t), 1, status, lat, lat, lat)
	}
	keys := make([]int64, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sortInts(keys)
	var sumLat float64
	for _, k := range keys {
		b := buckets[k]
		if b.Count > 0 {
			b.UpPercent = round2(100 * float64(b.UpCount) / float64(b.Count))
		}
		b.AvgMS, b.MinMS, b.MaxMS = round2(b.AvgMS), round2(b.MinMS), round2(b.MaxMS)
		st.Count += b.Count
		st.UpCount += b.UpCount
		sumLat += b.AvgMS * float64(b.Count)
		if b.MinMS > 0 && (st.MinMS == 0 || b.MinMS < st.MinMS) {
			st.MinMS = b.MinMS
		}
		if b.MaxMS > st.MaxMS {
			st.MaxMS = b.MaxMS
		}
		st.Series = append(st.Series, *b)
	}
	if st.Count > 0 {
		st.UpPercent = round2(100 * float64(st.UpCount) / float64(st.Count))
		st.AvgMS = round2(sumLat / float64(st.Count))
	}
	if st.Series == nil {
		st.Series = []Bucket{}
	}
	return st, nil
}

func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }

func sortInts(a []int64) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// ---------------------------------------------------------------- Verdichtung und Aufbewahrung

// SetRetention setzt die Aufbewahrung aus den Einstellungen (hourly 0 = unbegrenzt).
func (s *Store) SetRetention(raw, hourly time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rawRet, s.hourlyRet = raw, hourly
	if hourly == 0 {
		s.hourlyRet = -1
	}
}

// rawRetention: wie lange Einzelmessungen bleiben (Standard 30 Tage).
func (s *Store) rawRetention() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.rawRet > 0 {
		return s.rawRet
	}
	return RawRetention
}

// Aggregate verdichtet: abgeschlossene Tage zu Tageswerten, Rohpunkte aelter
// als die Aufbewahrung (Standard 30 Tage) zu Stundenwerten (dann loeschen),
// Stundenwerte aelter als ihre Aufbewahrung (Standard ein Jahr) loeschen.
// Idempotent, laeuft stuendlich.
func (s *Store) Aggregate(ctx context.Context, now time.Time) error {
	// Rohpunkte nur tageweise (UTC) loeschen: Tages- und Stundenwerte entstehen so immer aus vollstaendigen
	// Tagen/Stunden und werden nicht von einem schrumpfenden Rest ueberschrieben
	rawCut := ft(now.Add(-s.rawRetention()).UTC().Truncate(24 * time.Hour))
	s.mu.RLock()
	hourlyRet := s.hourlyRet
	s.mu.RUnlock()
	if hourlyRet == 0 {
		hourlyRet = HourlyRetention
	}
	// Tageswerte fuer alle abgeschlossenen Tage, die noch Rohpunkte haben
	dayCut := now.UTC().Truncate(24 * time.Hour).Format(TimeFormat)
	if _, err := s.w.ExecContext(ctx, `INSERT OR REPLACE INTO hc_daily (token, day, count, up_count, min_ms, avg_ms, max_ms)
		SELECT token, substr(time, 1, 10), count(*), sum(status), min(latency_ms), avg(latency_ms), max(latency_ms)
		FROM hc_measurements WHERE time < ? AND flags = 0 GROUP BY token, substr(time, 1, 10)`, dayCut); err != nil {
		return err
	}
	// Stundenwerte fuer Rohpunkte, die gleich geloescht werden
	if _, err := s.w.ExecContext(ctx, `INSERT OR REPLACE INTO hc_hourly (token, hour, count, up_count, min_ms, avg_ms, max_ms)
		SELECT token, substr(time, 1, 13) || ':00:00.000Z', count(*), sum(status), min(latency_ms), avg(latency_ms), max(latency_ms)
		FROM hc_measurements WHERE time < ? AND flags = 0 GROUP BY token, substr(time, 1, 13)`, rawCut); err != nil {
		return err
	}
	// fremde Messstellen ebenso zu Stundenwerten verdichten, bevor ihre Einzelpunkte geloescht werden
	if _, err := s.w.ExecContext(ctx, `INSERT OR IGNORE INTO hc_source_hourly (token, source, hour, count, up_count, avg_ms)
		SELECT token, src, substr(time, 1, 13) || ':00:00.000Z', count(*), sum(status), avg(CASE WHEN status = 1 THEN latency_ms END)
		FROM (SELECT token, details AS src, time, status, latency_ms FROM hc_measurements WHERE (flags & 8) != 0 AND time < ?
			UNION ALL SELECT token, source, time, status, latency_ms FROM hc_source_points WHERE time < ?) GROUP BY 1, 2, 3`, rawCut, rawCut); err != nil {
		return err
	}
	if _, err := s.w.ExecContext(ctx, `DELETE FROM hc_measurements WHERE time < ?`, rawCut); err != nil {
		return err
	}
	if _, err := s.w.ExecContext(ctx, `DELETE FROM hc_source_points WHERE time < ?`, rawCut); err != nil {
		return err
	}
	if hourlyRet < 0 {
		return nil // Stundenwerte und Ereignisse unbegrenzt
	}
	if _, err := s.w.ExecContext(ctx, `DELETE FROM hc_hourly WHERE hour < ?`, ft(now.Add(-hourlyRet))); err != nil {
		return err
	}
	if _, err := s.w.ExecContext(ctx, `DELETE FROM hc_source_hourly WHERE hour < ?`, ft(now.Add(-hourlyRet))); err != nil {
		return err
	}
	if _, err := s.w.ExecContext(ctx, `DELETE FROM hc_events WHERE time < ?`, ft(now.Add(-hourlyRet))); err != nil {
		return err
	}
	// abgeschlossene Stoerungen wie die Ereignisse (laufende bleiben)
	_, err := s.w.ExecContext(ctx, `DELETE FROM hc_incidents WHERE ended_at != '' AND ended_at < ?`, ft(now.Add(-hourlyRet)))
	return err
}

// ---------------------------------------------------------------- Wartungsfenster

type Maintenance struct {
	ID          int64     `json:"id"`
	UID         string    `json:"-"` // gleich auf allen Nodes der lokalen Gruppe (peermaint.go)
	RemoteID    int64     `json:"remote_id,omitempty"`
	Revision    int64     `json:"revision,omitempty"`
	Name        string    `json:"name"`
	StartAt     time.Time `json:"start_at"`
	EndAt       time.Time `json:"end_at"`
	Repeat      string    `json:"repeat"`
	RepeatUntil time.Time `json:"repeat_until"`
	Tokens      []string  `json:"tokens"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
}

// Covers sagt, ob das Fenster zum Zeitpunkt t den Check betrifft (Wiederholung nach UTC).
func (m Maintenance) Covers(token string, t time.Time) bool { return m.CoversIn(token, t, time.UTC) }

// CoversIn wie Covers, Wiederholungen nach der Wanduhr in loc (bleibt nach der Zeitumstellung zur selben Uhrzeit).
func (m Maintenance) CoversIn(token string, t time.Time, loc *time.Location) bool {
	if !m.Active || !m.EndAt.After(m.StartAt) {
		return false
	}
	if len(m.Tokens) > 0 {
		found := false
		for _, x := range m.Tokens {
			if x == token {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if !m.RepeatUntil.IsZero() && t.After(m.RepeatUntil) {
		return false
	}
	dur := m.EndAt.Sub(m.StartAt)
	if loc == nil {
		loc = time.UTC
	}
	switch m.Repeat {
	case "daily", "weekly":
		days := maintRepeatDays(m.Repeat)
		if t.Before(m.StartAt) {
			return false
		}
		// feste Schritte als Naeherung; die Zeitumstellung verschiebt hoechstens um eine Stunde, daher Nachbarn pruefen
		k := int(t.Sub(m.StartAt) / (time.Duration(days) * 24 * time.Hour))
		for _, n := range []int{k + 1, k, k - 1} {
			if n < 0 {
				continue
			}
			start := m.StartAt.In(loc).AddDate(0, 0, n*days)
			if !t.Before(start) && t.Before(start.Add(dur)) {
				return true
			}
		}
		return false
	case "monthly":
		if t.Before(m.StartAt) {
			return false
		}
		// immer vom Original rechnen, damit der 31. nicht nach einem kurzen Monat verrutscht
		for k := 0; k < 1200; k++ {
			start := m.StartAt.In(loc).AddDate(0, k, 0)
			if start.After(t) {
				return false
			}
			if t.Before(start.Add(dur)) {
				return true
			}
		}
		return false
	default:
		return !t.Before(m.StartAt) && t.Before(m.EndAt)
	}
}

// maintRepeatDays: Tage zwischen zwei Terminen (daily 1, weekly 7).
func maintRepeatDays(repeat string) int {
	if repeat == "weekly" {
		return 7
	}
	return 1
}

func (s *Store) MaintenanceList(ctx context.Context) ([]Maintenance, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, name, start_at, end_at, repeat, repeat_until, tokens, active, created_at, remote_id, revision FROM hc_maintenance ORDER BY start_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Maintenance
	for rows.Next() {
		var m Maintenance
		var st, en, until, tokens, created string
		var active int
		if err := rows.Scan(&m.ID, &m.Name, &st, &en, &m.Repeat, &until, &tokens, &active, &created, &m.RemoteID, &m.Revision); err != nil {
			return nil, err
		}
		m.StartAt, m.EndAt, m.RepeatUntil, m.CreatedAt = pt(st), pt(en), pt(until), pt(created)
		m.Tokens = splitList(tokens)
		if m.Tokens == nil {
			m.Tokens = []string{}
		}
		m.Active = active == 1
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) MaintenanceInsert(ctx context.Context, m *Maintenance) error {
	if m.UID == "" {
		m.UID = newUID()
	}
	res, err := s.w.ExecContext(ctx, `INSERT INTO hc_maintenance (name, start_at, end_at, repeat, repeat_until, tokens, active, created_at, remote_id, revision, uid, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		m.Name, ft(m.StartAt), ft(m.EndAt), m.Repeat, ft(m.RepeatUntil), strings.Join(m.Tokens, ","), b2i(m.Active), ft(time.Now()), m.RemoteID, max(m.Revision, 1), m.UID, ft(changeTime(ctx)))
	if err != nil {
		return err
	}
	m.ID, _ = res.LastInsertId()
	s.reloadMaintenance(ctx)
	s.changed(ctx, "maintenance", strconv.FormatInt(m.ID, 10), "upsert")
	return nil
}

func (s *Store) MaintenanceUpdate(ctx context.Context, m *Maintenance) error {
	_, err := s.w.ExecContext(ctx, `UPDATE hc_maintenance SET name=?, start_at=?, end_at=?, repeat=?, repeat_until=?, tokens=?, active=?, remote_id=CASE WHEN ?>0 THEN ? ELSE remote_id END, revision=CASE WHEN ?>0 THEN ? ELSE revision+1 END, updated_at=? WHERE id=?`,
		m.Name, ft(m.StartAt), ft(m.EndAt), m.Repeat, ft(m.RepeatUntil), strings.Join(m.Tokens, ","), b2i(m.Active), m.RemoteID, m.RemoteID, m.Revision, m.Revision, ft(changeTime(ctx)), m.ID)
	s.reloadMaintenance(ctx)
	if err == nil {
		s.changed(ctx, "maintenance", strconv.FormatInt(m.ID, 10), "upsert")
	}
	return err
}

func (s *Store) MaintenanceDelete(ctx context.Context, id int64) error {
	var rid int64
	var uid string
	_ = s.w.QueryRowContext(ctx, `SELECT remote_id, uid FROM hc_maintenance WHERE id = ?`, id).Scan(&rid, &uid)
	_, err := s.w.ExecContext(ctx, `DELETE FROM hc_maintenance WHERE id = ?`, id)
	s.reloadMaintenance(ctx)
	if err == nil {
		if uid != "" { // Loeschvermerk fuer die lokale Gruppe (Server-ID in revision)
			_, _ = s.w.ExecContext(ctx, `INSERT OR REPLACE INTO hc_tombstones (token, revision, deleted_at) VALUES (?, ?, ?)`, "m:"+uid, rid, ft(changeTime(ctx)))
		}
		ctx = context.WithValue(context.WithValue(ctx, deletedRemoteKey{}, rid), deletedUIDKey{}, uid)
		s.changed(ctx, "maintenance", strconv.FormatInt(id, 10), "delete")
	}
	return err
}

type deletedRemoteKey struct{}

// DeletedRemoteID liefert im "delete"-Hook die Server-ID des geloeschten Wartungsfensters (0 = nie synchronisiert).
func DeletedRemoteID(ctx context.Context) int64 {
	v, _ := ctx.Value(deletedRemoteKey{}).(int64)
	return v
}

// MaintenanceByRemote findet ein Wartungsfenster ueber seine Server-ID.
func (s *Store) MaintenanceByRemote(ctx context.Context, remoteID int64) (*Maintenance, error) {
	list, err := s.MaintenanceList(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].RemoteID == remoteID {
			return &list[i], nil
		}
	}
	return nil, nil
}

func (s *Store) reloadMaintenance(ctx context.Context) {
	list, err := s.MaintenanceList(ctx)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.maint = list
	s.mu.Unlock()
}

// location: Zeitzone fuer wiederkehrende Wartungsfenster (Zeitzone der Node).
func (s *Store) location() *time.Location {
	if s.Location != nil {
		if loc := s.Location(); loc != nil {
			return loc
		}
	}
	return time.Local
}

// InMaintenance prueft gegen den Cache der Wartungsfenster.
func (s *Store) InMaintenance(_ context.Context, token string, at time.Time) bool {
	loc := s.location()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range s.maint {
		if m.CoversIn(token, at, loc) {
			return true
		}
	}
	return false
}

// Counts liefert die Anzahl je Zustand fuer das Dashboard.
func (s *Store) Counts(ctx context.Context) (map[string]int, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT state, count(*) FROM hc_checks GROUP BY state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}

// CertExpiries liefert je HTTP(S)-Check das Ablaufdatum des Zertifikats aus der letzten Messung.
func (s *Store) CertExpiries(ctx context.Context) map[string]time.Time {
	out := map[string]time.Time{}
	rows, err := s.r.QueryContext(ctx, `SELECT m.token, m.details, m.message FROM hc_measurements m
		JOIN (SELECT mm.token, MAX(mm.node_seq) seq FROM hc_measurements mm JOIN hc_checks c ON c.token = mm.token
		      WHERE c.type IN ('http','keyword') AND (mm.details LIKE '%cert_not_after%' OR mm.message LIKE '%cert valid until%') AND mm.time > ? GROUP BY mm.token) x
		ON x.seq = m.node_seq`, ft(time.Now().Add(-3*24*time.Hour)))
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var token, details, msg string
		if rows.Scan(&token, &details, &msg) != nil {
			continue
		}
		if t, ok := certNotAfter([]byte(details)); ok {
			out[token] = t
		} else if t, ok := CertFromMessage(msg); ok {
			out[token] = t
		}
	}
	return out
}

// certNotAfter liest cert_not_after aus den Details; bei IPv4+IPv6 (verschachtelt je Familie) das fruehere.
func certNotAfter(raw []byte) (time.Time, bool) {
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil {
		return time.Time{}, false
	}
	parse := func(m map[string]json.RawMessage) (time.Time, bool) {
		var v string
		if json.Unmarshal(m["cert_not_after"], &v) != nil {
			return time.Time{}, false
		}
		t, err := time.Parse(time.RFC3339, v)
		return t, err == nil
	}
	if t, ok := parse(top); ok {
		return t, true
	}
	var best time.Time
	for _, fam := range []string{"ipv4", "ipv6"} {
		var sub map[string]json.RawMessage
		if json.Unmarshal(top[fam], &sub) == nil {
			if t, ok := parse(sub); ok && (best.IsZero() || t.Before(best)) {
				best = t
			}
		}
	}
	return best, !best.IsZero()
}

var reCertUntil = regexp.MustCompile(`cert valid until (\d{4}-\d{2}-\d{2})`)

// CertFromMessage liest das Ablaufdatum aus der Meldung (Online-Checks: vom Hub nur die Meldung).
func CertFromMessage(msg string) (time.Time, bool) {
	var best time.Time
	for _, m := range reCertUntil.FindAllStringSubmatch(msg, -1) {
		if t, err := time.Parse("2006-01-02", m[1]); err == nil && (best.IsZero() || t.Before(best)) {
			best = t
		}
	}
	return best, !best.IsZero()
}
