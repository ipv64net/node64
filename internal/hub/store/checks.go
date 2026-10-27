package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/scheduler"
)

// Check ist ein Online-Check aus hc2_checks mit dem Zustand dieser Messstelle.
type Check struct {
	Token          string
	UserID         int64
	Execution      string
	Locations      []string
	Policy         string
	NotifyDegraded bool
	Slot           int
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
	Paused         bool
	Parent         string
	Critical       bool
	NotifyDown     bool
	NotifyUp       bool
	Channels       []int64
	RepeatMinutes  int
	Revision       int64
	Deleted        bool
	Runtime        *scheduler.Runtime // Zustand dieser Messstelle, nil = noch keiner
}

// Obergrenzen der Timeouts auf den ipv64-Servern: ein Check mit z. B. 3600 s belegte sonst lange einen der Worker
// und bremste die Checks aller anderen aus.
const (
	MaxConnectTimeout = 30 * time.Second
	MaxTotalTimeout   = 60 * time.Second
)

// SchedulerCheck liefert die Sicht des Schedulers.
func (c *Check) SchedulerCheck() scheduler.Check {
	return scheduler.Check{Token: c.Token, Name: c.Name,
		Def: checks.Definition{Token: c.Token, Type: c.Type, Target: c.Target, Params: c.Params,
			Timeouts: checks.Timeouts{Connect: c.ConnectTimeout, Total: c.TotalTimeout}, IPMode: c.IPMode},
		Interval: c.Interval, RetryInterval: c.RetryInterval, Retries: c.Retries, Invert: c.Invert, Stabilize: c.Stabilize,
		Paused: c.Paused, Parent: c.Parent}
}

// MeasuredHere sagt, ob diese Messstelle den Check ausfuehrt: Online-Checks an
// jedem gewaehlten Standort; Push-Checks nur am ersten gewaehlten Standort, damit
// der Heartbeat nicht doppelt bewertet wird.
// live: Standorte mit lebendem hub; Push-Checks wertet der erste lebende Standort des Checks aus
// (faellt er aus, uebernimmt der naechste). nil = alle als lebend annehmen.
func (c *Check) MeasuredHere(location string, live map[string]bool) bool {
	if c.Deleted || (c.Execution != "online" && c.Execution != "both") || singleNodeType(string(c.Type)) {
		return false // Docker/Proxmox nie online (auch nicht, wenn sie dort gelandet sind)
	}
	if len(c.Locations) == 0 {
		return false
	}
	if c.Type == checks.TypePush {
		for _, l := range c.Locations {
			if live == nil || live[l] {
				return l == location
			}
		}
		return c.Locations[0] == location
	}
	for _, l := range c.Locations {
		if l == location {
			return true
		}
	}
	return false
}

const checkCols = `c.token, c.userid, c.execution, c.locations, c.policy, c.notify_degraded, c.slot, c.type, c.name, c.target, c.params,
	c.interval_sec, c.retry_interval_sec, c.retries, c.connect_timeout_ms, c.total_timeout_ms, c.invert, c.stabilize, c.ip_mode, c.paused,
	c.parent_token, c.critical, c.notify_down, c.notify_up, c.channels, c.repeat_minutes, c.revision, c.deleted_at,
	st.state, st.since, st.last_check_at, st.next_check_at, st.last_status, st.last_latency_ms, st.last_reason, st.last_message,
	st.consecutive_fail, st.consecutive_ok, st.down_since, c.last_push_at`

// LoadChecks laedt alle Checks, die dieser Messstelle zugeteilt sind
// (slot % n == i), inklusive Zustand dieser Messstelle.
func (s *Store) LoadChecks(ctx context.Context, slotMod, slotIdx int) ([]*Check, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+checkCols+` FROM hc2_checks c
		LEFT JOIN hc2_check_states st ON st.token = c.token AND st.source = ?
		WHERE c.deleted_at IS NULL AND c.execution IN ('online','both') AND FIND_IN_SET(?, c.locations) > 0 AND c.slot % ? = ?`,
		s.source, s.location, slotMod, slotIdx)
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
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

// LoadCheck laedt einen Check (auch geloeschte, damit der Aufrufer entfernen kann).
func (s *Store) LoadCheck(ctx context.Context, token string) (*Check, error) {
	c, err := scanCheck(s.db.QueryRowContext(ctx, `SELECT `+checkCols+` FROM hc2_checks c
		LEFT JOIN hc2_check_states st ON st.token = c.token AND st.source = ? WHERE c.token = ?`, s.source, token))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

func scanCheck(row interface{ Scan(...any) error }) (*Check, error) {
	var c Check
	var locations, params, channels, ipMode, typ string
	var iv, riv, cto, tto int64
	var invert, paused, critical, nd, nu, ndeg int
	var parent, deletedAt sql.NullString
	var state, since, last, next, lastStatus, lastReason, lastMsg, downSince, lastPush sql.NullString
	var lastLat sql.NullFloat64
	var cfail, cok sql.NullInt64
	if err := row.Scan(&c.Token, &c.UserID, &c.Execution, &locations, &c.Policy, &ndeg, &c.Slot, &typ, &c.Name, &c.Target, &params,
		&iv, &riv, &c.Retries, &cto, &tto, &invert, &c.Stabilize, &ipMode, &paused,
		&parent, &critical, &nd, &nu, &channels, &c.RepeatMinutes, &c.Revision, &deletedAt,
		&state, &since, &last, &next, &lastStatus, &lastLat, &lastReason, &lastMsg, &cfail, &cok, &downSince, &lastPush); err != nil {
		return nil, err
	}
	c.Type, c.IPMode = checks.Type(typ), checks.IPMode(ipMode)
	c.Locations = splitList(locations)
	c.Params = json.RawMessage(params)
	if len(strings.TrimSpace(params)) == 0 {
		c.Params = json.RawMessage("{}")
	}
	if typ != "push" && iv < 20 {
		iv = 20 // ipv64 misst nie oefter als alle 20 s (lokale Checks ab 5 s, z. B. nach dem Umhaengen)
	}
	if typ == "whois" { // WHOIS/RDAP-Server begrenzen Abfragen (auch fuer Eintraege von vor der Regel)
		iv, riv = max(iv, int64(checks.MinIntervalWhois.Seconds())), max(riv, int64(checks.MinRetryWhois.Seconds()))
	}
	if typ != "push" && riv < 20 {
		riv = 20 // auch im gestoerten Zustand nicht oefter (sonst alle 5 s, solange das Ziel ausfaellt)
	}
	c.Interval, c.RetryInterval = time.Duration(iv)*time.Second, time.Duration(riv)*time.Second
	c.ConnectTimeout, c.TotalTimeout = min(time.Duration(cto)*time.Millisecond, MaxConnectTimeout), min(time.Duration(tto)*time.Millisecond, MaxTotalTimeout)
	c.Invert, c.Paused, c.Critical, c.NotifyDown, c.NotifyUp, c.NotifyDegraded = invert == 1, paused == 1, critical == 1, nd == 1, nu == 1, ndeg == 1
	c.Parent = parent.String
	c.Deleted = deletedAt.Valid
	for _, ch := range splitList(channels) {
		var id int64
		if _, err := fmtSscan(ch, &id); err == nil {
			c.Channels = append(c.Channels, id)
		}
	}
	if state.Valid {
		rt := &scheduler.Runtime{State: scheduler.State(state.String), Since: pt(since), LastCheck: pt(last), NextCheck: pt(next),
			LastStatus: checks.Status(lastStatus.String), LastLatency: time.Duration(lastLat.Float64 * float64(time.Millisecond)),
			LastReason: checks.Reason(lastReason.String), LastMessage: lastMsg.String, ConsecutiveFail: int(cfail.Int64), ConsecutiveOK: int(cok.Int64),
			DownSince: pt(downSince)}
		c.Runtime = rt
	}
	// Push-Checks: letzter Heartbeat aus hc2_checks (gilt fuer alle Standorte). Sonst wuerde ein Standort,
	// der nach einem Ausfall (oder als Vertretung) uebernimmt, sofort "Push ausgeblieben" melden.
	if c.Type == checks.TypePush && lastPush.Valid {
		if c.Runtime == nil {
			c.Runtime = &scheduler.Runtime{State: scheduler.StatePending}
		}
		c.Runtime.LastPush = pt(lastPush)
	}
	return &c, nil
}

// Remember merkt sich userid und Intervall je Token (fuer Events, Wartung, Verdict).
func (s *Store) Remember(c *Check) {
	s.mu.Lock()
	s.users[c.Token] = c.UserID
	s.intervl[c.Token] = int(c.Interval.Seconds())
	s.mu.Unlock()
}

// Forget vergisst einen Token.
func (s *Store) Forget(token string) {
	s.mu.Lock()
	delete(s.users, token)
	delete(s.intervl, token)
	delete(s.states, token)
	s.mu.Unlock()
}

// ConfigChange ist eine Zeile aus hc2_config_log.
type ConfigChange struct {
	ID       int64
	UserID   int64
	Entity   string
	EntityID string
	Op       string
}

// MaxConfigLogID liefert die hoechste Log-ID (Startpunkt).
func (s *Store) MaxConfigLogID(ctx context.Context) (int64, error) {
	var id sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MAX(id) FROM hc2_config_log`).Scan(&id)
	return id.Int64, err
}

// ConfigChanges liefert Aenderungen seit einer Log-ID.
func (s *Store) ConfigChanges(ctx context.Context, since int64, limit int) ([]ConfigChange, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, userid, entity, entity_id, op FROM hc2_config_log WHERE id > ? ORDER BY id LIMIT ?`, since, limit)
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
		return nil, err
	}
	defer rows.Close()
	var out []ConfigChange
	for rows.Next() {
		var c ConfigChange
		if err := rows.Scan(&c.ID, &c.UserID, &c.Entity, &c.EntityID, &c.Op); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// PushRow ist ein eingegangener Heartbeat (von health.php oder dem hub geschrieben).
type PushRow struct {
	Token      string
	Time       time.Time
	ReceivedAt time.Time
	Status     checks.Status
	Message    string
}

// Pushes liefert Heartbeats, die seit received_at eingegangen sind.
func (s *Store) Pushes(ctx context.Context, since time.Time) ([]PushRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT token, time, received_at, status, message FROM hc2_measurements WHERE source = 'push' AND received_at > ? ORDER BY received_at LIMIT 5000`, ft(since))
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
		return nil, err
	}
	defer rows.Close()
	var out []PushRow
	for rows.Next() {
		var p PushRow
		var t, r sql.NullString
		var st int
		if err := rows.Scan(&p.Token, &t, &r, &st, &p.Message); err != nil {
			return nil, err
		}
		p.Time, p.ReceivedAt = pt(t), pt(r)
		p.Status = checks.Down
		if st == 1 {
			p.Status = checks.Up
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
