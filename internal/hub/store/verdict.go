package store

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/ipv64net/agent/internal/checks"
	"github.com/ipv64net/agent/internal/scheduler"
)

// Reverdict berechnet den Gesamtzustand eines Checks aus allen Messstellen
// (Sync-Plan 3.12) und schreibt bei einem Wechsel Zustand, Ereignis und
// Stoerung. Laeuft in einer Transaktion mit Zeilensperre, damit zwei
// Instanzen nicht gleichzeitig entscheiden.
func (s *Store) Reverdict(ctx context.Context, token string) error {
	s.Metrics.add(&s.Metrics.Verdicts, 1)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	var userid int64
	var policy, state, name, ctype, target, channels string
	var intervalSec, critical, nd, nu, ndeg int
	var incident sql.NullInt64
	var downSince sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT userid, policy, state, name, interval_sec, incident_id, down_since, type, target, critical, channels, notify_down, notify_up, notify_degraded
		FROM hc2_checks WHERE token = ? AND deleted_at IS NULL FOR UPDATE`, token).
		Scan(&userid, &policy, &state, &name, &intervalSec, &incident, &downSince, &ctype, &target, &critical, &channels, &nd, &nu, &ndeg)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}

	rows, err := tx.QueryContext(ctx, `SELECT source, state, last_status, last_reason, last_message, last_latency_ms, updated_at FROM hc2_check_states WHERE token = ?`, token)
	if err != nil {
		return err
	}
	type src struct {
		scheduler.SourceState
		reason, message string
		latency         float64
		updated         time.Time
	}
	var srcs []src
	now := time.Now().UTC()
	fresh := time.Duration(intervalSec) * 3 * time.Second
	if fresh < 5*time.Minute {
		fresh = 5 * time.Minute
	}
	for rows.Next() {
		var x src
		var st, ls, reason, msg sql.NullString
		var lat sql.NullFloat64
		var upd sql.NullString
		if err := rows.Scan(&x.Source, &st, &ls, &reason, &msg, &lat, &upd); err != nil {
			rows.Close()
			return err
		}
		x.State, x.LastStatus = scheduler.State(st.String), checks.Status(ls.String)
		x.reason, x.message, x.latency, x.updated = reason.String, msg.String, lat.Float64, pt(upd)
		// Agent-Messstellen gelten als frisch, solange der Agent online ist (Phase 3); bis dahin wie Standorte.
		x.Fresh = !x.updated.IsZero() && now.Sub(x.updated) <= fresh
		srcs = append(srcs, x)
	}
	rows.Close()

	states := make([]scheduler.SourceState, len(srcs))
	for i := range srcs {
		states[i] = srcs[i].SourceState
	}
	overall := scheduler.Overall(policy, states)
	if string(overall) == state {
		return tx.Commit()
	}
	s.Metrics.add(&s.Metrics.OverallChanges, 1)

	// Bestimmende Messstelle: bei down/degraded eine gestoerte, sonst die zuletzt aktualisierte
	var lead *src
	for i := range srcs {
		x := &srcs[i]
		if !x.Fresh {
			continue
		}
		isDown := x.State == scheduler.StateDown || (x.State == scheduler.StateFlapping && x.LastStatus == checks.Down)
		if (overall == scheduler.StateDown || overall == scheduler.StateDegraded || overall == scheduler.StateFlapping) && !isDown {
			continue
		}
		if lead == nil || x.updated.After(lead.updated) {
			lead = x
		}
	}
	reason, message, latency, lastStatus := "", "", 0.0, ""
	if lead != nil {
		reason, message, latency = lead.reason, lead.message, lead.latency
		lastStatus = string(lead.LastStatus)
	}
	var downList, upList []string
	for _, x := range srcs {
		if !x.Fresh {
			continue
		}
		if x.State == scheduler.StateDown || (x.State == scheduler.StateFlapping && x.LastStatus == checks.Down) {
			downList = append(downList, x.Source)
		} else if x.State == scheduler.StateUp || x.State == scheduler.StateStabilizing || x.State == scheduler.StateFlapping {
			upList = append(upList, x.Source)
		}
	}
	diag := diagnosis(downList, upList)
	if diag != "" {
		message = strings.TrimSpace(message + " | " + diag)
	}

	old := scheduler.State(state)
	kind, silent := eventKind(old, overall)
	nowS := now.Format(TimeFormat)
	var durationSec int64
	ds := pt(downSince)
	if old == scheduler.StateDown && !ds.IsZero() {
		durationSec = int64(now.Sub(ds).Seconds())
	}

	// Stoerung oeffnen/schliessen
	var incidentID any
	if incident.Valid && incident.Int64 > 0 {
		incidentID = incident.Int64
	}
	switch {
	case overall == scheduler.StateDown && incidentID == nil:
		res, err := tx.ExecContext(ctx, `INSERT INTO hc2_incidents (token, userid, started_at, reason, message, sources) VALUES (?,?,?,?,?,?)`,
			token, userid, nowS, nullStr(reason), truncate(message, 500), strings.Join(downList, ","))
		if err != nil {
			return err
		}
		id, _ := res.LastInsertId()
		incidentID = id
	case overall != scheduler.StateDown && overall != scheduler.StateFlapping && incidentID != nil:
		if _, err := tx.ExecContext(ctx, `UPDATE hc2_incidents SET ended_at = ? WHERE id = ? AND ended_at IS NULL`, nowS, incidentID); err != nil {
			return err
		}
		incidentID = nil
	}

	newDownSince := any(nil)
	if overall == scheduler.StateDown || overall == scheduler.StateFlapping {
		if ds.IsZero() || (old != scheduler.StateDown && old != scheduler.StateFlapping) {
			newDownSince = nowS
		} else {
			newDownSince = ds.Format(TimeFormat)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE hc2_checks SET state = ?, state_since = ?, last_check_at = ?, last_status = ?, last_latency_ms = ?, last_reason = ?, last_message = ?,
			down_since = ?, incident_id = ? WHERE token = ?`,
		string(overall), nowS, nowS, nullStr(lastStatus), latency, nullStr(reason), truncate(message, 500), newDownSince, incidentID, token); err != nil {
		return err
	}
	flags := 0
	if silent {
		flags |= FlagSilent
	}
	eventID := scheduler.NewID()
	if _, err := tx.ExecContext(ctx, `INSERT INTO hc2_events (event_id, token, userid, source, kind, time, from_state, to_state, reason, message, duration_sec, flaps, flags, incident_id)
		VALUES (?,?,?,'',?,?,?,?,?,?,?,0,?,?)`,
		eventID, token, userid, kind, nowS, string(old), string(overall), nullStr(reason), truncate(message, 500), durationSec, flags, incidentID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.log.Info("overall state changed", "token", token, "name", name, "from", old, "to", overall, "down", downList, "up", upList)
	if !silent && s.OnOverall != nil {
		var chIDs []int64
		for _, c := range splitList(channels) {
			var id int64
			if _, err := fmtSscan(c, &id); err == nil {
				chIDs = append(chIDs, id)
			}
		}
		s.OnOverall(OverallEvent{EventID: eventID, Token: token, UserID: userid, Name: name, Type: ctype, Target: target, Kind: kind, Time: now,
			From: old, To: overall, Reason: reason, Message: message, Duration: time.Duration(durationSec) * time.Second,
			Critical: critical == 1, Channels: chIDs, NotifyDown: nd == 1, NotifyUp: nu == 1, NotifyDegraded: ndeg == 1})
	}
	return nil
}

// OverallEvent ist ein Wechsel des Gesamtzustands, der benachrichtigt werden soll.
type OverallEvent struct {
	EventID, Token       string
	UserID               int64
	Name, Type, Target   string
	Kind                 string // down, up, degraded, degraded_end, flapping_start, flapping_end
	Time                 time.Time
	From, To             scheduler.State
	Reason, Message      string
	Duration             time.Duration
	Critical             bool
	Channels             []int64
	NotifyDown, NotifyUp bool
	NotifyDegraded       bool
}

// eventKind leitet Ereignisart und Stille aus dem Wechsel ab.
func eventKind(from, to scheduler.State) (string, bool) {
	switch {
	case to == scheduler.StateDown:
		return "down", false
	case to == scheduler.StateFlapping:
		return "flapping_start", false
	case from == scheduler.StateFlapping && to == scheduler.StateUp:
		return "flapping_end", false
	case from == scheduler.StateDown || from == scheduler.StateFlapping:
		return "up", false
	case to == scheduler.StateDegraded:
		return "degraded", false
	case from == scheduler.StateDegraded && to == scheduler.StateUp:
		return "degraded_end", false
	case to == scheduler.StateUp:
		return "up", from == scheduler.StatePending // pending -> up ist kein Alarm (still)
	default:
		return "state", true
	}
}

// diagnosis liefert den Hinweistext zu den beteiligten Messstellen.
func diagnosis(down, up []string) string {
	if len(down) == 0 || len(up) == 0 {
		if len(down) > 1 {
			return "alle Messstellen gestört: " + strings.Join(down, ", ")
		}
		return ""
	}
	inside := func(list []string) bool {
		for _, s := range list {
			if strings.HasPrefix(s, "agent:") {
				return true
			}
		}
		return false
	}
	outside := func(list []string) bool {
		for _, s := range list {
			if strings.HasPrefix(s, "loc:") {
				return true
			}
		}
		return false
	}
	switch {
	case inside(down) && !outside(down) && outside(up):
		return "innen gestört, außen OK → Heimnetz/Agent"
	case outside(down) && !inside(down) && inside(up):
		return "außen gestört (" + strings.Join(down, ", ") + "), innen OK → Router/Portfreigabe/CDN"
	default:
		return "gestört: " + strings.Join(down, ", ") + "; OK: " + strings.Join(up, ", ")
	}
}

// DueReminders liefert gestoerte Checks mit Wiederholung (repeat_minutes > 0).
// Time = down_since, Duration = Wiederholungsabstand.
func (s *Store) DueReminders(ctx context.Context) ([]OverallEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT token, userid, name, type, target, critical, channels, notify_down, notify_up, notify_degraded, repeat_minutes, down_since, last_reason, last_message
		FROM hc2_checks WHERE deleted_at IS NULL AND repeat_minutes > 0 AND state IN ('down','flapping') AND execution IN ('online','both')`)
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
		return nil, err
	}
	defer rows.Close()
	var out []OverallEvent
	for rows.Next() {
		var e OverallEvent
		var critical, nd, nu, ndeg, repeat int
		var channels string
		var ds, reason, msg sql.NullString
		if err := rows.Scan(&e.Token, &e.UserID, &e.Name, &e.Type, &e.Target, &critical, &channels, &nd, &nu, &ndeg, &repeat, &ds, &reason, &msg); err != nil {
			return nil, err
		}
		e.Critical, e.NotifyDown, e.NotifyUp, e.NotifyDegraded = critical == 1, nd == 1, nu == 1, ndeg == 1
		e.Time, e.Duration, e.Reason, e.Message, e.Kind = pt(ds), time.Duration(repeat)*time.Minute, reason.String, msg.String, "reminder"
		for _, c := range splitList(channels) {
			var id int64
			if _, err := fmtSscan(c, &id); err == nil {
				e.Channels = append(e.Channels, id)
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
