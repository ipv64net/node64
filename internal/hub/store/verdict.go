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
	var policy, state, name string
	var intervalSec int
	var incident sql.NullInt64
	var downSince sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT userid, policy, state, name, interval_sec, incident_id, down_since FROM hc2_checks WHERE token = ? AND deleted_at IS NULL FOR UPDATE`, token).
		Scan(&userid, &policy, &state, &name, &intervalSec, &incident, &downSince)
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
	if _, err := tx.ExecContext(ctx, `INSERT INTO hc2_events (event_id, token, userid, source, kind, time, from_state, to_state, reason, message, duration_sec, flaps, flags, incident_id)
		VALUES (?,?,?,'',?,?,?,?,?,?,?,0,?,?)`,
		scheduler.NewID(), token, userid, kind, nowS, string(old), string(overall), nullStr(reason), truncate(message, 500), durationSec, flags, incidentID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.log.Info("overall state changed", "token", token, "name", name, "from", old, "to", overall, "down", downList, "up", upList)
	return nil
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
		return "up", from != scheduler.StatePending // pending -> up ist kein Alarm
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
