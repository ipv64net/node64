package store

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/scheduler"
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
	var intervalSec, critical, nd, nu, ndeg, paused int
	var incident sql.NullInt64
	var downSince sql.NullString
	var execution, nodesCol string
	var ownerNode sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT userid, policy, state, name, interval_sec, incident_id, down_since, type, target, critical, channels, notify_down, notify_up, notify_degraded, execution, paused, nodes, node_id
		FROM hc2_checks WHERE token = ? AND deleted_at IS NULL FOR UPDATE`, token).
		Scan(&userid, &policy, &state, &name, &intervalSec, &incident, &downSince, &ctype, &target, &critical, &channels, &nd, &nu, &ndeg, &execution, &paused, &nodesCol, &ownerNode)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}

	rows, err := tx.QueryContext(ctx, `SELECT source, state, last_status, last_reason, last_message, last_latency_ms, updated_at, since FROM hc2_check_states WHERE token = ?`, token)
	if err != nil {
		return err
	}
	type src struct {
		scheduler.SourceState
		reason, message string
		latency         float64
		updated, since  time.Time
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
		var upd, since sql.NullString
		if err := rows.Scan(&x.Source, &st, &ls, &reason, &msg, &lat, &upd, &since); err != nil {
			rows.Close()
			return err
		}
		x.State, x.LastStatus = scheduler.State(st.String), checks.Status(ls.String)
		x.reason, x.message, x.latency, x.updated, x.since = reason.String, msg.String, lat.Float64, pt(upd), pt(since)
		// Nach dem Umhaengen zaehlen nur Messstellen des aktuellen Ausfuehrungsorts
		isNode := strings.HasPrefix(x.Source, "node:")
		if (execution == "online" && isNode) || (execution == "local" && !isNode) {
			continue
		}
		if isNode && !inList(measuringNodes(splitList(nodesCol), ownerNode.String), strings.TrimPrefix(x.Source, "node:")) {
			continue // Node misst den Check nicht (mehr)
		}
		// Node-Messstellen sind frisch, solange die Node online ist und den Check noch misst (Zustand nicht aelter
		// als 3 Intervalle, mind. 5 min); Standorte nach Alter des Zustands
		if strings.HasPrefix(x.Source, "node:") {
			x.Fresh = !x.updated.IsZero() && now.Sub(x.updated) <= fresh && s.NodeIsOnline(ctx, strings.TrimPrefix(x.Source, "node:"))
		} else {
			x.Fresh = !x.updated.IsZero() && now.Sub(x.updated) <= fresh
		}
		srcs = append(srcs, x)
	}
	rows.Close()

	states := make([]scheduler.SourceState, len(srcs))
	for i := range srcs {
		states[i] = srcs[i].SourceState
	}
	overall := scheduler.Overall(policy, states)
	if paused != 0 {
		overall = scheduler.StatePaused // pausiert statt "pending" (pausierte Messstellen zaehlen nicht)
	}
	// keine aktuelle Messstelle mehr: erst nach dem Fenster (3 Intervalle, mind. 5 min) als "nicht geprueft" werten,
	// bis dahin bleibt der Zustand stehen (ein kurzer Verbindungsabbruch einer Node aendert nichts)
	var newest time.Time
	anyFresh := false
	for _, x := range srcs {
		anyFresh = anyFresh || x.Fresh
		if x.updated.After(newest) {
			newest = x.updated
		}
	}
	if overall == scheduler.StatePending && paused == 0 && len(srcs) > 0 && !anyFresh && now.Sub(newest) <= fresh {
		return tx.Commit()
	}
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
	incidentOpen := incident.Valid && incident.Int64 > 0
	kind, silent := eventKind(old, overall, incidentOpen)
	// Keine Messstelle meldet mehr (z. B. die einzige messende Node ist offline): "wird nicht geprueft" melden statt
	// still auf "ausstehend" zu gehen; kommt wieder eine Messung, "wird wieder geprueft".
	lastCheck := nowStr()
	unchecked := overall == scheduler.StatePending && paused == 0 && len(srcs) > 0 && lead == nil
	if unchecked && old != scheduler.StatePending {
		kind, silent = "unchecked", false
		var nodeIDs []string
		for _, x := range srcs {
			if strings.HasPrefix(x.Source, "node:") {
				nodeIDs = append(nodeIDs, strings.TrimPrefix(x.Source, "node:"))
			}
		}
		reason, message = "unchecked", "keine Messung mehr seit "+newest.UTC().Format("02.01. 15:04")+" UTC"
		if names := nodeNames(ctx, tx, nodeIDs); len(names) > 0 {
			message += " – nicht erreichbar: " + strings.Join(names, ", ")
		}
		if !newest.IsZero() {
			lastCheck = newest.UTC().Format(TimeFormat)
		}
	} else if old == scheduler.StatePending && overall == scheduler.StateUp {
		var last string
		_ = tx.QueryRowContext(ctx, `SELECT kind FROM hc2_events WHERE token = ? ORDER BY time DESC LIMIT 1`, token).Scan(&last)
		if last == "unchecked" {
			kind, silent = "rechecked", false
		}
	}
	// Verspaetet gemeldeter Zustand einer Node (Node war offline oder der hub ohne Datenbank):
	// die Node hat in der Zeit selbst benachrichtigt, also hier still nachtragen statt doppelt melden.
	if lead != nil && strings.HasPrefix(lead.Source, "node:") && now.Sub(lead.updated) < 15*time.Second && !lead.since.IsZero() && now.Sub(lead.since) > 5*time.Minute {
		silent = true
	}
	// misst eine Stellvertreter-Node mit, benachrichtigt die lokale Gruppe (hier nur anzeigen)
	if !silent && execution != "online" {
		proxies, err := proxySet(ctx, tx, measuringNodes(splitList(nodesCol), ownerNode.String))
		if err != nil {
			return err
		}
		silent = len(proxies) > 0
	}
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
	case incidentID != nil && overall != scheduler.StateDown && overall != scheduler.StateFlapping && overall != scheduler.StateDegraded && overall != scheduler.StatePaused &&
		overall != scheduler.StatePending:
		// degraded nach down laesst die Stoerung offen: erst "up" beendet sie (ohne Messung bleibt sie offen)
		if _, err := tx.ExecContext(ctx, `UPDATE hc2_incidents SET ended_at = ? WHERE id = ? AND ended_at IS NULL`, nowS, incidentID); err != nil {
			return err
		}
		incidentID = nil
	case incidentID != nil:
		// Stoerung bleibt offen (down <-> degraded/flapping): betroffene Messstellen nachfuehren
		if _, err := tx.ExecContext(ctx, `UPDATE hc2_incidents SET sources = ? WHERE id = ? AND ended_at IS NULL`, strings.Join(downList, ","), incidentID); err != nil {
			return err
		}
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
		string(overall), nowS, lastCheck, nullStr(lastStatus), latency, nullStr(reason), truncate(message, 500), newDownSince, incidentID, token); err != nil {
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
	Execution            string // nur bei Erinnerungen gesetzt (online, both)
}

// eventKind leitet Ereignisart und Stille aus dem Wechsel ab. incidentOpen:
// vor dem Wechsel lief eine Stoerung (Check war down/flapping, evtl. inzwischen
// teilweise erholt). Erst "up" beendet sie; "degraded" dazwischen ist nur fuer
// Nutzer mit notify_degraded interessant.
func eventKind(from, to scheduler.State, incidentOpen bool) (string, bool) {
	switch {
	case to == scheduler.StateDown:
		return "down", false
	case to == scheduler.StateFlapping:
		return "flapping_start", false
	case to == scheduler.StateUp && from == scheduler.StateFlapping:
		return "flapping_end", false
	case to == scheduler.StateUp && incidentOpen:
		return "up", false
	case to == scheduler.StateUp && from == scheduler.StateDegraded:
		return "degraded_end", false
	case to == scheduler.StateUp && from == scheduler.StatePending:
		return "up", true // erster Zustand ist kein Alarm
	case to == scheduler.StateUp:
		return "up", true // z. B. aus paused/dependent
	case to == scheduler.StateDegraded:
		return "degraded", false
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
			if strings.HasPrefix(s, "node:") {
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
		return "innen gestört, außen OK → Heimnetz/Node"
	case outside(down) && !inside(down) && inside(up):
		return "außen gestört (" + strings.Join(down, ", ") + "), innen OK → Router/Portfreigabe/CDN"
	default:
		return "gestört: " + strings.Join(down, ", ") + "; OK: " + strings.Join(up, ", ")
	}
}

// DueReminders liefert gestoerte Checks mit Wiederholung (repeat_minutes > 0).
// Time = down_since, Duration = Wiederholungsabstand.
func (s *Store) DueReminders(ctx context.Context) ([]OverallEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT token, userid, name, type, target, critical, channels, notify_down, notify_up, notify_degraded, repeat_minutes, down_since, last_reason, last_message, execution
		FROM hc2_checks WHERE deleted_at IS NULL AND repeat_minutes > 0 AND state IN ('down','flapping') AND execution IN ('online','both')
		AND NOT EXISTS (SELECT 1 FROM hc2_nodes n WHERE n.userid = hc2_checks.userid AND n.proxy_via IS NOT NULL AND n.revoked_at IS NULL
			AND (FIND_IN_SET(n.node_id, hc2_checks.nodes) > 0 OR n.node_id = hc2_checks.node_id))`) // Stellvertreter: die Gruppe erinnert
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
		if err := rows.Scan(&e.Token, &e.UserID, &e.Name, &e.Type, &e.Target, &critical, &channels, &nd, &nu, &ndeg, &repeat, &ds, &reason, &msg, &e.Execution); err != nil {
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

func inList(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// UncheckedSweep bewertet Checks neu, fuer die seit mehr als 3 Intervallen (mind. 5 min) keine Messstelle mehr
// gemeldet hat, z. B. weil die einzige messende Node offline ist. Ohne neue Messungen liefe sonst keine Bewertung,
// und der Check bliebe beim letzten Zustand stehen. Nur der Housekeeper, einmal je Minute.
func (s *Store) UncheckedSweep(ctx context.Context) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT c.token FROM hc2_checks c WHERE c.deleted_at IS NULL AND c.paused = 0 AND c.execution IN ('local','both')
		AND c.state NOT IN ('pending','paused')
		AND NOT EXISTS (SELECT 1 FROM hc2_check_states st WHERE st.token = c.token AND st.updated_at > UTC_TIMESTAMP(3) - INTERVAL GREATEST(3 * c.interval_sec, 300) SECOND)
		LIMIT 500`)
	if err != nil {
		s.Metrics.add(&s.Metrics.DBErrors, 1)
		return 0, err
	}
	var tokens []string
	for rows.Next() {
		var t string
		if rows.Scan(&t) == nil {
			tokens = append(tokens, t)
		}
	}
	rows.Close()
	n := 0
	for _, t := range tokens {
		if err := s.Reverdict(ctx, t); err != nil {
			s.log.Warn("verdict of unchecked check failed", "token", t[:min(6, len(t))]+"…", "err", err)
			continue
		}
		n++
	}
	return n, rows.Err()
}

// nodeNames liefert die Namen der Nodes (fuer Meldungstexte).
func nodeNames(ctx context.Context, q rowQuerier, ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	rows, err := q.QueryContext(ctx, `SELECT name FROM hc2_nodes WHERE node_id IN (`+strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")+`) ORDER BY name`, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			out = append(out, n)
		}
	}
	return out
}
