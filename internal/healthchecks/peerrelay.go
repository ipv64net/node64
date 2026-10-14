package healthchecks

import (
	"context"
	"time"
)

// Weiterreichen der hub-Daten in der lokalen Gruppe (peer-Paket): Eine verknuepfte Node gibt an Nodes ohne
// Healthchecks-Sync weiter, was sie vom hub weiss – fuer Checks, die kein Mitglied der Gruppe misst, den
// Gesamtzustand, und fuer alle Checks die Messstellen ausserhalb der Gruppe (ipv64-Standorte, andere Nodes)
// samt Messpunkten. Was ein Mitglied selbst misst, kommt weiter direkt von ihm.

// RelaySource ist der Zustand einer Messstelle, wie ihn der hub meldet.
type RelaySource struct {
	Source    string    `json:"source"`
	Label     string    `json:"label"`
	State     string    `json:"state"`
	Since     time.Time `json:"since"`
	LastCheck time.Time `json:"last_check"`
	Status    string    `json:"status"`
	LatencyMS float64   `json:"latency_ms"`
	Reason    string    `json:"reason"`
	Message   string    `json:"message"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RelayState ist der Gesamtzustand eines Checks vom hub mit den Messstellen ausserhalb der Gruppe.
type RelayState struct {
	Token     string        `json:"token"`
	State     string        `json:"state,omitempty"` // leer = diese Node misst ihn selbst (kein Gesamtzustand vom hub)
	Since     time.Time     `json:"since"`
	LastCheck time.Time     `json:"last_check"`
	Status    string        `json:"status"`
	LatencyMS float64       `json:"latency_ms"`
	Reason    string        `json:"reason"`
	Message   string        `json:"message"`
	Sources   []RelaySource `json:"sources,omitempty"`
}

// RelayPoint ist ein Messpunkt einer Messstelle ausserhalb der Gruppe.
type RelayPoint struct {
	Token     string    `json:"token"`
	Source    string    `json:"source"`
	Time      time.Time `json:"time"`
	Status    int       `json:"status"` // 1 up, 0 down
	LatencyMS float64   `json:"latency_ms"`
	Reason    string    `json:"reason,omitempty"`
	Message   string    `json:"message,omitempty"`
}

// PeerRelayStates liefert die Zustaende vom hub (keep: Messstelle gehoert nicht zur Gruppe).
func (m *Module) PeerRelayStates(ctx context.Context, keep func(source string) bool) []RelayState {
	list, err := m.st.Checks(ctx)
	if err != nil {
		return nil
	}
	byToken := map[string]*RelayState{}
	var out []*RelayState
	for _, c := range list {
		r := &RelayState{Token: c.Token}
		if !c.MeasuredHere() { // Gesamtzustand kommt vom hub
			r.State, r.Since, r.LastCheck, r.Status = string(c.Runtime.State), c.Runtime.Since, c.Runtime.LastCheck, string(c.Runtime.LastStatus)
			r.LatencyMS, r.Reason, r.Message = msf(c.Runtime.LastLatency), string(c.Runtime.LastReason), c.Runtime.LastMessage
		}
		byToken[c.Token] = r
		out = append(out, r)
	}
	rows, err := m.st.r.QueryContext(ctx, `SELECT token, source, label, state, since, last_check_at, last_status, latency_ms, reason, message, updated_at FROM hc_sources`)
	if err == nil {
		for rows.Next() {
			var s RelaySource
			var token, since, last, upd string
			if rows.Scan(&token, &s.Source, &s.Label, &s.State, &since, &last, &s.Status, &s.LatencyMS, &s.Reason, &s.Message, &upd) != nil || !keep(s.Source) {
				continue
			}
			if r := byToken[token]; r != nil {
				s.Since, s.LastCheck, s.UpdatedAt = pt(since), pt(last), pt(upd)
				r.Sources = append(r.Sources, s)
			}
		}
		rows.Close()
	}
	res := make([]RelayState, 0, len(out))
	for _, r := range out {
		if r.State != "" || len(r.Sources) > 0 {
			res = append(res, *r)
		}
	}
	return res
}

// PeerRelayPoints liefert Messpunkte vom hub: aus hc_measurements (Checks, die diese Node nicht misst) ab der
// laufenden Nummer seq und aus hc_source_points (Hybrid-Checks, die sie misst) ab dem Zeitpunkt from.
func (m *Module) PeerRelayPoints(ctx context.Context, seq int64, from time.Time, limit int, keep func(source string) bool) (pts []RelayPoint, lastSeq int64, lastTime time.Time, more bool, err error) {
	lastSeq, lastTime = seq, from
	rows, err := m.st.r.QueryContext(ctx, `SELECT node_seq, token, time, status, latency_ms, reason, message, details FROM hc_measurements WHERE flags & 8 != 0 AND node_seq > ? ORDER BY node_seq LIMIT ?`, seq, limit)
	if err != nil {
		return nil, seq, from, false, err
	}
	n := 0
	for rows.Next() {
		var p RelayPoint
		var t string
		if rows.Scan(&lastSeq, &p.Token, &t, &p.Status, &p.LatencyMS, &p.Reason, &p.Message, &p.Source) != nil {
			continue
		}
		n++
		if keep(p.Source) {
			p.Time = pt(t)
			pts = append(pts, p)
		}
	}
	rows.Close()
	more = n == limit
	rows, err = m.st.r.QueryContext(ctx, `SELECT token, source, time, status, latency_ms FROM hc_source_points WHERE time > ? ORDER BY time LIMIT ?`, ft(from), limit)
	if err != nil {
		return pts, lastSeq, lastTime, more, nil
	}
	n = 0
	for rows.Next() {
		var p RelayPoint
		var t string
		if rows.Scan(&p.Token, &p.Source, &t, &p.Status, &p.LatencyMS) != nil {
			continue
		}
		n++
		p.Time = pt(t)
		lastTime = p.Time
		if keep(p.Source) {
			pts = append(pts, p)
		}
	}
	rows.Close()
	return pts, lastSeq, lastTime, more || n == limit, nil
}

// PeerRelayStart: Ausgangspunkte fuer den ersten Abruf (nur die juengste Zeit ab from).
func (m *Module) PeerRelayStart(ctx context.Context, from time.Time) int64 {
	var seq int64
	if m.st.r.QueryRowContext(ctx, `SELECT COALESCE(MIN(node_seq), 0) FROM hc_measurements WHERE flags & 8 != 0 AND time >= ?`, ft(from)).Scan(&seq) != nil || seq == 0 {
		return m.MaxMeasurementSeq(ctx)
	}
	return seq - 1
}

// ApplyPeerRelay uebernimmt hub-Daten von einer verknuepften Node der Gruppe. overall sagt je Check (messende
// Nodes), ob der Gesamtzustand vom hub gilt (keine Node der Gruppe misst ihn).
func (m *Module) ApplyPeerRelay(ctx context.Context, states []RelayState, pts []RelayPoint, overall func(nodes []string) bool) (int, error) {
	cache := map[string]*Check{}
	get := func(token string) *Check {
		c, ok := cache[token]
		if !ok {
			c, _ = m.st.Check(ctx, token)
			cache[token] = c
		}
		return c
	}
	// vor der Transaktion entscheiden: overall fragt die Gruppe (Datenbank), die Transaktion haelt die einzige
	// Schreibverbindung – darin aufgerufen, wartete die Node auf sich selbst
	take := map[string]bool{}
	for _, r := range states {
		if c := get(r.Token); c != nil && r.State != "" && !c.MeasuredHere() && (c.Execution == "online" || overall(c.Nodes)) {
			take[r.Token] = true
		}
	}
	for _, p := range pts {
		get(p.Token)
	}
	tx, err := m.st.w.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	var verdicts []RemoteState
	for _, r := range states {
		c := get(r.Token)
		if c == nil {
			continue
		}
		for _, s := range r.Sources {
			if !sourceBelongs(c, s.Source) {
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO hc_sources (token, source, label, state, since, last_check_at, last_status, latency_ms, reason, message, updated_at)
				VALUES (?,?,?,?,?,?,?,?,?,?,?)
				ON CONFLICT(token, source) DO UPDATE SET label=excluded.label, state=excluded.state, since=excluded.since, last_check_at=excluded.last_check_at,
					last_status=excluded.last_status, latency_ms=excluded.latency_ms, reason=excluded.reason, message=excluded.message, updated_at=excluded.updated_at`,
				r.Token, s.Source, s.Label, s.State, ft(s.Since), ft(s.LastCheck), s.Status, s.LatencyMS, s.Reason, s.Message, ft(s.UpdatedAt)); err != nil {
				return 0, err
			}
		}
		if !take[r.Token] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE hc_checks SET state=?, state_since=?, last_check_at=?, last_status=?, last_latency_ms=?, last_reason=?, last_message=? WHERE token=?`,
			r.State, ft(r.Since), ft(r.LastCheck), r.Status, r.LatencyMS, r.Reason, r.Message, r.Token); err != nil {
			return 0, err
		}
		verdicts = append(verdicts, RemoteState{Token: r.Token, State: r.State, Since: r.Since, Reason: r.Reason, Message: r.Message})
	}
	n := 0
	for _, p := range pts {
		c := get(p.Token)
		if c == nil || !sourceBelongs(c, p.Source) {
			continue
		}
		if c.MeasuredHere() {
			_, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO hc_source_points (token, source, time, status, latency_ms) VALUES (?,?,?,?,?)`,
				p.Token, p.Source, ft(p.Time), p.Status, p.LatencyMS)
		} else {
			_, err = tx.ExecContext(ctx, `INSERT INTO hc_measurements (token, time, status, latency_ms, reason, message, family, details, flags)
				SELECT ?,?,?,?,?,?,'',?,8 WHERE NOT EXISTS (SELECT 1 FROM hc_measurements WHERE token = ? AND time = ? AND details = ?)`,
				p.Token, ft(p.Time), p.Status, p.LatencyMS, p.Reason, p.Message, p.Source, p.Token, ft(p.Time), p.Source)
		}
		if err != nil {
			return 0, err
		}
		n++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	for _, r := range verdicts { // Stoerungen wie beim hub (nach dem Commit, eigene Schreibvorgaenge)
		if r.State != "pending" {
			m.remoteIncident(ctx, r)
		}
	}
	return n, nil
}
