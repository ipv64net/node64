package healthchecks

import (
	"context"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/scheduler"
	"github.com/ipv64net/node64/internal/wire"
)

// Messwerte und Zustaende in der lokalen Gruppe (peer-Paket, Schritt 3): jede Node liefert ihre eigenen
// Messpunkte und Zustaende; die anderen legen sie wie die Daten vom hub als Messstelle node:<id> ab
// (Zustand in hc_sources, Punkte in hc_source_points bzw. hc_measurements). Den Gesamtzustand eines Checks,
// den diese Node nicht misst, bestimmt ohne hub die Node selbst – nach derselben Regel wie der hub.

// peerFresh: so lange gilt der Zustand einer Node der Gruppe als aktuell (sie wird alle 15 s abgefragt).
const peerFresh = 2 * time.Minute

// PeerMeasurements liefert eigene Messpunkte ab seq (ohne uebernommene) und die hoechste gelesene Nummer.
func (m *Module) PeerMeasurements(ctx context.Context, since int64, limit int) ([]wire.Measurement, int64, bool, error) {
	list, err := m.MeasurementsAfter(ctx, since, limit)
	if err != nil {
		return nil, since, false, err
	}
	last, out := since, make([]wire.Measurement, 0, len(list))
	for _, x := range list {
		last = x.Seq
		if x.Flags&8 == 0 {
			out = append(out, x)
		}
	}
	return out, last, len(list) == limit, nil
}

// PeerStartSeq: Nummer vor dem ersten Messpunkt ab from (erster Abruf einer neuen Node: nur die juengste Zeit).
func (m *Module) PeerStartSeq(ctx context.Context, from time.Time) int64 {
	var seq int64
	if err := m.st.r.QueryRowContext(ctx, `SELECT COALESCE(MIN(node_seq), 0) FROM hc_measurements WHERE time >= ?`, ft(from)).Scan(&seq); err != nil || seq == 0 {
		return m.MaxMeasurementSeq(ctx)
	}
	return seq - 1
}

// ApplyPeerData uebernimmt Zustaende und Messpunkte einer Node der Gruppe (Messstelle node:<origin>).
func (m *Module) ApplyPeerData(ctx context.Context, origin, label string, states []wire.State, ms []wire.Measurement) (int, error) {
	source := "node:" + origin
	cache := map[string]*Check{}
	get := func(token string) *Check {
		c, ok := cache[token]
		if !ok {
			c, _ = m.st.Check(ctx, token)
			cache[token] = c
		}
		if c == nil || !sourceBelongs(c, source) {
			return nil
		}
		return c
	}
	tx, err := m.st.w.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	now := ft(time.Now())
	for _, s := range states {
		if get(s.Token) == nil {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO hc_sources (token, source, label, state, since, last_check_at, last_status, latency_ms, reason, message, updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(token, source) DO UPDATE SET label=excluded.label, state=excluded.state, since=excluded.since, last_check_at=excluded.last_check_at,
				last_status=excluded.last_status, latency_ms=excluded.latency_ms, reason=excluded.reason, message=excluded.message, updated_at=excluded.updated_at`,
			s.Token, source, label, s.State, ft(s.Since), ft(s.LastCheckAt), s.LastStatus, s.LatencyMS, s.Reason, s.Message, now); err != nil {
			return 0, err
		}
	}
	n := 0
	for _, x := range ms {
		c := get(x.Token)
		if c == nil || (x.Status != "up" && x.Status != "down") {
			continue
		}
		st := 0
		if x.Status == "up" {
			st = 1
		}
		if c.MeasuredHere() { // Diagramm mit einer Linie je Messstelle
			_, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO hc_source_points (token, source, time, status, latency_ms) VALUES (?,?,?,?,?)`,
				x.Token, source, ft(x.Time), st, x.LatencyMS)
		} else { // wie Punkte vom hub: flags 8, Messstelle in details
			_, err = tx.ExecContext(ctx, `INSERT INTO hc_measurements (token, time, status, latency_ms, reason, message, family, details, flags)
				SELECT ?,?,?,?,?,?,?,?,8 WHERE NOT EXISTS (SELECT 1 FROM hc_measurements WHERE token = ? AND time = ? AND details = ?)`,
				x.Token, ft(x.Time), st, x.LatencyMS, x.Reason, x.Message, x.Family, source, x.Token, ft(x.Time), source)
		}
		if err != nil {
			return 0, err
		}
		n++
	}
	return n, tx.Commit()
}

// PeerVerdicts bestimmt den Gesamtzustand der Checks, die diese Node nicht misst, aus den Messstellen
// (decide sagt je Check, ob die Gruppe entscheidet und nicht der hub).
func (m *Module) PeerVerdicts(ctx context.Context, decide func(nodes []string) bool) {
	list, err := m.st.Checks(ctx)
	if err != nil {
		return
	}
	for _, c := range list {
		if c.MeasuredHere() || c.Execution == "online" || !decide(c.Nodes) {
			continue
		}
		m.peerVerdict(ctx, c)
	}
}

func (m *Module) peerVerdict(ctx context.Context, c *Check) {
	type src struct {
		scheduler.SourceState
		since, last, updated time.Time
		latency              float64
		reason, message      string
	}
	rows, err := m.st.r.QueryContext(ctx, `SELECT source, state, last_status, since, last_check_at, latency_ms, reason, message, updated_at FROM hc_sources WHERE token = ?`, c.Token)
	if err != nil {
		return
	}
	var srcs []src
	nodes := 0
	fresh := 3 * c.Interval
	if fresh < 5*time.Minute {
		fresh = 5 * time.Minute
	}
	for rows.Next() {
		var x src
		var state, status, since, last, upd string
		if rows.Scan(&x.Source, &state, &status, &since, &last, &x.latency, &x.reason, &x.message, &upd) != nil || !sourceBelongs(c, x.Source) {
			continue
		}
		x.State, x.LastStatus = scheduler.State(state), checks.Status(status)
		x.since, x.last, x.updated = pt(since), pt(last), pt(upd)
		limit := fresh
		if strings.HasPrefix(x.Source, "node:") {
			nodes++
			limit = peerFresh
		}
		x.Fresh = !x.updated.IsZero() && time.Since(x.updated) <= limit
		srcs = append(srcs, x)
	}
	rows.Close()
	if nodes == 0 {
		return // keine Node der Gruppe misst ihn: Zustand bleibt, wie er ist
	}
	states := make([]scheduler.SourceState, len(srcs))
	for i := range srcs {
		states[i] = srcs[i].SourceState
	}
	overall := scheduler.Overall(c.Policy, states)
	if c.Paused {
		overall = scheduler.StatePaused
	}
	// bestimmende Messstelle: bei Stoerung eine gestoerte, sonst die zuletzt gemessene
	bad := overall == scheduler.StateDown || overall == scheduler.StateDegraded || overall == scheduler.StateFlapping
	var lead *src
	for i := range srcs {
		x := &srcs[i]
		if !x.Fresh {
			continue
		}
		isDown := x.State == scheduler.StateDown || (x.State == scheduler.StateFlapping && x.LastStatus == checks.Down)
		if bad && !isDown {
			continue
		}
		if lead == nil || x.last.After(lead.last) {
			lead = x
		}
	}
	since := c.Runtime.Since
	if overall != c.Runtime.State || since.IsZero() {
		since = time.Now().UTC()
		if lead != nil && !lead.since.IsZero() && overall == lead.State {
			since = lead.since
		}
	}
	if lead == nil { // keine aktuelle Messung (z. B. messende Node aus): letzte Messung bleibt stehen
		_, _ = m.st.w.ExecContext(ctx, `UPDATE hc_checks SET state=?, state_since=? WHERE token=?`, string(overall), ft(since), c.Token)
	} else {
		_, _ = m.st.w.ExecContext(ctx, `UPDATE hc_checks SET state=?, state_since=?, last_check_at=?, last_status=?, last_latency_ms=?, last_reason=?, last_message=? WHERE token=?`,
			string(overall), ft(since), ft(lead.last), string(lead.LastStatus), lead.latency, lead.reason, lead.message, c.Token)
	}
	if overall == scheduler.StatePending {
		return // unbekannt: eine offene Stoerung bleibt offen
	}
	r := RemoteState{Token: c.Token, State: string(overall), Since: since}
	if lead != nil {
		r.Reason, r.Message = lead.reason, lead.message
	}
	m.remoteIncident(ctx, r)
}
