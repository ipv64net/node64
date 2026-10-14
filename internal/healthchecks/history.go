package healthchecks

import (
	"context"
	"time"
)

// Verlauf fremder Messstellen (ipv64-Standorte, andere Nodes) vom hub nachladen: nach einem Zuruecksetzen,
// einer neuen Verknuepfung oder einer Offline-Zeit fehlen der Node diese Punkte, weil sie sie nur live bekommt.
// Der Sync-Client holt sie (Einzelmessungen bis 2 Tage, davor Stundenwerte); hier werden sie abgelegt wie die
// Live-Werte, ohne vorhandene Punkte zu verdoppeln.

// HistoryPoint ist eine Einzelmessung (Status, Latenz) oder ein Stundenwert (Count/Up) einer Messstelle.
type HistoryPoint struct {
	Source string    `json:"s"`
	Time   time.Time `json:"t"`
	Status int       `json:"st"`
	MS     float64   `json:"ms"`
	Count  int       `json:"n,omitempty"`
	Up     int       `json:"up,omitempty"`
}

// HistoryGaps liefert je Check den Zeitpunkt, ab dem fremde Messpunkte fehlen (hoechstens maxAge zurueck).
// Checks ohne Luecke (letzter fremder Punkt juenger als drei Intervalle, mindestens 5 min) fehlen in der Liste,
// ebenso Checks, die nur diese Node misst.
func (m *Module) HistoryGaps(ctx context.Context, maxAge time.Duration) map[string]time.Time {
	latest := map[string]time.Time{}
	rows, err := m.st.r.QueryContext(ctx, `SELECT token, MAX(time) FROM (SELECT token, time FROM hc_measurements WHERE (flags & 8) != 0
		UNION ALL SELECT token, time FROM hc_source_points) GROUP BY token`)
	if err == nil {
		for rows.Next() {
			var tok, t string
			if rows.Scan(&tok, &t) == nil {
				latest[tok] = pt(t)
			}
		}
		rows.Close()
	}
	list, err := m.st.Checks(ctx)
	if err != nil {
		return nil
	}
	now := time.Now().UTC()
	floor := now.Add(-maxAge).Truncate(time.Hour) // gleiche Grenze wie die Stundenwerte
	out := map[string]time.Time{}
	for _, c := range list {
		if c.Execution == "local" && len(c.Nodes) <= 1 && c.MeasuresHere() {
			continue // keine fremden Messstellen
		}
		l := latest[c.Token]
		gap := max(5*time.Minute, 3*c.Interval)
		if !l.IsZero() && now.Sub(l) < gap {
			continue
		}
		since := floor
		if l.After(floor) {
			since = l
		}
		out[c.Token] = since
	}
	return out
}

// HistoryEarliest: aeltester fremder Messpunkt je Check (fuer das einmalige Nachladen davor).
func (m *Module) HistoryEarliest(ctx context.Context) map[string]time.Time {
	out := map[string]time.Time{}
	rows, err := m.st.r.QueryContext(ctx, `SELECT token, MIN(time) FROM (SELECT token, time FROM hc_measurements WHERE (flags & 8) != 0
		UNION ALL SELECT token, time FROM hc_source_points) GROUP BY token`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var tok, t string
		if rows.Scan(&tok, &t) == nil {
			out[tok] = pt(t)
		}
	}
	return out
}

// DropSourceHourlyFrom verwirft Stundenwerte fremder Messstellen ab from, sobald dort Einzelpunkte liegen
// (sonst zaehlte das Diagramm diese Stunden doppelt).
func (m *Module) DropSourceHourlyFrom(ctx context.Context, token string, from time.Time) {
	_, _ = m.st.w.ExecContext(ctx, `DELETE FROM hc_source_hourly WHERE token = ? AND hour >= ?`, token, ft(from))
}

// HistoryTokens: alle Checks mit moeglichen fremden Messstellen (fuer die Stundenwerte nach dem Verknuepfen).
func (m *Module) HistoryTokens(ctx context.Context) []string {
	list, err := m.st.Checks(ctx)
	if err != nil {
		return nil
	}
	var out []string
	for _, c := range list {
		if !(c.Execution == "local" && len(c.Nodes) <= 1 && c.MeasuresHere()) {
			out = append(out, c.Token)
		}
	}
	return out
}

// StoreHistory legt nachgeladene Einzelmessungen ab: misst diese Node den Check mit, in hc_source_points,
// sonst als fremde Punkte in hc_measurements (flags 8, Messstelle in details). Liefert die Zahl neuer Punkte.
func (m *Module) StoreHistory(ctx context.Context, token string, pts []HistoryPoint) int {
	c, _ := m.st.Check(ctx, token)
	if c == nil || len(pts) == 0 {
		return 0
	}
	self := "node:" + selfNodeID()
	tx, err := m.st.w.BeginTx(ctx, nil)
	if err != nil {
		return 0
	}
	defer tx.Rollback() //nolint:errcheck
	n := 0
	if c.MeasuresHere() {
		for _, p := range pts {
			if p.Source == self {
				continue
			}
			res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO hc_source_points (token, source, time, status, latency_ms) VALUES (?,?,?,?,?)`, token, p.Source, ft(p.Time), p.Status, p.MS)
			if err == nil {
				if k, _ := res.RowsAffected(); k > 0 {
					n++
				}
			}
		}
	} else {
		have := map[string]bool{}
		from, to := pts[0].Time, pts[0].Time
		for _, p := range pts {
			if p.Time.Before(from) {
				from = p.Time
			}
			if p.Time.After(to) {
				to = p.Time
			}
		}
		if rows, err := tx.QueryContext(ctx, `SELECT details, time FROM hc_measurements WHERE token = ? AND (flags & 8) != 0 AND time >= ? AND time <= ?`, token, ft(from), ft(to)); err == nil {
			for rows.Next() {
				var src, t string
				if rows.Scan(&src, &t) == nil {
					have[src+"|"+t] = true
				}
			}
			rows.Close()
		}
		for _, p := range pts {
			k := p.Source + "|" + ft(p.Time)
			if p.Source == self || have[k] {
				continue
			}
			have[k] = true
			if _, err := tx.ExecContext(ctx, `INSERT INTO hc_measurements (token, time, status, latency_ms, reason, message, family, details, flags) VALUES (?,?,?,?,'','','',?,8)`,
				token, ft(p.Time), p.Status, p.MS, p.Source); err == nil {
				n++
			}
		}
	}
	if tx.Commit() != nil {
		return 0
	}
	return n
}

// StoreHistoryHourly legt nachgeladene Stundenwerte ab, nur fuer Stunden ohne Einzelpunkte dieser Messstelle
// (sonst zaehlte das Diagramm sie doppelt).
func (m *Module) StoreHistoryHourly(ctx context.Context, token string, pts []HistoryPoint) int {
	if len(pts) == 0 {
		return 0
	}
	self := "node:" + selfNodeID()
	raw := map[string]bool{}
	if rows, err := m.st.r.QueryContext(ctx, `SELECT DISTINCT details, substr(time, 1, 13) FROM hc_measurements WHERE token = ? AND (flags & 8) != 0
		UNION SELECT DISTINCT source, substr(time, 1, 13) FROM hc_source_points WHERE token = ?`, token, token); err == nil {
		for rows.Next() {
			var src, h string
			if rows.Scan(&src, &h) == nil {
				raw[src+"|"+h] = true
			}
		}
		rows.Close()
	}
	n := 0
	for _, p := range pts {
		h := ft(p.Time)[:13]
		if p.Source == self || p.Count <= 0 || raw[p.Source+"|"+h] {
			continue
		}
		var avg any
		if p.Up > 0 && p.MS > 0 {
			avg = p.MS
		}
		if res, err := m.st.w.ExecContext(ctx, `INSERT OR IGNORE INTO hc_source_hourly (token, source, hour, count, up_count, avg_ms) VALUES (?,?,?,?,?,?)`,
			token, p.Source, h+":00:00.000Z", p.Count, p.Up, avg); err == nil {
			if k, _ := res.RowsAffected(); k > 0 {
				n++
			}
		}
	}
	return n
}
