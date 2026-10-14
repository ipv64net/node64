package healthchecks

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Messstellen eines Checks (Node, ipv64-Standorte, andere Nodes) wie im Portal: letzter Zustand je
// Messstelle aus den remote_states des Hubs, dazu der eigene Zustand, wenn diese Node mitmisst.

// SourceRow ist eine Zeile der Messstellen-Tabelle.
type SourceRow struct {
	Source    string
	Label     string
	State     string
	Since     time.Time
	LastCheck time.Time
	Status    string
	LatencyMS float64
	Reason    string
	Message   string
	Self      bool // diese Node
	Stale     bool // laenger keine Messung
}

// Icon fuer die Art der Messstelle.
func (s SourceRow) Icon() string {
	switch {
	case s.Self:
		return "bi-house-fill text-success"
	case strings.HasPrefix(s.Source, "loc:"):
		return "bi-cloud-fill text-primary"
	}
	return "bi-hdd-network text-secondary"
}

// sourceLabel liefert einen lesbaren Namen fuer eine Messstelle.
func sourceLabel(source, label string) string {
	switch {
	case strings.HasPrefix(source, "loc:"):
		if label == "" {
			label = strings.TrimPrefix(source, "loc:")
		}
		return "ipv64 " + label
	case label != "":
		return label
	case strings.HasPrefix(source, "node:"):
		return "Node " + strings.TrimPrefix(source, "node:")
	}
	return source
}

// sourceBelongs: gleiche Regeln wie im Hub (nach dem Umhaengen zaehlen nur aktuelle Messstellen).
func sourceBelongs(c *Check, source string) bool {
	isNode := strings.HasPrefix(source, "node:")
	if (c.Execution == "online" && isNode) || (c.Execution == "local" && !isNode) {
		return false
	}
	if isNode && len(c.Nodes) > 0 {
		id := strings.TrimPrefix(source, "node:")
		for _, n := range c.Nodes {
			if n == id {
				return true
			}
		}
		return false
	}
	if strings.HasPrefix(source, "loc:") && len(c.Locations) > 0 {
		code := strings.TrimPrefix(source, "loc:")
		for _, l := range c.Locations {
			if l == code {
				return true
			}
		}
		return false
	}
	return true
}

// applySource speichert Zustand und Messpunkt einer Messstelle. Messpunkte nur fuer Checks, die
// diese Node selbst misst (Hybrid); fuer reine Online-/Fremd-Checks liegen sie in hc_measurements.
func (m *Module) applySource(ctx context.Context, c *Check, r RemoteState) {
	_, _ = m.st.w.ExecContext(ctx, `INSERT INTO hc_sources (token, source, label, state, since, last_check_at, last_status, latency_ms, reason, message, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(token, source) DO UPDATE SET label=excluded.label, state=excluded.state, since=excluded.since, last_check_at=excluded.last_check_at,
			last_status=excluded.last_status, latency_ms=excluded.latency_ms, reason=excluded.reason, message=excluded.message, updated_at=excluded.updated_at`,
		r.Token, r.Source, r.SourceLabel, r.SourceState, ft(r.SourceSince), ft(r.Time), r.Status, r.LatencyMS, r.Reason, r.Message, ft(time.Now()))
	if c.MeasuredHere() && !r.Time.IsZero() && (r.Status == "up" || r.Status == "down") {
		st := 0
		if r.Status == "up" {
			st = 1
		}
		_, _ = m.st.w.ExecContext(ctx, `INSERT OR IGNORE INTO hc_source_points (token, source, time, status, latency_ms) VALUES (?,?,?,?,?)`,
			r.Token, r.Source, ft(r.Time), st, r.LatencyMS)
	}
}

// sources liefert die Messstellen-Tabelle eines Checks (eigene Zeile zuerst).
func (m *Module) sources(ctx context.Context, c *Check, selfLabel string) []SourceRow {
	var out []SourceRow
	rows, err := m.st.r.QueryContext(ctx, `SELECT source, label, state, since, last_check_at, last_status, latency_ms, reason, message FROM hc_sources WHERE token = ? ORDER BY source`, c.Token)
	if err != nil {
		return nil
	}
	defer rows.Close()
	staleAfter := 3 * c.Interval
	if staleAfter < 10*time.Minute {
		staleAfter = 10 * time.Minute
	}
	for rows.Next() {
		var s SourceRow
		var since, last string
		if rows.Scan(&s.Source, &s.Label, &s.State, &since, &last, &s.Status, &s.LatencyMS, &s.Reason, &s.Message) != nil {
			continue
		}
		if !sourceBelongs(c, s.Source) {
			continue
		}
		s.Since, s.LastCheck, s.Label = pt(since), pt(last), sourceLabel(s.Source, s.Label)
		s.Stale = s.LastCheck.IsZero() || time.Since(s.LastCheck) > staleAfter
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil // nur diese Node misst: keine Tabelle noetig
	}
	if c.MeasuredHere() {
		rt := m.liveRuntime(c)
		self := SourceRow{Source: "self", Label: selfLabel, State: string(rt.State), Since: rt.Since, LastCheck: rt.LastCheck, Status: string(rt.LastStatus),
			LatencyMS: msf(rt.LastLatency), Reason: string(rt.LastReason), Message: rt.LastMessage, Self: true}
		out = append([]SourceRow{self}, out...)
	}
	return out
}

// diagnosis vergleicht innen (Node) und aussen (ipv64-Standorte) wie im Portal.
func diagnosis(rows []SourceRow, tr func(string, ...any) string) string {
	in := ""
	var out []string
	for _, s := range rows {
		if s.Stale {
			continue
		}
		if s.Self || strings.HasPrefix(s.Source, "node:") {
			in = s.State
		} else if strings.HasPrefix(s.Source, "loc:") {
			out = append(out, s.State)
		}
	}
	if in == "" || len(out) == 0 {
		return ""
	}
	outUp, outDown := false, true
	for _, s := range out {
		if s == "up" {
			outUp = true
		}
		if s != "down" {
			outDown = false
		}
	}
	switch {
	case in == "down" && outUp:
		return tr("hc.diag.inside")
	case in == "up" && outDown:
		return tr("hc.diag.outside")
	case in == "down" && outDown:
		return tr("hc.diag.both")
	}
	return ""
}

// ---------------------------------------------------------------- Diagramm (Linie je Messstelle)

type chartPoint struct {
	T  time.Time `json:"t"`
	MS *float64  `json:"ms"`           // null = gestoert bzw. keine Messung
	Up *float64  `json:"up,omitempty"` // Verfuegbarkeit in % (Stunden-/Tageswerte)
}

type chartSeries struct {
	Source string       `json:"source"`
	Label  string       `json:"label"`
	Points []chartPoint `json:"points"`
}

var chartRanges = map[string]struct {
	span   time.Duration
	bucket string // raw, hour, day
}{
	"1h": {time.Hour, "raw"}, "6h": {6 * time.Hour, "raw"}, "24h": {24 * time.Hour, "raw"},
	"7d": {7 * 24 * time.Hour, "hour"}, "30d": {30 * 24 * time.Hour, "hour"}, "1y": {365 * 24 * time.Hour, "day"},
}

func f64(v float64) *float64 { return &v }

// apiChart liefert Messreihen je Messstelle: bis 24 h Einzelmessungen, 7/30 Tage Stundenmittel,
// 1 Jahr Tagesmittel (wie das Portal).
func (m *Module) apiChart(w http.ResponseWriter, r *http.Request) {
	c := m.load(w, r)
	if c == nil {
		return
	}
	rng := r.URL.Query().Get("range")
	cr, ok := chartRanges[rng]
	if !ok {
		writeErr(w, http.StatusBadRequest, "range must be one of 1h, 6h, 24h, 7d, 30d, 1y")
		return
	}
	cr.bucket = chartBuckets[ChartDetail(m.core)][rng] // Diagramm-Aufloesung aus den Einstellungen
	rawCut := time.Now().UTC().Add(-m.st.rawRetention())
	ctx := r.Context()
	lang := ""
	if m.g.Lang != nil {
		lang = m.g.Lang(r)
	}
	tr := m.translator(lang)
	from := time.Now().UTC().Add(-cr.span)
	series := map[string]*chartSeries{}
	get := func(src string) *chartSeries {
		s := series[src]
		if s == nil {
			s = &chartSeries{Source: src}
			series[src] = s
		}
		return s
	}
	labels := map[string]string{}
	for _, s := range m.sources(ctx, c, tr("hc.sources.this_node")) {
		labels[s.Source] = s.Label
	}
	// Quelle der Punkte: eigene Messungen (flags ohne 8), fremde Messstellen je nach Check
	type q struct {
		sql  string
		args []any
	}
	var qs []q
	// Quellen liefern einheitlich (src, time, status, latency_ms). Fremde Messstellen aus beiden Ablagen:
	// hc_measurements (flags 8, solange diese Node nicht mitmisst) und hc_source_points (seit sie mitmisst).
	selfSrc := `SELECT 'self' AS src, time, status, latency_ms FROM hc_measurements WHERE token = ? AND time >= ? AND (flags & 8) = 0`
	remoteSrc := `SELECT details AS src, time, status, latency_ms FROM hc_measurements WHERE token = ? AND time >= ? AND (flags & 8) != 0
		UNION ALL SELECT source AS src, time, status, latency_ms FROM hc_source_points WHERE token = ? AND time >= ?`
	selfArgs, remoteArgs := []any{c.Token, ft(from)}, []any{c.Token, ft(from), c.Token, ft(from)}
	switch cr.bucket {
	case "raw":
		raw := func(src string, limit int) string {
			return `SELECT src, time, status, latency_ms FROM (` + src + `) ORDER BY time LIMIT ` + strconv.Itoa(limit)
		}
		limit := 20000
		if cr.span > 24*time.Hour {
			limit = 200000 // feine Aufloesung ueber Tage: jede Messung
		}
		qs = append(qs, q{raw(selfSrc, limit), selfArgs}, q{raw(remoteSrc, 2*limit), remoteArgs})
	default:
		n := 13 // Stunde
		if cr.bucket == "day" {
			n = 10
		}
		agg := func(src string) string {
			return `SELECT src, substr(time, 1, ` + strconv.Itoa(n) + `), count(*), sum(status), avg(CASE WHEN status = 1 THEN latency_ms END) FROM (` + src + `) GROUP BY 1, 2 ORDER BY 2`
		}
		qs = append(qs, q{agg(selfSrc), selfArgs}, q{agg(remoteSrc), remoteArgs})
		if cr.bucket == "day" && c.MeasuredHere() {
			// eigene Tageswerte fuer die Zeit vor den aufbewahrten Einzelmessungen
			qs = append(qs, q{`SELECT 'self', day, count, up_count, avg_ms FROM hc_daily WHERE token = ? AND day >= ? AND day < ? ORDER BY day`,
				[]any{c.Token, from.Format("2006-01-02"), rawCut.Format("2006-01-02")}})
		}
		// fremde Messstellen: Stundenwerte (vom hub nachgeladen bzw. verdichtet) fuer Zeiten ohne Einzelpunkte
		qs = append(qs, q{`SELECT source, substr(hour, 1, ` + strconv.Itoa(n) + `), sum(count), sum(up_count), sum(avg_ms * up_count) / NULLIF(sum(CASE WHEN avg_ms IS NOT NULL THEN up_count END), 0)
			FROM hc_source_hourly WHERE token = ? AND hour >= ? GROUP BY 1, 2 ORDER BY 2`, []any{c.Token, ft(from)}})
		if cr.bucket == "hour" && c.MeasuredHere() && from.Before(rawCut) {
			// eigene Stundenwerte fuer die Zeit vor den aufbewahrten Einzelmessungen
			qs = append(qs, q{`SELECT 'self', substr(hour, 1, 13), count, up_count, avg_ms FROM hc_hourly WHERE token = ? AND hour >= ? AND hour < ? ORDER BY hour`,
				[]any{c.Token, ft(from), ft(rawCut)}})
		}
	}
	type acc struct {
		count, up int
		latW      float64
		latN      int
	}
	sums := map[string]map[time.Time]*acc{}
	for _, x := range qs {
		rows, err := m.st.r.QueryContext(ctx, x.sql, x.args...)
		if err != nil {
			m.log.Warn("chart query failed", "err", err)
			continue
		}
		for rows.Next() {
			var src, t string
			if cr.bucket == "raw" {
				var status int
				var lat float64
				if rows.Scan(&src, &t, &status, &lat) != nil {
					continue
				}
				p := chartPoint{T: pt(t)}
				if status == 1 {
					p.MS = f64(round2(lat))
				}
				get(src).Points = append(get(src).Points, p)
				continue
			}
			var count, up int
			var avg *float64
			if rows.Scan(&src, &t, &count, &up, &avg) != nil {
				continue
			}
			var tm time.Time
			if len(t) == 13 {
				tm, _ = time.Parse("2006-01-02T15", t)
			} else {
				tm, _ = time.Parse("2006-01-02", t[:10])
			}
			if sums[src] == nil {
				sums[src] = map[time.Time]*acc{}
			}
			a := sums[src][tm]
			if a == nil {
				a = &acc{}
				sums[src][tm] = a
			}
			a.count += count
			a.up += up
			if avg != nil && up > 0 {
				a.latW += *avg * float64(up)
				a.latN += up
			}
		}
		rows.Close()
	}
	for src, byT := range sums {
		for tm, a := range byT {
			p := chartPoint{T: tm}
			if a.latN > 0 {
				p.MS = f64(round2(a.latW / float64(a.latN)))
			}
			if a.count > 0 {
				p.Up = f64(round2(100 * float64(a.up) / float64(a.count)))
			}
			get(src).Points = append(get(src).Points, p)
		}
	}
	out := make([]chartSeries, 0, len(series))
	for src, s := range series {
		if len(s.Points) == 0 {
			continue
		}
		sort.Slice(s.Points, func(i, j int) bool { return s.Points[i].T.Before(s.Points[j].T) })
		switch {
		case src == "self":
			s.Label = tr("hc.sources.this_node")
		case labels[src] != "":
			s.Label = labels[src]
		default:
			s.Label = sourceLabel(src, "")
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Source == "self") != (out[j].Source == "self") {
			return out[i].Source == "self"
		}
		return out[i].Source < out[j].Source
	})
	writeJSON(w, http.StatusOK, map[string]any{"range": rng, "bucket": cr.bucket, "series": out})
}
