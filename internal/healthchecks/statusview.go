package healthchecks

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/scheduler"
)

// Statusseiten: Berechnung der oeffentlichen Sicht. Gerechnet wird nur auf Abruf, das Ergebnis bleibt 30 s je
// (Seite, Sprache) im Speicher; Aenderungen an Seiten und Ankuendigungen leeren den Speicher (Store.OnStatusChange).
// Ohne Abruf kostet eine Statusseite nichts (kein Hintergrundjob). Die oeffentlichen Routen stehen in statuspublic.go.
//
// Zustand eines Eintrags (aktuell, aus dem Laufzeitzustand wie in der Liste):
//   pausiert -> paused; Wartung laeuft -> maintenance; noch nie gemessen (pending) oder seit 3 Intervallen nicht
//   gemessen (stale) -> unknown; up -> up; down und dependent (uebergeordneter Check gestoert, der Dienst ist fuer
//   Besucher trotzdem nicht erreichbar) -> down; flapping, stabilizing (antwortet wieder, Stoerung noch offen) und
//   degraded (ein Teil der Messstellen gestoert) -> degraded.
//
// Tagesbalken (Kalendertage in der Zeitzone der Node): heute und gestern aus den Einzelmessungen (genaue Grenzen),
// aeltere Tage aus hc_daily. hc_daily rechnet in UTC-Tagen; der Versatz von 1-2 Stunden an den Tagesgrenzen wird
// bewusst hingenommen (sonst muessten bis zu 30 Tage Einzelmessungen je Abruf gelesen werden). Messungen in Wartung
// oder abhaengig gestoert zaehlen nicht (wie hc_daily: flags = 0).
//   none:        keine Messung und keine Stoerung an dem Tag
//   down:        Verfuegbarkeit unter 95 % oder Stoerungen von zusammen mindestens 15 Minuten
//   maintenance: sonst, wenn Wartungsfenster mindestens die Haelfte des Tages abdecken
//   partial:     sonst, wenn eine Messung fehlschlug oder eine kurze Stoerung (< 15 min) lief
//   up:          alle Messungen in Ordnung
//
// Gesamtzustand (Gruppe und Seite) aus dem aktuellen Zustand der Eintraege, nicht aus den Balken: down, wenn einer
// down ist; sonst degraded, wenn einer degraded ist; sonst maintenance, wenn einer in Wartung ist; sonst up, wenn
// einer up ist; sonst (nur pausiert/unbekannt oder leer) unknown.

const (
	statusCacheTTL     = 30 * time.Second
	statusDownUptime   = 95.0 // unter diesem Wert ist ein Tag (bzw. eine Stunde) rot
	statusDownMinutes  = 15   // ab so vielen Minuten Stoerung ist ein Tag (bzw. eine Stunde) rot
	statusHistory      = 30 * 24 * time.Hour
	statusMaintAhead   = 7 * 24 * time.Hour
	statusMaxIncidents = 100 // Stoerungen in der Sicht (neueste zuerst)
)

// statusNow ist die Uhr der Berechnung (Tests).
var statusNow = time.Now

// StatusPageRef ist eine Seite zur Auswahl (PROXY64-Hostart "Statusseite").
type StatusPageRef struct {
	ID      int64
	Slug    string
	Title   string
	Enabled bool
}

// statusState haelt den Zwischenspeicher der Sichten und die Drosselung der Passwort-Fehlversuche.
type statusState struct {
	mu    sync.Mutex
	views map[statusKey]*statusEntry
	fails map[string]*statusFail // IP -> Fehlversuche
}

type statusKey struct {
	id   int64
	lang string
}

type statusEntry struct {
	ready bool
	at    time.Time
	v     *StatusView
	err   error
	done  chan struct{}
	// status.json fertig kodiert und gzip-komprimiert (einmal je Eintrag, beim ersten Abruf)
	once     sync.Once
	json, gz []byte
}

// statusJSONBytes liefert status.json der Seite (roh und gzip) aus dem Zwischenspeicher.
func (m *Module) statusJSONBytes(ctx context.Context, p *StatusPage, lang string) ([]byte, []byte, error) {
	e, err := m.statusEntryFor(ctx, p, lang)
	if err != nil {
		return nil, nil, err
	}
	e.once.Do(func() {
		e.json, _ = json.Marshal(e.v)
		e.json = append(e.json, '\n')
		e.gz = statusGzip(e.json)
	})
	return e.json, e.gz, nil
}

// statusStates ordnet jedem Modul seinen Zustand zu (ohne Feld im Modul; Module gibt es je Prozess eines).
var statusStates sync.Map // *Module -> *statusState

func (m *Module) statusState() *statusState {
	if s, ok := statusStates.Load(m); ok {
		return s.(*statusState)
	}
	s, _ := statusStates.LoadOrStore(m, &statusState{views: map[statusKey]*statusEntry{}, fails: map[string]*statusFail{}})
	return s.(*statusState)
}

// statusFlush verwirft alle zwischengespeicherten Sichten (Store.OnStatusChange).
func (m *Module) statusFlush() {
	s := m.statusState()
	s.mu.Lock()
	s.views = map[statusKey]*statusEntry{}
	s.mu.Unlock()
}

// statusView berechnet die oeffentliche Sicht einer Seite (zwischengespeichert, lang "de"/"en").
// Gleichzeitige Abrufe derselben Seite warten auf eine einzige Berechnung.
func (m *Module) statusView(ctx context.Context, p *StatusPage, lang string) (*StatusView, error) {
	e, err := m.statusEntryFor(ctx, p, lang)
	if err != nil {
		return nil, err
	}
	return e.v, nil
}

// statusEntryFor liefert den (fertigen) Eintrag im Zwischenspeicher, rechnet bei Bedarf.
func (m *Module) statusEntryFor(ctx context.Context, p *StatusPage, lang string) (*statusEntry, error) {
	s := m.statusState()
	key := statusKey{p.ID, lang}
	s.mu.Lock()
	if e := s.views[key]; e != nil && (!e.ready || statusNow().Sub(e.at) < statusCacheTTL) {
		s.mu.Unlock()
		select {
		case <-e.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if e.err == nil {
			return e, nil
		}
		return nil, e.err
	}
	e := &statusEntry{done: make(chan struct{})}
	s.views[key] = e
	s.mu.Unlock()
	v, err := m.buildStatusView(context.WithoutCancel(ctx), p, lang)
	s.mu.Lock()
	e.v, e.err, e.at, e.ready = v, err, statusNow(), true
	if err != nil && s.views[key] == e {
		delete(s.views, key) // Fehler nicht zwischenspeichern
	}
	s.mu.Unlock()
	close(e.done)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// statusLocation ist die Zeitzone der Node (Einstellung des Kerns), sonst die des Containers.
func (m *Module) statusLocation(ctx context.Context) *time.Location {
	if m.core != nil {
		if tz := m.core.SettingOr(ctx, "node.timezone", ""); tz != "" {
			if loc, err := time.LoadLocation(tz); err == nil {
				return loc
			}
		}
	}
	return time.Local
}

// statusAgg zaehlt Messungen.
type statusAgg struct{ count, up int }

func (a *statusAgg) add(b statusAgg) { a.count += b.count; a.up += b.up }

// statusPct: Verfuegbarkeit in Prozent, abgerundet auf zwei Stellen (99,996 % ist nicht 100 %); -1 ohne Daten.
func statusPct(a statusAgg) float64 {
	if a.count == 0 {
		return -1
	}
	return math.Floor(10000*float64(a.up)/float64(a.count)) / 100
}

// statusBucket bewertet einen Balken (Tag oder Stunde), Regeln siehe oben.
func statusBucket(label string, a statusAgg, downMins int, maint bool) StatusViewDay {
	d := StatusViewDay{Day: label, Uptime: statusPct(a), DownMins: downMins}
	switch {
	case a.count == 0 && downMins == 0 && maint:
		d.State = "maintenance"
	case a.count == 0 && downMins == 0:
		d.State = "none"
	case (a.count > 0 && d.Uptime < statusDownUptime) || downMins >= statusDownMinutes:
		d.State = "down"
	case maint:
		d.State = "maintenance"
	case a.up < a.count || downMins > 0:
		d.State = "partial"
	default:
		d.State = "up"
	}
	return d
}

// statusOverall fasst Zustaende zusammen (Regeln siehe oben).
func statusOverall(states []string) string {
	has := map[string]bool{}
	for _, s := range states {
		has[s] = true
	}
	switch {
	case has["down"]:
		return "down"
	case has["degraded"] || has["partial"]:
		return "degraded"
	case has["maintenance"]:
		return "maintenance"
	case has["up"]:
		return "up"
	}
	return "unknown"
}

// statusItemState ist der aktuelle Zustand eines Eintrags (Regeln siehe oben).
func (m *Module) statusItemState(c *Check, inMaint bool) (string, time.Time) {
	rt := m.liveRuntime(c)
	switch {
	case c.Paused || rt.State == scheduler.StatePaused:
		return "paused", rt.Since
	case inMaint:
		return "maintenance", time.Time{}
	case rt.State == "" || rt.State == scheduler.StatePending || stale(c, rt.LastCheck, string(rt.State)):
		return "unknown", time.Time{}
	}
	switch rt.State {
	case scheduler.StateUp:
		return "up", rt.Since
	case scheduler.StateDown, scheduler.StateDependent:
		return "down", rt.Since
	case scheduler.StateFlapping, scheduler.StateStabilizing, scheduler.StateDegraded:
		return "degraded", rt.Since
	}
	return "unknown", time.Time{}
}

// statusReason uebersetzt einen Grund in einen allgemeinen Text (nie die Rohmeldung).
func statusReason(tr func(string, ...any) string, reason string) string {
	if reason == "" || reason == "ok" {
		return ""
	}
	key := "hc.reasons." + reason
	if s := tr(key); s != key {
		return s
	}
	return tr("hc.status.pub.reason_other")
}

// statusSpan ist ein Zeitraum (Stoerung oder Wartung).
type statusSpan struct{ from, to time.Time }

// statusOverlap verteilt Zeitraeume auf die Balken bounds[i]..bounds[i+1] (Dauer je Balken).
func statusOverlap(bounds []time.Time, spans []statusSpan) []time.Duration {
	out := make([]time.Duration, len(bounds)-1)
	for _, sp := range spans {
		for i := range out {
			a, b := bounds[i], bounds[i+1]
			if sp.from.After(a) {
				a = sp.from
			}
			if sp.to.Before(b) {
				b = sp.to
			}
			if b.After(a) {
				out[i] += b.Sub(a)
			}
		}
	}
	return out
}

// statusMinutes rundet Dauern auf ganze Minuten auf (auch eine kurze Stoerung zaehlt).
func statusMinutes(ds []time.Duration) []int {
	out := make([]int, len(ds))
	for i, d := range ds {
		out[i] = int(math.Ceil(d.Minutes()))
	}
	return out
}

// statusMaintOccurrences liefert die Termine eines Wartungsfensters, die [from, to) beruehren (wie Covers).
func statusMaintOccurrences(mw Maintenance, from, to time.Time) []statusSpan {
	if !mw.Active || !mw.EndAt.After(mw.StartAt) {
		return nil
	}
	dur := mw.EndAt.Sub(mw.StartAt)
	var out []statusSpan
	add := func(s time.Time) bool {
		if !s.Before(to) || (!mw.RepeatUntil.IsZero() && s.After(mw.RepeatUntil)) {
			return false
		}
		e := s.Add(dur)
		if !mw.RepeatUntil.IsZero() && e.After(mw.RepeatUntil) {
			e = mw.RepeatUntil
		}
		if e.After(from) {
			out = append(out, statusSpan{s, e})
		}
		return len(out) < 500
	}
	switch mw.Repeat {
	case "daily", "weekly":
		step := 24 * time.Hour
		if mw.Repeat == "weekly" {
			step = 7 * 24 * time.Hour
		}
		k := 0
		if from.After(mw.StartAt) {
			k = max(int(from.Sub(mw.StartAt)/step)-1, 0)
		}
		for ; add(mw.StartAt.Add(time.Duration(k) * step)); k++ {
		}
	case "monthly":
		for k := 0; k < 1200 && add(mw.StartAt.AddDate(0, k, 0)); k++ {
		}
	default:
		add(mw.StartAt)
	}
	return out
}

// statusMaintFor: betrifft das Fenster den Check?
func statusMaintFor(mw Maintenance, token string) bool {
	return len(mw.Tokens) == 0 || contains(mw.Tokens, token)
}

// statusTokenChunks ruft fn fuer Teilmengen der Tokens auf (Platzhalter "?,?,..."): wenige Abfragen auch bei
// 1000 Eintraegen, innerhalb der Grenzen von SQLite und ueber den Index (token, ...).
func statusTokenChunks(tokens []string, fn func(ph string, args []any) error) error {
	const n = 400
	for i := 0; i < len(tokens); i += n {
		part := tokens[i:min(i+n, len(tokens))]
		args := make([]any, len(part))
		for j, t := range part {
			args[j] = t
		}
		if err := fn(strings.TrimSuffix(strings.Repeat("?,", len(part)), ","), args); err != nil {
			return err
		}
	}
	return nil
}

// statusIncidentRow ist eine Stoerung ohne Rohmeldung.
type statusIncidentRow struct {
	start, end time.Time // end leer = laeuft
	reason     string
}

// statusIncidents laedt die Stoerungen der Tokens, die nach from noch liefen (eine Abfrage je 400 Tokens).
func (m *Module) statusIncidents(ctx context.Context, tokens []string, from time.Time) (map[string][]statusIncidentRow, error) {
	out := map[string][]statusIncidentRow{}
	err := statusTokenChunks(tokens, func(ph string, args []any) error {
		rows, err := m.st.r.QueryContext(ctx, `SELECT token, started_at, ended_at, reason FROM hc_incidents
			WHERE token IN (`+ph+`) AND (ended_at = '' OR ended_at >= ?) ORDER BY started_at DESC`, append(args, ft(from))...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var tok, st, en, reason string
			if err := rows.Scan(&tok, &st, &en, &reason); err != nil {
				return err
			}
			out[tok] = append(out[tok], statusIncidentRow{start: pt(st), end: pt(en), reason: reason})
		}
		return rows.Err()
	})
	return out, err
}

// statusDownSpans: Stoerungen als Zeitraeume (laufende bis now).
func statusDownSpans(list []statusIncidentRow, now time.Time) []statusSpan {
	out := make([]statusSpan, 0, len(list))
	for _, i := range list {
		end := i.end
		if end.IsZero() || end.After(now) {
			end = now
		}
		out = append(out, statusSpan{i.start, end})
	}
	return out
}

// statusMaintCover: je Balken, ob die Fenster (die den Token betreffen) ihn mindestens zur Haelfte abdecken.
func statusMaintCover(bounds []time.Time, wins []Maintenance, occ [][]statusSpan, token string) []bool {
	var spans []statusSpan
	for i, mw := range wins {
		if statusMaintFor(mw, token) {
			spans = append(spans, occ[i]...)
		}
	}
	out := make([]bool, len(bounds)-1)
	if len(spans) == 0 {
		return out
	}
	cov := statusOverlap(bounds, spans)
	for i := range out {
		out[i] = cov[i] > 0 && 2*cov[i] >= bounds[i+1].Sub(bounds[i])
	}
	return out
}

// buildStatusView rechnet die Sicht ohne Zwischenspeicher (auch fuer die Vorschau ungespeicherter Seiten).
// Abfragen gesamt: Checks, Einstellung Zeitzone, Wartungen, Ankuendigungen und je 400 Tokens hc_daily, Messungen
// (heute/gestern) und Stoerungen.
func (m *Module) buildStatusView(ctx context.Context, p *StatusPage, lang string) (*StatusView, error) {
	now := statusNow()
	loc := m.statusLocation(ctx)
	tr := m.translator(lang)
	days := p.Days
	if days != 30 && days != 60 {
		days = 90
	}
	v := &StatusView{Slug: p.Slug, Title: p.Title, Description: p.Description, Footer: p.Footer, Layout: p.Layout, Theme: p.Theme,
		Accent: p.Accent, Days: days, ShowUptime: p.ShowUptime, RefreshSec: p.RefreshSec, PoweredBy: p.PoweredBy, Generated: now.UTC(),
		Groups: []StatusViewGroup{}, Notices: []StatusNotice{}, Maintenance: []StatusViewMaint{}, Incidents: []StatusViewIncid{}}

	all, err := m.st.Checks(ctx)
	if err != nil {
		return nil, err
	}
	byTok := make(map[string]*Check, len(all))
	for _, c := range all {
		byTok[c.Token] = c
	}
	var tokens []string
	seen := map[string]bool{}
	for _, g := range p.Groups {
		for _, it := range g.Items {
			if byTok[it.Token] != nil && !seen[it.Token] {
				seen[it.Token] = true
				tokens = append(tokens, it.Token)
			}
		}
	}

	// Grenzen der Tagesbalken: Mitternacht in der Zeitzone der Node, der letzte endet jetzt
	y, mo, d := now.In(loc).Date()
	bounds := make([]time.Time, days+1)
	labels := make([]string, days)
	for i := 0; i < days; i++ {
		bounds[i] = time.Date(y, mo, d-(days-1-i), 0, 0, 0, 0, loc)
		labels[i] = bounds[i].Format("2006-01-02")
	}
	bounds[days] = now
	yesterday, today := bounds[days-2], bounds[days-1]

	// Tageswerte (aeltere Tage)
	daily := map[string]map[string]statusAgg{}
	err = statusTokenChunks(tokens, func(ph string, args []any) error {
		rows, err := m.st.r.QueryContext(ctx, `SELECT token, day, count, up_count FROM hc_daily WHERE token IN (`+ph+`) AND day >= ? AND day < ?`,
			append(args, labels[0], labels[days-2])...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var tok, day string
			var a statusAgg
			if err := rows.Scan(&tok, &day, &a.count, &a.up); err != nil {
				return err
			}
			if daily[tok] == nil {
				daily[tok] = map[string]statusAgg{}
			}
			daily[tok][day] = a
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	// gestern und heute aus den Einzelmessungen
	raw := map[string]*[2]statusAgg{}
	err = statusTokenChunks(tokens, func(ph string, args []any) error {
		rows, err := m.st.r.QueryContext(ctx, `SELECT token, time >= ?, count(*), coalesce(sum(status), 0) FROM hc_measurements
			WHERE token IN (`+ph+`) AND time >= ? AND time <= ? AND flags = 0 GROUP BY 1, 2`,
			append(append([]any{ft(today)}, args...), ft(yesterday), ft(now))...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var tok string
			var isToday int
			var a statusAgg
			if err := rows.Scan(&tok, &isToday, &a.count, &a.up); err != nil {
				return err
			}
			if raw[tok] == nil {
				raw[tok] = &[2]statusAgg{}
			}
			raw[tok][min(max(isToday, 0), 1)].add(a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	incFrom := bounds[0]
	if h := now.Add(-statusHistory); h.Before(incFrom) {
		incFrom = h
	}
	incs, err := m.statusIncidents(ctx, tokens, incFrom)
	if err != nil {
		return nil, err
	}
	wins, err := m.st.MaintenanceList(ctx)
	if err != nil {
		return nil, err
	}
	occ := make([][]statusSpan, len(wins))
	for i, mw := range wins {
		occ[i] = statusMaintOccurrences(mw, bounds[0], now)
	}

	// je Token einmal rechnen (ein Check kann mehrfach auf der Seite stehen)
	type tokView struct {
		state  string
		uptime float64
		bars   []StatusViewDay
	}
	tv := make(map[string]*tokView, len(tokens))
	for _, tok := range tokens {
		c := byTok[tok]
		inMaint := false
		for _, mw := range wins {
			if mw.Covers(tok, now) {
				inMaint = true
				break
			}
		}
		x := &tokView{bars: make([]StatusViewDay, days)}
		x.state, _ = m.statusItemState(c, inMaint)
		downs := statusMinutes(statusOverlap(bounds, statusDownSpans(incs[tok], now)))
		maint := statusMaintCover(bounds, wins, occ, tok)
		var total statusAgg
		for i := 0; i < days; i++ {
			var a statusAgg
			switch {
			case i == days-1 && raw[tok] != nil:
				a = raw[tok][1]
			case i == days-2 && raw[tok] != nil:
				a = raw[tok][0]
			case i < days-2:
				a = daily[tok][labels[i]]
			}
			total.add(a)
			x.bars[i] = statusBucket(labels[i], a, downs[i], maint[i])
		}
		x.uptime = statusPct(total)
		tv[tok] = x
	}

	// Gruppen und Eintraege in der Reihenfolge der Seite; Gruppen ohne (vorhandene) Checks fallen weg
	var pageStates []string
	labelOf := map[string][]string{} // Token -> Anzeigenamen (fuer Wartungen)
	type incItem struct {
		label string
		tok   string
	}
	var incItems []incItem
	for _, g := range p.Groups {
		vg := StatusViewGroup{Name: g.Name, Items: []StatusViewItem{}}
		var states []string
		for _, it := range g.Items {
			c := byTok[it.Token]
			if c == nil {
				continue
			}
			label := it.Label
			if label == "" {
				label = c.Name
			}
			x := tv[it.Token]
			vg.Items = append(vg.Items, StatusViewItem{ID: it.ID, Label: label, State: x.state, Uptime: x.uptime, Bars: x.bars})
			states = append(states, x.state)
			labelOf[it.Token] = append(labelOf[it.Token], label)
			incItems = append(incItems, incItem{label, it.Token})
		}
		if len(vg.Items) == 0 {
			continue
		}
		vg.Overall = statusOverall(states)
		pageStates = append(pageStates, states...)
		v.Groups = append(v.Groups, vg)
	}
	v.Overall = statusOverall(pageStates)

	// Wartungen: laufende und die der naechsten 7 Tage (je Fenster der naechste Termin)
	for _, mw := range wins {
		next := statusMaintOccurrences(mw, now, now.Add(statusMaintAhead))
		if len(next) == 0 {
			continue
		}
		var items []string
		for _, tok := range tokens {
			if statusMaintFor(mw, tok) {
				items = append(items, labelOf[tok]...)
			}
		}
		if len(items) == 0 {
			continue
		}
		o := next[0]
		v.Maintenance = append(v.Maintenance, StatusViewMaint{Title: mw.Name, Start: o.from.UTC(), End: o.to.UTC(), Active: !o.from.After(now), Items: items})
	}
	sort.SliceStable(v.Maintenance, func(i, j int) bool { return v.Maintenance[i].Start.Before(v.Maintenance[j].Start) })

	// Stoerungen der letzten 30 Tage und Ankuendigungen
	since := now
	if p.ShowHistory {
		since = now.Add(-statusHistory)
		for _, ii := range incItems {
			for _, i := range incs[ii.tok] {
				if !i.end.IsZero() && i.end.Before(since) {
					continue
				}
				v.Incidents = append(v.Incidents, StatusViewIncid{Item: ii.label, Start: i.start, End: i.end, Reason: statusReason(tr, i.reason)})
			}
		}
		sort.SliceStable(v.Incidents, func(i, j int) bool { return v.Incidents[i].Start.After(v.Incidents[j].Start) })
		if len(v.Incidents) > statusMaxIncidents {
			v.Incidents = v.Incidents[:statusMaxIncidents]
		}
	}
	if p.ID != 0 {
		notices, err := m.st.StatusNotices(ctx, p.ID, since)
		if err != nil {
			return nil, err
		}
		for _, n := range notices {
			if !p.ShowHistory && !n.ResolvedAt.IsZero() {
				continue
			}
			v.Notices = append(v.Notices, n)
		}
	}
	return v, nil
}

// statusItemDetail liefert die Details eines Eintrags der Seite (nur Eintraege dieser Seite, sonst
// ErrStatusPageNotFound). Nicht zwischengespeichert: wenige Abfragen fuer einen Check.
func (m *Module) statusItemDetail(ctx context.Context, p *StatusPage, itemID int64, lang string) (*StatusItemDetail, error) {
	var it *StatusItem
	for gi := range p.Groups {
		for ii := range p.Groups[gi].Items {
			if p.Groups[gi].Items[ii].ID == itemID {
				it = &p.Groups[gi].Items[ii]
			}
		}
	}
	if it == nil || itemID == 0 {
		return nil, ErrStatusPageNotFound
	}
	c, err := m.st.Check(ctx, it.Token)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, ErrStatusPageNotFound
	}
	now := statusNow()
	loc := m.statusLocation(ctx)
	tr := m.translator(lang)
	label := it.Label
	if label == "" {
		label = c.Name
	}
	wins, err := m.st.MaintenanceList(ctx)
	if err != nil {
		return nil, err
	}
	inMaint := false
	for _, mw := range wins {
		if mw.Covers(c.Token, now) {
			inMaint = true
			break
		}
	}
	d := &StatusItemDetail{ID: it.ID, Label: label, Incidents: []StatusViewIncid{}}
	d.State, d.Since = m.statusItemState(c, inMaint)
	if !d.Since.IsZero() {
		d.Since = d.Since.UTC()
	}

	// Verfuegbarkeit 24 h / 7 / 30 Tage und Latenz 24 h: Einzelmessungen, dazu Stundenwerte (nur vorhanden, wenn die
	// Einzelmessungen kuerzer aufbewahrt werden; beide ueberschneiden sich nicht)
	f24, f7, f30 := now.Add(-24*time.Hour), now.Add(-7*24*time.Hour), now.Add(-30*24*time.Hour)
	var a24, a7, a30 statusAgg
	var latSum float64
	var latN int
	var hourAgg = map[string]statusAgg{} // UTC-Stunde "2006-01-02T15" -> Messungen
	rows, err := m.st.r.QueryContext(ctx, `SELECT substr(time, 1, 13), count(*), coalesce(sum(status), 0),
		coalesce(sum(CASE WHEN status = 1 THEN latency_ms ELSE 0 END), 0), coalesce(sum(CASE WHEN status = 1 AND latency_ms > 0 THEN 1 ELSE 0 END), 0)
		FROM hc_measurements WHERE token = ? AND time >= ? AND time <= ? AND flags = 0 GROUP BY 1`, c.Token, ft(f30.Truncate(time.Hour)), ft(now))
	if err != nil {
		return nil, err
	}
	addHour := func(hour string, a statusAgg, lat float64, latCount int) {
		t, err := time.Parse("2006-01-02T15", hour)
		if err != nil {
			return
		}
		// angebrochene Stunden am Anfang zaehlen zum laengeren Zeitraum (Stundenraster genuegt fuer die Anzeige)
		if !t.Before(f30.Truncate(time.Hour)) {
			a30.add(a)
		}
		if !t.Before(f7.Truncate(time.Hour)) {
			a7.add(a)
		}
		if !t.Before(f24.Truncate(time.Hour)) {
			a24.add(a)
			latSum += lat
			latN += latCount
			h := hourAgg[hour]
			h.add(a)
			hourAgg[hour] = h
		}
	}
	for rows.Next() {
		var hour string
		var a statusAgg
		var lat float64
		var n int
		if err := rows.Scan(&hour, &a.count, &a.up, &lat, &n); err != nil {
			rows.Close()
			return nil, err
		}
		addHour(hour, a, lat, n)
	}
	rows.Close()
	rows, err = m.st.r.QueryContext(ctx, `SELECT substr(hour, 1, 13), count, up_count, avg_ms FROM hc_hourly WHERE token = ? AND hour >= ?`,
		c.Token, ft(f30.Truncate(time.Hour)))
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var hour string
		var a statusAgg
		var avg float64
		if err := rows.Scan(&hour, &a.count, &a.up, &avg); err != nil {
			rows.Close()
			return nil, err
		}
		n := 0
		if avg > 0 {
			n = a.up
		}
		addHour(hour, a, avg*float64(n), n)
	}
	rows.Close()
	d.Uptime24h, d.Uptime7d, d.Uptime30d = statusPct(a24), statusPct(a7), statusPct(a30)
	d.Latency = -1
	if latN > 0 {
		d.Latency = math.Round(100*latSum/float64(latN)) / 100
	}

	// 24 Stundenbalken (aelteste zuerst, die letzte Stunde endet jetzt)
	bounds := make([]time.Time, 25)
	cur := now.Truncate(time.Hour)
	for i := 0; i < 24; i++ {
		bounds[i] = cur.Add(-time.Duration(23-i) * time.Hour)
	}
	bounds[24] = now
	incs, err := m.statusIncidents(ctx, []string{c.Token}, bounds[0])
	if err != nil {
		return nil, err
	}
	downs := statusMinutes(statusOverlap(bounds, statusDownSpans(incs[c.Token], now)))
	occ := make([][]statusSpan, len(wins))
	for i, mw := range wins {
		occ[i] = statusMaintOccurrences(mw, bounds[0], now)
	}
	maint := statusMaintCover(bounds, wins, occ, c.Token)
	d.Hours = make([]StatusViewDay, 24)
	for i := 0; i < 24; i++ {
		d.Hours[i] = statusBucket(bounds[i].In(loc).Format("2006-01-02T15"), hourAgg[bounds[i].UTC().Format("2006-01-02T15")], downs[i], maint[i])
	}

	// letzte 5 Stoerungen (ohne Rohmeldung)
	list, err := m.st.Incidents(ctx, c.Token, 5)
	if err != nil {
		return nil, err
	}
	for _, i := range list {
		vi := StatusViewIncid{Item: label, Start: i.StartedAt, Reason: statusReason(tr, i.Reason)}
		if !i.Open {
			vi.End = i.EndedAt
		}
		d.Incidents = append(d.Incidents, vi)
	}
	return d, nil
}

// StatusPageRefs liefert alle Seiten zur Auswahl (PROXY64).
func (m *Module) StatusPageRefs(ctx context.Context) []StatusPageRef {
	list, err := m.st.StatusPages(ctx)
	if err != nil {
		return nil
	}
	out := make([]StatusPageRef, 0, len(list))
	for _, p := range list {
		out = append(out, StatusPageRef{ID: p.ID, Slug: p.Slug, Title: p.Title, Enabled: p.Enabled})
	}
	return out
}
