package monitor64

import (
	"context"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/monitor64/eval"
)

// Monitor64 auf den Statusseiten (Plan "Statusseiten (entschieden 2026-11-09)"): Healthchecks fragt ueber
// module.StatusFeed Zustand, Balken, Stoerungen und Wartungen der aufgenommenen Hosts bzw. Dienste ab. Nach aussen
// gehen nur Name und Zustand: keine Werte, Adressen, Texte oder Dienstnamen (ausser beim einzeln aufgenommenen Dienst).
//
// Zustand: Host pausiert -> paused; noch keine Runde -> unknown; Wartung -> maintenance; nicht erreichbar ->
// unreachable; sonst der schlimmste Dienst ohne "nur anzeigen" (Host, wie die Probleme) bzw. der Dienst selbst.
//
// Balken und Stoerungen aus der Problem-Historie (m64_problems, Zustandswechsel aus m64_events): kritisch und nicht
// erreichbar = gestoert, Warnung und unbekannt = eingeschraenkt. Host-Eintrag: alle Probleme des Hosts; Dienst-Eintrag:
// die des Dienstes und "nicht erreichbar" des Hosts. Wartungszeit zaehlt nicht (wie bei den Checks), ebenso die Zeit
// vor dem Anlegen des Hosts.

var _ module.StatusFeed = (*Module)(nil)

const (
	statusSrcHost      = "m64:host:"
	statusSrcSvc       = "m64:svc:"
	statusMaxProblems  = 50000 // Obergrenze je Abfrage (die Seite rechnet hoechstens alle 30 s)
	statusMaxIncidents = 100   // Stoerungen je Quelle (neueste zuerst)
	statusMaxDays      = 800   // Tage, die ein wiederkehrendes Wartungsfenster hoechstens durchlaeuft
)

// StatusSourceHost ist die Quelle eines Host-Eintrags auf einer Statusseite.
func StatusSourceHost(uid string) string { return statusSrcHost + uid }

// StatusSourceService ist die Quelle eines Dienst-Eintrags auf einer Statusseite.
func StatusSourceService(uid, key string) string { return statusSrcSvc + uid + "/" + key }

// parseStatusSource zerlegt eine Quelle (key "" = Host).
func parseStatusSource(s string) (host, key string, ok bool) {
	if uid, found := strings.CutPrefix(s, statusSrcHost); found {
		return uid, "", validStatusUID(uid)
	}
	if rest, found := strings.CutPrefix(s, statusSrcSvc); found {
		uid, key, cut := strings.Cut(rest, "/")
		return uid, key, cut && validStatusUID(uid) && key != "" && len(key) <= 200
	}
	return "", "", false
}

func validStatusUID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// statusSvcName ist der Name eines Dienstes in der Auswahl und auf der Seite.
func statusSvcName(r *ServiceRow) string { return firstNonEmpty(r.Name, r.Key) }

// statusAddable: Dienste, die man einzeln aufnehmen kann (uebernommen, keine Zugaenge).
func statusAddable(r *ServiceRow) bool { return r.Adopted == 1 && !strings.HasPrefix(r.Key, "access:") }

// StatusTargets liefert Hosts und ihre Dienste zur Auswahl im Editor der Statusseite.
func (m *Module) StatusTargets(ctx context.Context) ([]module.StatusTarget, error) {
	hosts, err := m.store.Hosts(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := m.store.Services(ctx, "")
	if err != nil {
		return nil, err
	}
	byHost := map[string][]*ServiceRow{}
	for _, r := range rows {
		if statusAddable(r) {
			byHost[r.HostUID] = append(byHost[r.HostUID], r)
		}
	}
	out := make([]module.StatusTarget, 0, len(hosts)+len(rows))
	for _, h := range hosts {
		out = append(out, module.StatusTarget{Source: StatusSourceHost(h.UID), Host: h.Name, Group: h.Group, Paused: h.Paused})
		list := byHost[h.UID]
		sort.SliceStable(list, func(i, j int) bool {
			return strings.ToLower(statusSvcName(list[i])) < strings.ToLower(statusSvcName(list[j]))
		})
		for _, r := range list {
			out = append(out, module.StatusTarget{Source: StatusSourceService(h.UID, r.Key), Host: h.Name, Name: statusSvcName(r), Group: h.Group, Paused: h.Paused})
		}
	}
	return out, nil
}

// tspan ist ein Zeitraum [from, to).
type tspan struct{ from, to time.Time }

// spanUnion sortiert und verschmilzt Zeitraeume (leere fallen weg).
func spanUnion(in []tspan) []tspan {
	list := make([]tspan, 0, len(in))
	for _, s := range in {
		if s.to.After(s.from) {
			list = append(list, s)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].from.Before(list[j].from) })
	var out []tspan
	for _, s := range list {
		if n := len(out); n > 0 && !s.from.After(out[n-1].to) {
			if s.to.After(out[n-1].to) {
				out[n-1].to = s.to
			}
			continue
		}
		out = append(out, s)
	}
	return out
}

// spanSubtract: a ohne b (beide verschmolzen und sortiert).
func spanSubtract(a, b []tspan) []tspan {
	var out []tspan
	for _, s := range a {
		cur := s
		for _, x := range b {
			if !x.to.After(cur.from) {
				continue
			}
			if !x.from.Before(cur.to) {
				break
			}
			if x.from.After(cur.from) {
				out = append(out, tspan{cur.from, x.from})
			}
			cur.from = x.to
			if !cur.to.After(cur.from) {
				break
			}
		}
		if cur.to.After(cur.from) {
			out = append(out, cur)
		}
	}
	return out
}

// spanOverlap: Dauer der Zeitraeume innerhalb [from, to).
func spanOverlap(spans []tspan, from, to time.Time) time.Duration {
	var d time.Duration
	for _, s := range spans {
		a, b := s.from, s.to
		if from.After(a) {
			a = from
		}
		if to.Before(b) {
			b = to
		}
		if b.After(a) {
			d += b.Sub(a)
		}
	}
	return d
}

// statusWindowSpans liefert die Zeitraeume eines Wartungsfensters innerhalb [from, to) (wiederkehrend nach der
// Wanduhr in loc, wie eval.Window.Active).
func statusWindowSpans(w eval.Window, from, to time.Time, loc *time.Location) []tspan {
	lo, hi := from, to
	if !w.Start.IsZero() && w.Start.After(lo) {
		lo = w.Start
	}
	if !w.End.IsZero() && w.End.Before(hi) {
		hi = w.End
	}
	if !hi.After(lo) {
		return nil
	}
	if w.Recurring == nil {
		return []tspan{{lo, hi}}
	}
	if loc == nil {
		loc = time.UTC
	}
	r := w.Recurring
	l := lo.In(loc)
	var out []tspan
	for i := 0; i < statusMaxDays; i++ {
		d := time.Date(l.Year(), l.Month(), l.Day()-1+i, 0, 0, 0, 0, loc) // ab dem Vortag (ueber Mitternacht)
		if !d.Before(hi) {
			break
		}
		if len(r.Days) > 0 && !slices.Contains(r.Days, d.Weekday()) {
			continue
		}
		s := time.Date(d.Year(), d.Month(), d.Day(), 0, int(r.From), 0, 0, loc)
		e := time.Date(d.Year(), d.Month(), d.Day(), 0, int(r.To), 0, 0, loc)
		if r.To <= r.From { // ueber Mitternacht (gleich = ganzer Tag)
			e = time.Date(d.Year(), d.Month(), d.Day()+1, 0, int(r.To), 0, 0, loc)
		}
		if s.Before(lo) {
			s = lo
		}
		if e.After(hi) {
			e = hi
		}
		if e.After(s) {
			out = append(out, tspan{s, e})
		}
	}
	return out
}

// statusMaintNext liefert den laufenden bzw. naechsten Termin eines Fensters, der vor until beginnt.
func statusMaintNext(w eval.Window, now, until time.Time, loc *time.Location) (module.StatusMaint, bool) {
	sm := module.StatusMaint{ID: w.ID, Title: w.Reason}
	if w.Recurring == nil {
		if (!w.End.IsZero() && !w.End.After(now)) || (!w.Start.IsZero() && !w.Start.Before(until)) {
			return sm, false
		}
		sm.Start, sm.End, sm.Active = w.Start, w.End, !w.Start.After(now)
		return sm, true
	}
	// Termine dauern hoechstens einen Tag: zwei Tage Rand genuegen, damit Beginn und Ende nicht abgeschnitten sind
	for _, s := range statusWindowSpans(w, now.Add(-48*time.Hour), until.Add(48*time.Hour), loc) {
		if !s.to.After(now) {
			continue
		}
		if !s.from.Before(until) {
			break
		}
		sm.Start, sm.End, sm.Active = s.from, s.to, !s.from.After(now)
		return sm, true
	}
	return sm, false
}

// statusProblem ist ein Problem mit seinen Abschnitten (Zustand je Zeitraum).
type statusProblem struct {
	key            string
	opened, closed time.Time
	segs           []statusSeg
}

type statusSeg struct {
	tspan
	state string // warn, crit, unknown, unreachable
}

// statusChunks ruft fn fuer Teilmengen der Werte auf (Platzhalter "?,?,...", innerhalb der Grenzen von SQLite).
func statusChunks(vals []string, fn func(ph string, args []any) error) error {
	const n = 400
	for i := 0; i < len(vals); i += n {
		part := vals[i:min(i+n, len(vals))]
		args := make([]any, len(part))
		for j, v := range part {
			args[j] = v
		}
		if err := fn(strings.TrimSuffix(strings.Repeat("?,", len(part)), ","), args); err != nil {
			return err
		}
	}
	return nil
}

// statusProblems laedt die Probleme der Hosts, die [from, now] beruehren, mit ihren Zustandswechseln.
func (m *Module) statusProblems(ctx context.Context, hosts []string, from, now time.Time) (map[string][]*statusProblem, error) {
	out := map[string][]*statusProblem{}
	byUID := map[string]*statusProblem{}
	var uids []string
	initial := map[string]string{} // Problem -> Zustand ohne Ereignisse (offen: aktuell, geschlossen: schlimmster)
	err := statusChunks(hosts, func(ph string, args []any) error {
		rows, err := m.st.Reader().QueryContext(ctx, `SELECT uid, host_uid, service_key, state, worst, opened_at, closed_at FROM m64_problems
			WHERE deleted = 0 AND host_uid IN (`+ph+`) AND opened_at <= ? AND (closed_at = '' OR closed_at >= ?) ORDER BY opened_at LIMIT ?`,
			append(args, ts(now), ts(from), statusMaxProblems)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var uid, host, key, state, worst, opened, closed string
			if err := rows.Scan(&uid, &host, &key, &state, &worst, &opened, &closed); err != nil {
				return err
			}
			p := &statusProblem{key: key, opened: parseTS(opened), closed: parseTS(closed)}
			if p.opened.IsZero() {
				continue
			}
			initial[uid] = state
			if !p.closed.IsZero() {
				initial[uid] = worst
			}
			out[host] = append(out[host], p)
			byUID[uid] = p
			uids = append(uids, uid)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	type ev struct {
		at   time.Time
		kind string
	}
	evs := map[string][]ev{}
	err = statusChunks(uids, func(ph string, args []any) error {
		rows, err := m.st.Reader().QueryContext(ctx, `SELECT problem_uid, ts, kind FROM m64_events
			WHERE problem_uid IN (`+ph+`) AND kind IN ('warn', 'crit', 'unknown', 'unreachable') ORDER BY ts, id`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var uid, at, kind string
			if err := rows.Scan(&uid, &at, &kind); err != nil {
				return err
			}
			evs[uid] = append(evs[uid], ev{parseTS(at), kind})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	for uid, p := range byUID {
		end := p.closed
		if end.IsZero() || end.After(now) {
			end = now
		}
		start, state := p.opened, initial[uid]
		for _, e := range evs[uid] {
			if !e.at.After(start) { // Ereignis beim Oeffnen: Zustand zu Beginn
				state = e.kind
				continue
			}
			if !e.at.Before(end) {
				break
			}
			if e.kind == state {
				continue
			}
			p.segs = append(p.segs, statusSeg{tspan{start, e.at}, state})
			start, state = e.at, e.kind
		}
		if end.After(start) {
			p.segs = append(p.segs, statusSeg{tspan{start, end}, state})
		}
	}
	return out, nil
}

// statusHostView liefert den aktuellen Stand eines Hosts (nil = noch keine Runde bzw. nicht eingeplant).
func (m *Module) statusHostView(uid string) *HostView {
	m.rtMu.Lock()
	rt := m.rts[uid]
	m.rtMu.Unlock()
	if rt == nil {
		return nil
	}
	return rt.getView()
}

// statusStateOf ist der Zustand eines Eintrags (Regeln siehe oben); key "" = Host.
func statusStateOf(h *Host, v *HostView, key string, inMaint bool) string {
	switch {
	case h.Paused:
		return module.StatusPaused
	case inMaint || (v != nil && v.View == eval.ViewMaintenance):
		return module.StatusMaintenance
	case v == nil:
		return module.StatusUnknown
	case v.View == eval.ViewUnreachable:
		return module.StatusUnreachable
	}
	if key != "" {
		for _, s := range v.Services {
			if s.Key == key {
				return s.State.String()
			}
		}
		return module.StatusUnknown
	}
	w := eval.OK
	for _, s := range v.Services {
		if !s.ShowOnly && s.State.Worse(w) {
			w = s.State
		}
	}
	return w.String()
}

// statusHostData ist, was alle Eintraege eines Hosts teilen (Wartungen).
type statusHostData struct {
	maint []tspan
	list  []module.StatusMaint
}

// StatusSources liefert den Stand der Quellen fuer eine Statusseite (Regeln siehe oben).
func (m *Module) StatusSources(ctx context.Context, q module.StatusQuery) (map[string]*module.StatusSource, error) {
	out := map[string]*module.StatusSource{}
	type want struct{ src, host, key string }
	var wants []want
	seen := map[string]bool{}
	hostSet := map[string]bool{}
	var hostUIDs []string
	for _, s := range q.Sources {
		h, k, ok := parseStatusSource(s)
		if !ok || seen[s] {
			continue
		}
		seen[s] = true
		wants = append(wants, want{s, h, k})
		if !hostSet[h] {
			hostSet[h] = true
			hostUIDs = append(hostUIDs, h)
		}
	}
	if len(wants) == 0 {
		return out, nil
	}
	now := q.Now
	if now.IsZero() {
		now = time.Now()
	}
	hostList, err := m.store.Hosts(ctx)
	if err != nil {
		return nil, err
	}
	hosts := map[string]*Host{}
	for _, h := range hostList {
		if hostSet[h.UID] {
			hosts[h.UID] = h
		}
	}
	rows, err := m.store.Services(ctx, "")
	if err != nil {
		return nil, err
	}
	svcs := map[string]*ServiceRow{}
	for _, r := range rows {
		if hostSet[r.HostUID] && statusAddable(r) {
			svcs[r.HostUID+"|"+r.Key] = r
		}
	}
	// Zeitraum der Historie: ab dem ersten Balken bzw. dem Beginn der Stoerungsliste
	var from time.Time
	if len(q.Bounds) >= 2 {
		from = q.Bounds[0]
	}
	if !q.History.IsZero() && (from.IsZero() || q.History.Before(from)) {
		from = q.History
	}
	probs := map[string][]*statusProblem{}
	if !from.IsZero() && from.Before(now) {
		if probs, err = m.statusProblems(ctx, hostUIDs, from, now); err != nil {
			return nil, err
		}
	}
	cfg := m.config()
	loc := m.location()
	hd := map[string]*statusHostData{}
	hostData := func(h *Host) *statusHostData {
		if d := hd[h.UID]; d != nil {
			return d
		}
		d := &statusHostData{}
		ref := hostRef(h)
		var spans []tspan
		for _, w := range cfg.maint {
			if !w.Applies(ref) {
				continue
			}
			if !from.IsZero() {
				spans = append(spans, statusWindowSpans(w, from, now, loc)...)
			}
			if sm, ok := statusMaintNext(w, now, now.Add(q.Ahead), loc); ok {
				d.list = append(d.list, sm)
			}
		}
		d.maint = spanUnion(spans)
		hd[h.UID] = d
		return d
	}

	for _, w := range wants {
		h := hosts[w.host]
		if h == nil {
			continue
		}
		src := &module.StatusSource{Name: h.Name, Group: h.Group, Incidents: []module.StatusIncident{}, Maintenance: []module.StatusMaint{}}
		if w.key != "" {
			row := svcs[w.host+"|"+w.key]
			if row == nil {
				continue
			}
			src.Name = h.Name + " – " + statusSvcName(row)
		}
		inMaint, _ := eval.InMaintenance(cfg.maint, now, hostRef(h), loc)
		src.State = statusStateOf(h, m.statusHostView(h.UID), w.key, inMaint)
		d := hostData(h)
		src.Maintenance = append(src.Maintenance, d.list...)

		// Zeitraeume aus den Problemen
		var downs, warns, unreach []tspan
		var openSince, lastClosed time.Time
		for _, p := range probs[h.UID] {
			if w.key != "" && p.key != w.key && p.key != "" {
				continue
			}
			for _, sg := range p.segs {
				switch sg.state {
				case "crit", "unreachable":
					downs = append(downs, sg.tspan)
					if sg.state == "unreachable" {
						unreach = append(unreach, sg.tspan)
					}
				case "warn", "unknown":
					warns = append(warns, sg.tspan)
				}
			}
			if p.closed.IsZero() {
				if openSince.IsZero() || p.opened.Before(openSince) {
					openSince = p.opened
				}
			} else if p.closed.After(lastClosed) {
				lastClosed = p.closed
			}
		}
		switch src.State {
		case module.StatusOK:
			src.Since = lastClosed
		case module.StatusWarn, module.StatusCrit, module.StatusUnreachable, module.StatusUnknown:
			src.Since = openSince
		}
		created := h.CreatedAt
		skip := spanUnion(append([]tspan{{time.Time{}, created}}, d.maint...)) // Wartung und vor dem Anlegen zaehlen nicht
		downAll := spanSubtract(spanUnion(downs), skip)
		warnAll := spanSubtract(spanSubtract(spanUnion(warns), downAll), skip)
		unreach = spanUnion(unreach)

		// Balken
		for i := 0; i+1 < len(q.Bounds); i++ {
			a, b := q.Bounds[i], q.Bounds[i+1]
			if created.After(a) {
				a = created
			}
			if now.Before(b) {
				b = now
			}
			var bar module.StatusBar
			if b.After(a) {
				bar.Maint = spanOverlap(d.maint, a, b)
				bar.Observed = b.Sub(a) - bar.Maint
				bar.Down = spanOverlap(downAll, a, b)
				bar.Warn = spanOverlap(warnAll, a, b)
			}
			src.Bars = append(src.Bars, bar)
		}

		// Stoerungen (gestoerte Zeitraeume ohne Wartung), neueste zuerst
		if !q.History.IsZero() {
			for i := len(downAll) - 1; i >= 0 && len(src.Incidents) < statusMaxIncidents; i-- {
				s := downAll[i]
				if s.to.Before(q.History) {
					break
				}
				inc := module.StatusIncident{Start: s.from, End: s.to, Reason: "crit"}
				if !s.to.Before(now) {
					inc.End = time.Time{} // laeuft
				}
				if spanOverlap(unreach, s.from, s.to) > 0 {
					inc.Reason = "unreachable"
				}
				src.Incidents = append(src.Incidents, inc)
			}
		}
		out[w.src] = src
	}
	return out, nil
}
