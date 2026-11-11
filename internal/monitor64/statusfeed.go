package monitor64

import (
	"context"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Monitor64 auf den Statusseiten (Plan "Statusseiten (entschieden 2026-11-09)"): Healthchecks fragt ueber
// module.StatusFeed Zustand, Balken, Stoerungen und Wartungen der aufgenommenen Hosts bzw. Dienste ab. Nach aussen
// gehen nur Name und Zustand: keine Werte, Adressen, Texte oder Dienstnamen (ausser beim einzeln aufgenommenen Dienst).
//
// Zustand: Host pausiert -> paused; Wartung -> maintenance; noch keine Runde bzw. im Cluster kein Stand der
// zustaendigen Node (nicht erreichbar, noch nichts gemeldet) -> unknown; nicht erreichbar -> unreachable; sonst der
// schlimmste Dienst ohne "nur anzeigen" (Host, wie die Probleme) bzw. der Dienst selbst. Im Cluster liefert jede Node
// denselben Stand: fremd ueberwachte Hosts aus dem abgeglichenen Zustand der zustaendigen Node (idleView).
//
// Balken und Stoerungen aus der Problem-Historie (m64_problems, Zustandswechsel aus m64_events): kritisch und nicht
// erreichbar = gestoert, Warnung und unbekannt = eingeschraenkt. Host-Eintrag: alle Probleme des Hosts; Dienst-Eintrag:
// die des Dienstes und "nicht erreichbar" des Hosts. Wartungszeit zaehlt nicht (wie bei den Checks), ebenso die Zeit
// vor dem Anlegen des Hosts und die Zeit, in der er pausiert war (weder gestoert noch beobachtet). Wiederkehrende
// Fenster ohne Beginn wirken erst ab ihrer letzten Aenderung (nicht rueckwirkend auf die ganze Historie).
//
// Ebenso zaehlt die Zeit nicht, in der Monitor64 nicht lief (Modul aus, Node aus, Neustart ab 5 min; Luecken je Node
// in m64_gaps, uptime.go): ein offenes Problem laeuft in dieser Zeit nicht als Stoerung weiter, und sie gilt nicht als
// beobachtete gute Zeit. Im Cluster zaehlt fuer einen Host nur die Zeit, in der keine seiner Nodes lief (zustaendige,
// bevorzugte und Ersatz-Nodes nach heutigem Stand - eine Ersatz-Node uebernimmt nach wenigen Minuten). Grenzen: die
// Luecke einer anderen Node kommt erst an, wenn sie wieder laeuft (bis dahin zeigt der Host "unbekannt", die Balken
// zaehlen die Zeit noch); frueher eingetragene Nodes des Hosts und eine Ersatz-Node, die mangels Mehrheit nicht
// uebernehmen durfte, bleiben unberuecksichtigt.

var _ module.StatusFeed = (*Module)(nil)

// Obergrenzen der Problem-Historie (Variablen fuer die Tests)
var (
	statusMaxProblems     = 50000 // je Anfrage (die Seite rechnet hoechstens alle 30 s)
	statusMaxProblemsHost = 10000 // je Host (die neuesten)
)

const (
	statusSrcHost      = "m64:host:"
	statusSrcSvc       = "m64:svc:"
	statusMaxIncidents = 100 // Stoerungen je Quelle (neueste zuerst)
	statusMaxDays      = 800 // Tage, die ein wiederkehrendes Wartungsfenster hoechstens durchlaeuft
)

// StatusSourceHost ist die Quelle eines Host-Eintrags auf einer Statusseite.
func StatusSourceHost(uid string) string { return statusSrcHost + uid }

// StatusSourceService ist die Quelle eines Dienst-Eintrags auf einer Statusseite.
func StatusSourceService(uid, key string) string { return statusSrcSvc + uid + "/" + key }

// parseStatusSource zerlegt eine Quelle (key "" = Host); Format und Pruefung im Kern (module.ParseStatusSource).
func parseStatusSource(s string) (host, key string, ok bool) { return module.ParseStatusSource(s) }

func validStatusKey(k string) bool { return module.ValidStatusKey(k) }

func validStatusUID(s string) bool { return module.ValidStatusUID(s) }

// statusSvcName ist der Name eines Dienstes in der Auswahl und auf der Seite, uebersetzt nach lang ("" = Deutsch;
// erkannte Namen sind Token, siehe model.T).
func (m *Module) statusSvcName(r *ServiceRow, lang string) string {
	name := firstNonEmpty(r.Name, r.Key)
	if m.g.Translate == nil {
		return name
	}
	if lang == "" {
		lang = "de"
	}
	return model.Translate(name, func(key string, args ...any) string { return m.g.Translate(lang, key, args...) })
}

// statusAddable: Dienste, die man einzeln aufnehmen kann (uebernommen, keine Zugaenge, Schluessel passt in die Quelle).
func statusAddable(r *ServiceRow) bool {
	return r.Adopted == 1 && !strings.HasPrefix(r.Key, "access:") && validStatusKey(r.Key)
}

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
		if !validStatusUID(h.UID) { // Quelle waere ungueltig (die Seite liesse sich nicht speichern)
			continue
		}
		out = append(out, module.StatusTarget{Source: StatusSourceHost(h.UID), Host: h.Name, Group: h.Group, Paused: h.Paused})
		list := byHost[h.UID]
		sort.SliceStable(list, func(i, j int) bool {
			return strings.ToLower(m.statusSvcName(list[i], "")) < strings.ToLower(m.statusSvcName(list[j], ""))
		})
		for _, r := range list {
			out = append(out, module.StatusTarget{Source: StatusSourceService(h.UID, r.Key), Host: h.Name, Name: m.statusSvcName(r, ""), Group: h.Group, Paused: h.Paused})
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

// spanIntersect: Zeitraeume, die in a und in b liegen (beide verschmolzen und sortiert).
func spanIntersect(a, b []tspan) []tspan {
	var out []tspan
	for i, j := 0, 0; i < len(a) && j < len(b); {
		lo, hi := statusLater(a[i].from, b[j].from), statusEarlier(a[i].to, b[j].to)
		if hi.After(lo) {
			out = append(out, tspan{lo, hi})
		}
		if a[i].to.Before(b[j].to) {
			i++
		} else {
			j++
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

// statusScanSpans liefert die Zeitraeume eines wiederkehrenden Fensters innerhalb des Tages [day, next) minutengenau
// ueber eval.Window.Active (fuer Tage mit Zeitumstellung: dort fehlen bzw. doppeln sich Uhrzeiten der Wanduhr, und
// time.Date liefert fuer sie andere Zeitpunkte, als die Bewertung der Runden annimmt).
func statusScanSpans(r *eval.Recurrence, day, next time.Time, loc *time.Location) []tspan {
	probe := eval.Window{Hosts: []string{"x"}, Recurring: r}
	ref := eval.HostRef{ID: "x"}
	var out []tspan
	for t := day; t.Before(next); t = t.Add(time.Minute) {
		if !probe.Active(t, ref, loc) {
			continue
		}
		e := statusEarlier(t.Add(time.Minute), next)
		if n := len(out); n > 0 && out[n-1].to.Equal(t) {
			out[n-1].to = e
		} else {
			out = append(out, tspan{t, e})
		}
	}
	return out
}

// statusWindowSpans liefert die Zeitraeume eines Wartungsfensters innerhalb [from, to) (wiederkehrend nach der
// Wanduhr in loc, wie eval.Window.Active), aufsteigend.
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
	var out, dst []tspan
	for i := 0; i < statusMaxDays; i++ {
		d := time.Date(l.Year(), l.Month(), l.Day()-1+i, 0, 0, 0, 0, loc) // ab dem Vortag (ueber Mitternacht)
		if !d.Before(hi) {
			break
		}
		next := time.Date(d.Year(), d.Month(), d.Day()+1, 0, 0, 0, 0, loc)
		_, o0 := d.Zone()
		_, o1 := next.Zone()
		if o0 != o1 && next.After(lo) {
			dst = append(dst, tspan{d, next}) // Zeitumstellung an diesem Tag
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
	if len(dst) == 0 {
		return out
	}
	// Tage mit Zeitumstellung minutengenau nach der Wanduhr (wie die Runden); Termine, die ueber die Tagesgrenze
	// reichen, bleiben ein Stueck
	out = spanSubtract(out, dst)
	for _, day := range dst {
		for _, s := range statusScanSpans(r, day.from, day.to, loc) {
			s.from, s.to = statusLater(s.from, lo), statusEarlier(s.to, hi)
			if s.to.After(s.from) {
				out = append(out, s)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].from.Before(out[j].from) })
	merged := out[:0]
	for _, s := range out {
		if n := len(merged); n > 0 && merged[n-1].to.Equal(s.from) && statusDayEdge(dst, s.from) {
			merged[n-1].to = s.to
			continue
		}
		merged = append(merged, s)
	}
	return merged
}

// statusDayEdge: t ist Beginn oder Ende eines der Tage.
func statusDayEdge(days []tspan, t time.Time) bool {
	for _, d := range days {
		if t.Equal(d.from) || t.Equal(d.to) {
			return true
		}
	}
	return false
}

func statusLater(a, b time.Time) time.Time {
	if a.Before(b) {
		return b
	}
	return a
}

func statusEarlier(a, b time.Time) time.Time {
	if a.After(b) {
		return b
	}
	return a
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

// statusProblems laedt die Probleme der Hosts, die [from, now] beruehren, mit ihren Zustandswechseln. Bei sehr vielen
// Problemen bleiben die neuesten (je Host hoechstens statusMaxProblemsHost, insgesamt statusMaxProblems).
func (m *Module) statusProblems(ctx context.Context, hosts []string, from, now time.Time) (map[string][]*statusProblem, error) {
	out := map[string][]*statusProblem{}
	byUID := map[string]*statusProblem{}
	var uids []string
	initial := map[string]string{} // Problem -> Zustand ohne Ereignisse (offen: aktuell, geschlossen: schlimmster)
	err := statusChunks(hosts, func(ph string, args []any) error {
		left := statusMaxProblems - len(byUID)
		if left <= 0 {
			return nil
		}
		rows, err := m.st.Reader().QueryContext(ctx, `SELECT uid, host_uid, service_key, state, worst, opened_at, closed_at FROM (
			SELECT uid, host_uid, service_key, state, worst, opened_at, closed_at, ROW_NUMBER() OVER (PARTITION BY host_uid ORDER BY opened_at DESC, id DESC) AS rn
			FROM m64_problems WHERE deleted = 0 AND host_uid IN (`+ph+`) AND opened_at <= ? AND (closed_at = '' OR closed_at >= ?))
			WHERE rn <= ? ORDER BY opened_at DESC LIMIT ?`,
			append(args, ts(now), ts(from), statusMaxProblemsHost, left)...)
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
	case statusNoState(v):
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

// statusNoState: kein verwertbarer Stand - noch keine Runde, im Cluster kein Stand der zustaendigen Node (nicht
// erreichbar bzw. noch nichts gemeldet; die Ansicht enthaelt dann evtl. noch die alten Dienste) oder eine leere Ansicht.
// Eine Ansicht "unbekannt" mit Diensten zaehlt nach ihren Diensten (ein Dienst "nur anzeigen" zaehlt beim Host nicht).
func statusNoState(v *HostView) bool {
	if v == nil {
		return true
	}
	if c := v.Cluster; c != nil && (c.Note == noteOwnerUnreachable || c.Note == noteNoData) {
		return true
	}
	return v.View == eval.ViewUnknown && len(v.Services) == 0
}

// statusHostData ist, was alle Eintraege eines Hosts teilen (Wartungen, Pausen, Laufzeit-Luecken).
type statusHostData struct {
	maint []tspan
	off   []tspan // Wartung, Pause und Zeiten ohne laufendes Monitor64 (zaehlen nicht als beobachtet)
	list  []module.StatusMaint
}

// statusGaps liefert je Node die Zeitraeume seit from, in denen Monitor64 dort nicht lief (m64_gaps, verschmolzen).
func (m *Module) statusGaps(ctx context.Context, from, now time.Time) (map[string][]tspan, error) {
	rows, err := m.st.Reader().QueryContext(ctx, `SELECT node_id, from_at, to_at FROM m64_gaps WHERE to_at >= ? AND from_at <= ?`, ts(from), ts(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]tspan{}
	for rows.Next() {
		var node, a, b string
		if err := rows.Scan(&node, &a, &b); err != nil {
			return nil, err
		}
		if s := (tspan{parseTS(a), statusEarlier(parseTS(b), now)}); !s.from.IsZero() && s.to.After(s.from) {
			out[node] = append(out[node], s)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for node, spans := range out {
		out[node] = spanUnion(spans)
	}
	return out, nil
}

// statusHostGaps: Zeitraeume, in denen keine Node den Host ueberwachen konnte - Monitor64 lief auf keiner seiner
// Nodes (zustaendige, bevorzugte, Ersatz-Nodes). Ohne Cluster ist das die Luecke dieser Node.
func statusHostGaps(h *Host, self string, gaps map[string][]tspan) []tspan {
	if len(gaps) == 0 {
		return nil
	}
	nodes := candidatesOf(h, self)
	if o := ownerOf(h, self); !slices.Contains(nodes, o) {
		nodes = append(nodes, o)
	}
	out := gaps[nodes[0]]
	for _, n := range nodes[1:] {
		if len(out) == 0 {
			break
		}
		out = spanIntersect(out, gaps[n])
	}
	return out
}

// statusLoad laedt nur die gefragten Hosts und Dienste (jeder Abruf einer oeffentlichen Seite fragt hier an).
func (m *Module) statusLoad(ctx context.Context, hostUIDs []string, svcWants [][2]string) (map[string]*Host, map[string]*ServiceRow, error) {
	hosts := map[string]*Host{}
	err := statusChunks(hostUIDs, func(ph string, args []any) error {
		rows, err := m.st.Reader().QueryContext(ctx, `SELECT `+hostCols+` FROM m64_hosts WHERE deleted = 0 AND uid IN (`+ph+`)`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			h, err := scanHost(rows)
			if err != nil {
				return err
			}
			hosts[h.UID] = h
		}
		return rows.Err()
	})
	if err != nil {
		return nil, nil, err
	}
	svcs := map[string]*ServiceRow{}
	const n = 200 // Paare je Abfrage (zwei Platzhalter je Paar)
	for i := 0; i < len(svcWants); i += n {
		part := svcWants[i:min(i+n, len(svcWants))]
		conds := make([]string, len(part))
		args := make([]any, 0, 2*len(part))
		for j, p := range part {
			conds[j] = "(host_uid = ? AND key = ?)"
			args = append(args, p[0], p[1])
		}
		err := func() error {
			rows, err := m.st.Reader().QueryContext(ctx, `SELECT host_uid, key, name, adopted FROM m64_services WHERE deleted = 0 AND (`+strings.Join(conds, " OR ")+`)`, args...)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				r := &ServiceRow{}
				if err := rows.Scan(&r.HostUID, &r.Key, &r.Name, &r.Adopted); err != nil {
					return err
				}
				if statusAddable(r) {
					svcs[r.HostUID+"|"+r.Key] = r
				}
			}
			return rows.Err()
		}()
		if err != nil {
			return nil, nil, err
		}
	}
	return hosts, svcs, nil
}

// statusPauses liefert je Host die Zeitraeume, in denen er pausiert war: aus den Host-Ereignissen "pause"/"resume"
// und, solange er pausiert ist, bis jetzt. Fehlt das Ereignis zum Beginn bzw. Ende, gilt die letzte Aenderung des
// Hosts (die Pause begann bzw. endete spaetestens dann).
func (m *Module) statusPauses(ctx context.Context, hosts map[string]*Host, now time.Time) (map[string][]tspan, error) {
	uids := make([]string, 0, len(hosts))
	for uid := range hosts {
		uids = append(uids, uid)
	}
	sort.Strings(uids)
	type ev struct {
		at    time.Time
		pause bool
	}
	evs := map[string][]ev{}
	err := statusChunks(uids, func(ph string, args []any) error {
		rows, err := m.st.Reader().QueryContext(ctx, `SELECT host_uid, ts, kind FROM m64_events
			WHERE host_uid IN (`+ph+`) AND problem_uid = '' AND kind IN ('pause', 'resume') ORDER BY ts, id`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var uid, at, kind string
			if err := rows.Scan(&uid, &at, &kind); err != nil {
				return err
			}
			if t := parseTS(at); !t.IsZero() {
				evs[uid] = append(evs[uid], ev{t, kind == "pause"})
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	out := map[string][]tspan{}
	for _, uid := range uids {
		h := hosts[uid]
		var spans []tspan
		var start time.Time
		paused := false
		for _, e := range evs[uid] {
			switch {
			case e.pause && !paused:
				start, paused = e.at, true
			case !e.pause && paused:
				spans, paused = append(spans, tspan{start, e.at}), false
			}
		}
		switch {
		case h.Paused && paused:
			spans = append(spans, tspan{start, now})
		case h.Paused && !h.UpdatedAt.IsZero():
			spans = append(spans, tspan{h.UpdatedAt, now})
		case paused && !h.UpdatedAt.IsZero():
			spans = append(spans, tspan{start, h.UpdatedAt})
		}
		if spans = spanUnion(spans); len(spans) > 0 {
			out[uid] = spans
		}
	}
	return out, nil
}

// statusHistoryMaint liefert die Wartungsfenster fuer die Historie: wiederkehrende Fenster ohne Beginn wirken erst ab
// ihrer letzten Aenderung (sonst gaelten sie rueckwirkend fuer die ganze Historie und verdeckten alte Stoerungen).
func (m *Module) statusHistoryMaint(ctx context.Context, ws []eval.Window, now time.Time) ([]eval.Window, error) {
	need := false
	for _, w := range ws {
		need = need || (w.Recurring != nil && w.Start.IsZero())
	}
	if !need {
		return ws, nil
	}
	since := map[string]time.Time{}
	rows, err := m.st.Reader().QueryContext(ctx, `SELECT uid, updated_at FROM m64_maint WHERE deleted = 0 AND recur != '' AND start_at = ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var uid, at string
		if err := rows.Scan(&uid, &at); err != nil {
			return nil, err
		}
		since[uid] = parseTS(at)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := slices.Clone(ws)
	for i := range out {
		if out[i].Recurring != nil && out[i].Start.IsZero() {
			out[i].Start = now // unbekannt: nicht rueckwirkend
			if s := since[out[i].ID]; !s.IsZero() && s.Before(now) {
				out[i].Start = s
			}
		}
	}
	return out, nil
}

// StatusSources liefert den Stand der Quellen fuer eine Statusseite (Regeln siehe oben).
func (m *Module) StatusSources(ctx context.Context, q module.StatusQuery) (map[string]*module.StatusSource, error) {
	out := map[string]*module.StatusSource{}
	type want struct{ src, host, key string }
	var wants []want
	seen := map[string]bool{}
	hostSet := map[string]bool{}
	var hostUIDs []string
	var svcWants [][2]string
	for _, s := range q.Sources {
		h, k, ok := parseStatusSource(s)
		if !ok || seen[s] {
			continue
		}
		seen[s] = true
		wants = append(wants, want{s, h, k})
		if k != "" {
			svcWants = append(svcWants, [2]string{h, k})
		}
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
	hosts, svcs, err := m.statusLoad(ctx, hostUIDs, svcWants)
	if err != nil {
		return nil, err
	}
	// Zeitraum der Historie: ab dem ersten Balken bzw. dem Beginn der Stoerungsliste
	var from time.Time
	if len(q.Bounds) >= 2 {
		from = q.Bounds[0]
	}
	if !q.History.IsZero() && (from.IsZero() || q.History.Before(from)) {
		from = q.History
	}
	cfg := m.config()
	loc := m.location()
	probs := map[string][]*statusProblem{}
	pauses := map[string][]tspan{}
	gaps := map[string][]tspan{}
	self := m.clusterSelf()
	histMaint := cfg.maint
	if !from.IsZero() && from.Before(now) {
		if probs, err = m.statusProblems(ctx, hostUIDs, from, now); err != nil {
			return nil, err
		}
		if pauses, err = m.statusPauses(ctx, hosts, now); err != nil {
			return nil, err
		}
		if gaps, err = m.statusGaps(ctx, from, now); err != nil {
			return nil, err
		}
		if histMaint, err = m.statusHistoryMaint(ctx, cfg.maint, now); err != nil {
			return nil, err
		}
	}
	hd := map[string]*statusHostData{}
	hostData := func(h *Host) *statusHostData {
		if d := hd[h.UID]; d != nil {
			return d
		}
		d := &statusHostData{}
		ref := hostRef(h)
		var spans []tspan
		if !from.IsZero() {
			for _, w := range histMaint {
				if w.Applies(ref) {
					spans = append(spans, statusWindowSpans(w, from, now, loc)...)
				}
			}
		}
		for _, w := range cfg.maint { // laufende und kommende Termine wie die Runden (ohne Begrenzung der Historie)
			if !w.Applies(ref) {
				continue
			}
			if sm, ok := statusMaintNext(w, now, now.Add(q.Ahead), loc); ok {
				d.list = append(d.list, sm)
			}
		}
		d.maint = spanUnion(spans)
		d.off = spanUnion(append(append(slices.Clone(d.maint), pauses[h.UID]...), statusHostGaps(h, self, gaps)...))
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
			src.Name = h.Name + " – " + m.statusSvcName(row, q.Lang)
		}
		inMaint, _ := eval.InMaintenance(cfg.maint, now, hostRef(h), loc)
		v := m.statusHostView(h.UID)
		src.State = statusStateOf(h, v, w.key, inMaint)
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
		case module.StatusWarn, module.StatusCrit, module.StatusUnreachable:
			src.Since = openSince
		case module.StatusUnknown:
			if !statusNoState(v) { // ohne Stand (Cluster) ist nicht bekannt, seit wann
				src.Since = openSince
			}
		}
		created := h.CreatedAt
		skip := spanUnion(append([]tspan{{time.Time{}, created}}, d.off...)) // Wartung, Pause, Zeit ohne Monitor64 und vor dem Anlegen zaehlen nicht
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
				bar.Observed = b.Sub(a) - spanOverlap(d.off, a, b)
				bar.Down = spanOverlap(downAll, a, b)
				bar.Warn = spanOverlap(warnAll, a, b)
			}
			src.Bars = append(src.Bars, bar)
		}

		// Stoerungen (gestoerte Zeitraeume ohne Wartung, Pause und Zeit ohne Monitor64), neueste zuerst
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
