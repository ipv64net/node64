package healthchecks

import (
	"context"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/module"
)

// Statusseiten: Eintraege aus Monitor64 (Plan docs/PLAN-NODE64-MONITOR64.md "Statusseiten (entschieden 2026-11-09)").
// Ein Eintrag hat statt des Check-Tokens eine Quelle "m64:host:<uid>" bzw. "m64:svc:<uid>/<key>"; Zustand, Balken,
// Stoerungen und Wartungen liefert Monitor64 ueber module.StatusFeed (cmd/node64/main.go: SetMonitor64Status). Ist
// Monitor64 aus oder nicht registriert, fallen die Eintraege beim Anzeigen weg (wie geloeschte Checks), die Seite
// laeuft weiter und der Editor zeigt einen Hinweis. Im Cluster gehen die Eintraege mit der Seite mit (wie Tokens),
// angezeigt werden sie vorerst nur auf der Node, deren Monitor64 den Host kennt.
//
// Zustand: ok -> up (in Betrieb), warn -> degraded (eingeschraenkt), crit und unreachable -> down (gestoert),
// unknown -> unknown, maintenance -> maintenance, paused -> paused. Tagesbalken wie bei den Checks (statusBucket), die
// Zeiten statt Messungen: beobachtete und gestoerte Sekunden; eingeschraenkte Zeit macht einen sonst guten Balken gelb.

// statusM64Group ist die Gruppe der Monitor64-Eintraege in der Auswahl des Editors (Filter).
const statusM64Group = "Monitor64"

const statusM64Prefix = "m64:"

var statusM64Re = regexp.MustCompile(`^m64:(?:host:[A-Za-z0-9_-]{1,64}|svc:[A-Za-z0-9_-]{1,64}/[^\x00-\x1f\x7f]{1,200})$`)

// statusM64Feeds ordnet jedem Modul die Verbindung zu Monitor64 zu (ohne Feld im Modul, wie statusStates).
var statusM64Feeds sync.Map // *Module -> func() module.StatusFeed

// SetMonitor64Status verbindet Monitor64 mit den Statusseiten; fn liefert nil, solange Monitor64 nicht laeuft.
func (m *Module) SetMonitor64Status(fn func() module.StatusFeed) { statusM64Feeds.Store(m, fn) }

// m64Status liefert Monitor64 (nil = aus oder nicht registriert).
func (m *Module) m64Status() module.StatusFeed {
	if fn, ok := statusM64Feeds.Load(m); ok {
		if f, _ := fn.(func() module.StatusFeed); f != nil {
			return f()
		}
	}
	return nil
}

// isM64Source: Eintrag aus Monitor64 (statt Check-Token).
func isM64Source(tok string) bool { return strings.HasPrefix(tok, statusM64Prefix) }

// validM64Source prueft die Form einer Monitor64-Quelle.
func validM64Source(tok string) bool { return statusM64Re.MatchString(tok) }

// statusM64HostUID liefert den Host einer Quelle (fuer den Link im Editor).
func statusM64HostUID(tok string) string {
	rest := strings.TrimPrefix(tok, statusM64Prefix)
	if uid, ok := strings.CutPrefix(rest, "host:"); ok {
		return uid
	}
	rest = strings.TrimPrefix(rest, "svc:")
	uid, _, _ := strings.Cut(rest, "/")
	return uid
}

// statusM64State bildet den Zustand aus Monitor64 auf die Zustaende der Statusseite ab.
func statusM64State(s string) string {
	switch s {
	case module.StatusOK:
		return "up"
	case module.StatusWarn:
		return "degraded"
	case module.StatusCrit, module.StatusUnreachable:
		return "down"
	case module.StatusMaintenance:
		return "maintenance"
	case module.StatusPaused:
		return "paused"
	}
	return "unknown"
}

// statusM64Agg: Zeiten eines Balkens als Messungen (Sekunden beobachtet / davon nicht gestoert).
func statusM64Agg(b module.StatusBar) statusAgg {
	obs := max(b.Observed, 0)
	down := min(max(b.Down, 0), obs)
	return statusAgg{count: int(obs / time.Second), up: int((obs - down) / time.Second)}
}

// statusM64Bar bewertet einen Balken (Laenge span; Wartung ab der Haelfte wie statusMaintCover).
func statusM64Bar(label string, b module.StatusBar, span time.Duration) StatusViewDay {
	maint := b.Maint > 0 && 2*b.Maint >= span
	d := statusBucket(label, statusM64Agg(b), int(math.Ceil(max(b.Down, 0).Minutes())), maint)
	if d.State == "up" && b.Warn > 0 {
		d.State = "partial"
	}
	return d
}

// statusM64Sources fragt Monitor64 nach dem Stand der Quellen; ohne Monitor64 oder bei einem Fehler nil (die
// Eintraege fallen weg, die Seite laeuft weiter).
func (m *Module) statusM64Sources(ctx context.Context, sources []string, q module.StatusQuery) map[string]*module.StatusSource {
	if len(sources) == 0 {
		return nil
	}
	f := m.m64Status()
	if f == nil {
		return nil
	}
	q.Sources = sources
	res, err := f.StatusSources(ctx, q)
	if err != nil {
		m.log.Warn("status page: monitor64", "err", err)
		return nil
	}
	return res
}

// statusM64Detail liefert die Details eines Monitor64-Eintrags (wie statusItemDetail, ohne Latenz).
func (m *Module) statusM64Detail(ctx context.Context, p *StatusPage, it *StatusItem, lang string) (*StatusItemDetail, error) {
	now := statusNow()
	loc := m.statusLocation(ctx)
	tr := m.translator(lang)
	// Balken der Anfrage: 30 Tage bis 7 Tage, 7 Tage bis 24 Stunden, 24 Stunden bis zum ersten Stundenbalken, dann die
	// 24 Stundenbalken (aelteste zuerst, die letzte Stunde endet jetzt) - eine Abfrage fuer alles
	const first = 3
	cur := now.Truncate(time.Hour)
	bounds := []time.Time{now.Add(-30 * 24 * time.Hour), now.Add(-7 * 24 * time.Hour), now.Add(-24 * time.Hour)}
	for i := 0; i < 24; i++ {
		bounds = append(bounds, cur.Add(-time.Duration(23-i)*time.Hour))
	}
	bounds = append(bounds, now)
	var hist time.Time
	if p.ShowHistory {
		hist = now.Add(-statusHistory)
	}
	s := m.statusM64Sources(ctx, []string{it.Token}, module.StatusQuery{Bounds: bounds, History: hist, Now: now})[it.Token]
	if s == nil {
		return nil, ErrStatusPageNotFound
	}
	label := it.Label
	if label == "" {
		label = s.Name
	}
	d := &StatusItemDetail{ID: it.ID, Label: label, State: statusM64State(s.State), Incidents: []StatusViewIncid{}, Latency: -1}
	if !s.Since.IsZero() {
		d.Since = s.Since.UTC()
	}
	bar := func(i int) module.StatusBar {
		if i < len(s.Bars) {
			return s.Bars[i]
		}
		return module.StatusBar{}
	}
	var a30, a7, a24 statusAgg
	for i := 0; i+1 < len(bounds); i++ {
		a := statusM64Agg(bar(i))
		a30.add(a)
		if i >= 1 {
			a7.add(a)
		}
		if i >= 2 {
			a24.add(a)
		}
	}
	d.Uptime24h, d.Uptime7d, d.Uptime30d = statusPct(a24), statusPct(a7), statusPct(a30)
	if !p.ShowUptime {
		d.Uptime24h, d.Uptime7d, d.Uptime30d = -1, -1, -1
	}
	d.ShowUptime, d.ShowHistory = p.ShowUptime, p.ShowHistory
	d.Hours = make([]StatusViewDay, 24)
	for i := 0; i < 24; i++ {
		k := first + i
		d.Hours[i] = statusM64Bar(statusHourLabel(bounds[k], loc), bar(k), bounds[k+1].Sub(bounds[k]))
		if !p.ShowUptime {
			d.Hours[i].Uptime = -1
		}
	}
	if p.ShowHistory {
		for _, i := range s.Incidents {
			if len(d.Incidents) >= 5 {
				break
			}
			d.Incidents = append(d.Incidents, statusM64Incident(tr, label, i))
		}
	}
	return d, nil
}

// statusM64Incident: Stoerung eines Monitor64-Eintrags mit allgemeinem Grund (hc.reasons.m64_<grund>).
func statusM64Incident(tr func(string, ...any) string, label string, i module.StatusIncident) StatusViewIncid {
	vi := StatusViewIncid{Item: label, Start: i.Start.UTC(), Reason: statusReason(tr, "m64_"+i.Reason)}
	if !i.End.IsZero() {
		vi.End = i.End.UTC()
	}
	return vi
}

// statusM64Targets liefert die Auswahl fuer den Editor (nil, on=false ohne Monitor64).
func (m *Module) statusM64Targets(ctx context.Context) (list []module.StatusTarget, on bool) {
	f := m.m64Status()
	if f == nil {
		return nil, false
	}
	list, err := f.StatusTargets(ctx)
	if err != nil {
		m.log.Warn("status page: monitor64 targets", "err", err)
	}
	return list, true
}

// statusM64Label ist der Name eines Eintrags in Editor und Vorgabe der Bezeichnung (Host bzw. "Host – Dienst").
func statusM64Label(t module.StatusTarget) string {
	if t.Name == "" {
		return t.Host
	}
	return t.Host + " – " + t.Name
}

// statusAddM64 haengt Monitor64-Eintraege an die Gruppe an, die Monitor64 kennt und die dort noch fehlen (Reihenfolge
// wie die Auswahl). Ohne Monitor64 passiert nichts.
func (m *Module) statusAddM64(ctx context.Context, g *StatusGroup, sources []string) error {
	if len(sources) == 0 {
		return nil
	}
	f := m.m64Status()
	if f == nil {
		return nil
	}
	list, err := f.StatusTargets(ctx)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, s := range sources {
		want[s] = true
	}
	has := map[string]bool{}
	for _, it := range g.Items {
		has[it.Token] = true
	}
	for _, t := range list {
		if want[t.Source] && !has[t.Source] {
			g.Items, has[t.Source] = append(g.Items, StatusItem{Token: t.Source}), true
		}
	}
	return nil
}
