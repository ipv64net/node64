package monitor64

import (
	"context"
	"sort"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/monitor64/eval"
)

// Dashboard des Kerns: kleine Karte mit Kennzahlen (module.CardProvider) und die Probleme in der gemeinsamen Liste
// "Letzte Stoerungen" mit den Healthchecks (module.IncidentProvider).

// NavState: Gesamtzustand fuer den Punkt neben "Monitor64" in der Navigation (module.NavStateProvider) - aus dem
// Stand im Speicher wie die Zaehler der Uebersicht. Pausierte Hosts, Hosts im Wartungsfenster und reine
// Anzeige-Dienste zaehlen nicht; nicht erreichbar ist kritisch, Unbekannt eine Warnung. Ohne Hosts kein Punkt.
func (m *Module) NavState() string {
	vs := m.Views()
	if len(vs) == 0 {
		return ""
	}
	out := module.NavOK
	for _, v := range vs {
		if v.Host == nil || v.Host.Paused || v.Maint != nil || v.View == eval.ViewOffline { // ausgeschaltet (#229) zaehlt nicht
			continue
		}
		if v.View == eval.ViewUnreachable {
			return module.NavCrit
		}
		if c := v.Cluster; c != nil && (c.Note == noteOwnerUnreachable || c.Note == noteNoData) {
			out = module.NavWarn // Stand der zustaendigen Node fehlt: unbekannt
			continue
		}
		for _, s := range v.Services {
			if s.ShowOnly {
				continue
			}
			switch s.State {
			case eval.Crit:
				return module.NavCrit
			case eval.Warn, eval.Unknown:
				out = module.NavWarn
			}
		}
	}
	return out
}

// Card liefert die Dashboard-Karte: Hosts, Dienste, offene Probleme nach Zustand, Wartung, letzte Stoerung.
func (m *Module) Card(ctx context.Context) (*module.Card, error) {
	c := &module.Card{TitleKey: "nav.monitor64", Icon: "bi-activity", Image: "monitor64.svg", Path: "/monitor64"}
	// Zahlen aus dem Stand im Speicher (wie die Uebersicht, aber ohne deren Datenbank-Abfragen)
	var hosts, services, unreach, crit, warn, unknown, maint, paused int64
	for _, v := range m.Views() {
		hosts++
		if v.Maint != nil {
			maint++
		}
		if v.Host.Paused {
			paused++
		}
		down := v.View == eval.ViewUnreachable && !v.Host.Paused
		if down {
			unreach++
		}
		for _, s := range v.Services {
			services++
			if down || v.Host.Paused || v.View == eval.ViewOffline || s.ShowOnly {
				continue
			}
			switch s.State {
			case eval.Crit:
				crit++
			case eval.Warn:
				warn++
			case eval.Unknown:
				unknown++
			}
		}
	}
	red := func(n int64) string {
		if n > 0 {
			return "text-danger"
		}
		return ""
	}
	c.Stats = []module.CardStat{
		{LabelKey: "monitor64.card.hosts", Value: hosts},
		{LabelKey: "monitor64.card.services", Value: services},
		{LabelKey: "monitor64.card.unreachable", Value: unreach, Class: red(unreach)},
		{LabelKey: "monitor64.card.crit", Value: crit, Class: red(crit)},
	}
	st := module.CardStat{LabelKey: "monitor64.card.warn", Value: warn}
	if warn > 0 {
		st.Class = "text-warning-emphasis"
	}
	c.Stats = append(c.Stats, st)
	if unknown > 0 {
		c.Stats = append(c.Stats, module.CardStat{LabelKey: "monitor64.card.unknown", Value: unknown, Class: "text-body-secondary"})
	}
	if maint > 0 {
		c.Stats = append(c.Stats, module.CardStat{LabelKey: "monitor64.card.maint", Value: maint})
	}
	if paused > 0 {
		c.Stats = append(c.Stats, module.CardStat{LabelKey: "monitor64.card.paused", Value: paused})
	}
	if inc := m.DashIncidents(ctx, 1); len(inc) > 0 {
		c.Stats = append(c.Stats, module.CardStat{LabelKey: "monitor64.card.last", Text: inc[0].Name, Title: inc[0].Name, Ago: inc[0].StartedAt})
	}
	return c, nil
}

// DashIncidents liefert die letzten Probleme (offen und geloest, neueste zuerst) fuer "Letzte Stoerungen".
func (m *Module) DashIncidents(ctx context.Context, n int) []module.IncidentInfo {
	if n <= 0 {
		return nil
	}
	hosts := map[string]string{}
	svcs := map[string]string{}
	for _, v := range m.Views() {
		hosts[v.Host.UID] = v.Host.Name
		for _, s := range v.Services {
			svcs[v.Host.UID+"|"+s.Key] = s.Name
		}
	}
	// offene stehen in Problems vorne: offene und geloeste getrennt holen, dann nach Beginn mischen (mit Reserve fuer
	// Probleme geloeschter Hosts, die unten wegfallen)
	var list []problemRow
	for _, status := range []string{"open", "closed"} {
		l, err := m.store.Problems(ctx, problemFilter{Status: status, Limit: n + 50})
		if err != nil {
			m.log.Warn("monitor64: dashboard problems", "err", err)
			continue
		}
		list = append(list, l...)
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].Opened.After(list[j].Opened) })
	asked := map[string]bool{}
	svcName := func(hostUID, key string) string {
		if n := svcs[hostUID+"|"+key]; n != "" {
			return n
		}
		if !asked[hostUID] { // Host noch nicht abgefragt (z. B. pausiert): Namen aus der Datenbank
			asked[hostUID] = true
			if rows, err := m.store.Services(ctx, hostUID); err == nil {
				for _, r := range rows {
					if svcs[hostUID+"|"+r.Key] == "" {
						svcs[hostUID+"|"+r.Key] = r.Name
					}
				}
			}
		}
		return firstNonEmpty(svcs[hostUID+"|"+key], key)
	}
	var out []module.IncidentInfo
	for _, p := range list {
		host, ok := hosts[p.HostUID]
		if !ok {
			continue // Host geloescht bzw. nicht (mehr) auf dieser Node
		}
		name := host
		if p.Key != "" {
			name += " · " + svcName(p.HostUID, p.Key)
		}
		state := firstNonEmpty(p.Worst, p.State)
		if p.Closed.IsZero() {
			state = p.State
		}
		if p.Key == "" {
			state = "unreachable"
		}
		if _, ok := stateRank[state]; !ok || state == "ok" {
			state = "crit"
		}
		out = append(out, module.IncidentInfo{Name: name, Path: "/monitor64/host/" + p.HostUID, StartedAt: p.Opened, EndedAt: p.Closed,
			Open: p.Closed.IsZero(), Source: "nav.monitor64", StateKey: "monitor64.state." + state, Warn: state == "warn"})
		if len(out) >= n {
			break
		}
	}
	return out
}
