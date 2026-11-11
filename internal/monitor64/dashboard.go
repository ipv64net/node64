package monitor64

import (
	"context"
	"sort"

	"github.com/ipv64net/node64/internal/module"
)

// Dashboard des Kerns: kleine Karte mit Kennzahlen (module.CardProvider) und die Probleme in der gemeinsamen Liste
// "Letzte Stoerungen" mit den Healthchecks (module.IncidentProvider).

// Card liefert die Dashboard-Karte: Hosts, Dienste, offene Probleme nach Zustand, Wartung, letzte Stoerung.
func (m *Module) Card(ctx context.Context) (*module.Card, error) {
	c := &module.Card{TitleKey: "nav.monitor64", Icon: "bi-activity", Image: "monitor64.svg", Path: "/monitor64"}
	d := m.overview(ctx)
	var crit, warn, unknown int64
	for _, p := range d.Problems {
		switch {
		case p.Unreach:
		case p.State == "crit":
			crit++
		case p.State == "warn":
			warn++
		default:
			unknown++
		}
	}
	var maint, paused int64
	for _, h := range d.Hosts {
		if h.Maint != nil {
			maint++
		}
		if h.Paused {
			paused++
		}
	}
	red := func(n int64) string {
		if n > 0 {
			return "text-danger"
		}
		return ""
	}
	c.Stats = []module.CardStat{
		{LabelKey: "monitor64.card.hosts", Value: int64(len(d.Hosts))},
		{LabelKey: "monitor64.card.services", Value: int64(d.Services)},
		{LabelKey: "monitor64.card.unreachable", Value: int64(d.Unreachable), Class: red(int64(d.Unreachable))},
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
