package dns64

import (
	"context"
	"sort"

	"github.com/ipv64net/node64/internal/dns64/querylog"
	"github.com/ipv64net/node64/internal/metrics"
)

// Metrics: Kennzahlen fuer GET /api/metrics (Prometheus). Zaehler laufen seit dem letzten Start des
// DNS-Servers (Aenderungen an den Einstellungen starten ihn neu, rate() kommt damit zurecht).
func (m *Module) Metrics(ctx context.Context, w *metrics.Writer) {
	e := m.running()
	w.Gauge("node64_dns64_up", "DNS-Server laeuft.", metrics.Bool(e != nil))
	if e == nil {
		return
	}
	w.Gauge("node64_dns64_start_time_seconds", "Start des DNS-Servers (Unix-Zeit).", float64(e.started.Unix()))
	w.Gauge("node64_dns64_blocking_paused", "Blockieren pausiert.", metrics.Bool(m.pauseState().Active))

	c := e.store.Counters()
	keys := make([]querylog.CountKey, 0, len(c.Queries))
	for k := range c.Queries {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Status != keys[j].Status {
			return keys[i].Status < keys[j].Status
		}
		return keys[i].Proto < keys[j].Proto
	})
	for _, k := range keys {
		v := c.Queries[k]
		proto := k.Proto
		if proto == "" {
			proto = "udp"
		}
		w.Counter("node64_dns64_queries_total", "Anfragen je Ergebnis (allowed, cached, blocked, local, error, custom) und Protokoll.", float64(v),
			"status", k.Status.String(), "proto", proto)
	}
	gkeys := make([]querylog.GroupCountKey, 0, len(c.Groups))
	for k := range c.Groups {
		gkeys = append(gkeys, k)
	}
	sort.Slice(gkeys, func(i, j int) bool {
		if gkeys[i].Group != gkeys[j].Group {
			return gkeys[i].Group < gkeys[j].Group
		}
		return gkeys[i].Status < gkeys[j].Status
	})
	for _, k := range gkeys {
		w.Counter("node64_dns64_group_queries_total", "Anfragen je Geraetegruppe und Ergebnis.", float64(c.Groups[k]), "group", k.Group, "status", k.Status.String())
	}
	if list, err := m.Groups(ctx); err == nil {
		states := m.groupStates()
		for _, g := range list {
			st := states[g.ID]
			w.Gauge("node64_dns64_group_internet_off", "Internet aus fuer die Gruppe (Knopf oder Zeitplan).", metrics.Bool(st.Off), "group", g.Name)
			w.Gauge("node64_dns64_group_free", "Knopf Frei aktiv (Zeitplaene und Kategorien ausgesetzt).", metrics.Bool(st.Free), "group", g.Name)
			w.Gauge("node64_dns64_group_members", "Eintraege (MAC, IP, Netz) der Gruppe.", float64(len(g.Members)), "group", g.Name)
		}
	}
	w.Counter("node64_dns64_query_duration_seconds_sum", "Summe der Antwortzeiten.", c.Duration.Seconds())
	w.Counter("node64_dns64_query_duration_seconds_count", "Anzahl Antworten in der Summe.", float64(c.Answered))
	w.Counter("node64_dns64_querylog_dropped_total", "Nicht ins Abfrage-Log geschriebene Eintraege (Puffer voll).", float64(c.Dropped))
	w.Counter("node64_dns64_refused_total", "Abgewiesene Anfragen von ausserhalb der erlaubten Netze.", float64(e.srv.Refused().Count))

	if e.lists != nil {
		w.Gauge("node64_dns64_blocklist_domains", "Domains in den geladenen Blocklisten.", float64(e.lists.Matcher().Size()))
	}
	if e.cache != nil {
		cs := e.cache.Stats()
		w.Gauge("node64_dns64_cache_entries", "Eintraege im Cache.", float64(cs.Entries))
		w.Gauge("node64_dns64_cache_max_entries", "Groesse des Caches.", float64(cs.Max))
		w.Counter("node64_dns64_cache_hits_total", "Treffer im Cache.", float64(cs.Hits))
		w.Counter("node64_dns64_cache_misses_total", "Fehlschlaege im Cache.", float64(cs.Misses))
		w.Counter("node64_dns64_cache_stale_served_total", "Abgelaufene Eintraege ausgeliefert (serve stale).", float64(cs.StaleServed))
	}
	if e.up != nil {
		for _, u := range e.up.Stats() {
			name := u.Name
			if name == "" {
				name = u.URL
			}
			l := []string{"upstream", name, "proto", u.Proto}
			w.Gauge("node64_dns64_upstream_up", "Upstream gesund.", metrics.Bool(u.Healthy), l...)
			w.Counter("node64_dns64_upstream_requests_total", "Anfragen an den Upstream.", float64(u.Requests), l...)
			w.Counter("node64_dns64_upstream_errors_total", "Fehler des Upstreams.", float64(u.Errors), l...)
			w.Gauge("node64_dns64_upstream_latency_seconds", "Mittlere Antwortzeit des Upstreams.", u.AvgMs/1000, l...)
		}
	}
}
