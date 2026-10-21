package web

import (
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/ipv64net/node64/internal/metrics"
	"github.com/ipv64net/node64/internal/module"
)

// apiMetrics: Kennzahlen von Kern und laufenden Modulen im Textformat von Prometheus (docs/PROMETHEUS.md).
// Auth wie die uebrige API (API-Key als Bearer-Token oder Sitzung).
func (s *Server) apiMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()
	m := metrics.New()

	host, _ := os.Hostname()
	m.Gauge("node64_info", "Node64-Version und Name dieser Node (Wert immer 1).", 1, "version", s.Version,
		"node_id", s.Store.SettingOr(ctx, SettingNodeID, ""), "node_name", s.Store.SettingOr(ctx, SettingNodeName, ""), "hostname", host)
	m.Gauge("node64_start_time_seconds", "Startzeit des Prozesses (Unix-Zeit).", float64(s.StartedAt.Unix()))
	m.Gauge("node64_uptime_seconds", "Laufzeit seit dem Start.", time.Since(s.StartedAt).Seconds())
	m.Gauge("node64_database_bytes", "Groesse der Datenbank inkl. WAL.", float64(s.Store.Size()))

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m.Gauge("go_goroutines", "Anzahl Goroutinen.", float64(runtime.NumGoroutine()))
	m.Gauge("go_memstats_heap_alloc_bytes", "Belegter Heap.", float64(ms.HeapAlloc))
	m.Gauge("go_memstats_sys_bytes", "Vom Betriebssystem bezogener Speicher.", float64(ms.Sys))
	m.Counter("go_gc_cycles_total", "Abgeschlossene GC-Laeufe.", float64(ms.NumGC))

	for _, st := range s.Modules.List(ctx) {
		if !st.Info.Available {
			continue
		}
		m.Gauge("node64_module_enabled", "Modul in den Einstellungen eingeschaltet.", metrics.Bool(st.Enabled), "module", st.Info.Name)
		m.Gauge("node64_module_running", "Modul laeuft.", metrics.Bool(st.Running), "module", st.Info.Name)
		m.Gauge("node64_module_error", "Modul meldet einen Fehler (last_error gesetzt).", metrics.Bool(st.LastError != ""), "module", st.Info.Name)
		if st.Info.Version != "" {
			m.Gauge("node64_module_info", "Version des Moduls (Wert immer 1).", 1, "module", st.Info.Name, "version", st.Info.Version)
		}
	}

	if s.Sync != nil {
		st := s.Sync.State()
		m.Gauge("node64_link_linked", "Node mit einem ipv64.net-Konto verknuepft.", metrics.Bool(st.Linked))
		m.Gauge("node64_link_connected", "Verbindung zum ipv64.net-Hub steht.", metrics.Bool(st.Connected))
		m.Gauge("node64_link_outbox", "Noch nicht an den Hub uebertragene Eintraege.", float64(st.Outbox))
		m.Gauge("node64_link_conflicts", "Offene Sync-Konflikte.", float64(st.Conflicts))
		if t, err := time.Parse(time.RFC3339, st.LastSyncAt); err == nil {
			m.Gauge("node64_link_last_sync_seconds", "Letzter erfolgreicher Abgleich mit dem Hub (Unix-Zeit).", float64(t.Unix()))
		}
		if st.Linked {
			m.Gauge("node64_link_online_checks_today", "Heute verbrauchte Online-Messungen.", float64(st.ChecksToday))
			m.Gauge("node64_link_online_checks_limit", "Tageslimit Online-Messungen (0 = keins).", float64(st.ChecksLimit))
		}
	}

	if s.Peer != nil {
		if list, err := s.Peer.Members(ctx); err == nil {
			online := 0
			for _, x := range list {
				if x.Online() {
					online++
				}
				m.Gauge("node64_group_member_up", "Mitglied der lokalen Gruppe erreichbar.", metrics.Bool(x.Online()), "node_id", x.NodeID, "node_name", x.Name)
			}
			m.Gauge("node64_group_members", "Mitglieder der lokalen Gruppe (ohne diese Node).", float64(len(list)))
			m.Gauge("node64_group_members_online", "Erreichbare Mitglieder der lokalen Gruppe.", float64(online))
		}
	}

	if s.Certs != nil {
		s.Certs.Metrics(ctx, m)
	}

	for _, mod := range s.Modules.Modules() {
		if p, ok := mod.(module.MetricsProvider); ok && s.Modules.IsRunning(mod.Info().Name) {
			p.Metrics(ctx, m)
		}
	}

	m.Gauge("node64_mcp_enabled", "MCP-Schnittstelle (KI-Anwendungen) eingeschaltet.", metrics.Bool(s.mcpEnabled(ctx)))
	for _, c := range s.mcpCounter.Snapshot() {
		m.Counter("node64_mcp_calls_total", "Werkzeugaufrufe ueber die MCP-Schnittstelle seit dem Start.", float64(c.Count), "tool", c.Tool, "result", c.Result)
	}

	m.Gauge("node64_scrape_duration_seconds", "Dauer dieser Abfrage.", time.Since(start).Seconds())
	w.Header().Set("Content-Type", metrics.ContentType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = m.WriteTo(w)
}
