package cdn64

import (
	"context"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/metrics"
)

// Metrics liefert die Kennzahlen von CDN64 fuer GET /api/metrics (module.MetricsProvider): je Host Zaehler seit dem
// Start, Zahlen der letzten 24 Stunden (wie die Dashboard-Karte), Erreichbarkeit des Ziels; CDN64 online mit
// eingeschalteten Namen, Tunnel je Server und Kontingent (letzter Abgleich mit ipv64, keine Abfrage dort).
func (m *Module) Metrics(ctx context.Context, w *metrics.Writer) {
	list, err := m.hosts(ctx)
	if err != nil {
		return
	}
	var day map[int64]HostStat
	if sdb := m.stats2.Load(); sdb != nil {
		day, _ = sdb.sums(ctx, time.Now().Add(-24*time.Hour))
	}
	w.Gauge("node64_cdn64_hosts", "Hosts (proxy, redirect, 404, passthrough)", float64(len(list)))
	if hs := m.hpSettings(); hs.Decoy || hs.Access || hs.Block { // Honeypot64 (honeypot.go), nur wenn ein Punkt an ist
		w.Gauge("node64_cdn64_honeypot_blocks", "IPs blocked right now because the honeypot reported them", float64(len(m.hpList())))
		w.Counter("node64_cdn64_honeypot_rejected_total", "Connections and requests rejected because of a honeypot block since node start", float64(m.hp.rejected.Load()))
		w.Counter("node64_cdn64_honeypot_blocks_total", "Honeypot blocks taken over since node start", float64(m.hp.added.Load()))
		w.Counter("node64_cdn64_honeypot_decoy_total", "Requests without a matching host handed to the honeypot decoy since node start", float64(m.hp.decoyed.Load()))
		w.Counter("node64_cdn64_honeypot_reported_total", "Accesses handed to the honeypot log sensor since node start", float64(m.hp.reported.Load()))
	}
	for _, h := range list {
		name := ""
		if len(h.Names) > 0 {
			name = h.Names[0]
		}
		l := []string{"host_id", strconv.FormatInt(h.ID, 10), "host", name, "kind", h.Kind}
		w.Gauge("node64_cdn64_host_enabled", "1 host enabled, 0 disabled", metrics.Bool(h.Enabled), l...)
		st := m.statsOf(h.ID)
		w.Counter("node64_cdn64_host_requests_total", "Requests since node start", float64(st.requests.Load()), l...)
		w.Counter("node64_cdn64_host_errors_total", "5xx answers and unreachable target since node start", float64(st.errors.Load()), l...)
		w.Counter("node64_cdn64_host_blocked_total", "Rejected (exploits, blocklists, limits) since node start", float64(st.blocked.Load()), l...)
		d := day[h.ID]
		for _, s := range []struct {
			class string
			n     int64
		}{{"2xx", d.S2}, {"3xx", d.S3}, {"4xx", d.S4}, {"5xx", d.S5}} {
			w.Gauge("node64_cdn64_host_requests_24h", "Requests in the last 24 hours by status class", float64(s.n), append(l, "status", s.class)...)
		}
		w.Gauge("node64_cdn64_host_bytes_24h", "Bytes sent in the last 24 hours", float64(d.Bytes), l...)
		w.Gauge("node64_cdn64_host_blocked_24h", "Rejected in the last 24 hours", float64(d.Blocked), l...)
		if h.probed() {
			switch r := m.reach.get(h.ID); r.State {
			case ReachUp, ReachSlow:
				w.Gauge("node64_cdn64_host_target_up", "1 target reachable, 0 not (last check)", 1, l...)
				w.Gauge("node64_cdn64_host_target_latency_seconds", "Connect time to the target (last check)", float64(r.Ms)/1000, l...)
			case ReachDown:
				w.Gauge("node64_cdn64_host_target_up", "1 target reachable, 0 not (last check)", 0, l...)
			}
		}
	}
	m.onlineMetrics(ctx, w)
}

// onlineMetrics: CDN64 online (nur, wenn eingerichtet).
func (m *Module) onlineMetrics(ctx context.Context, w *metrics.Writer) {
	if names, err := m.onlineNames(ctx); err == nil {
		for _, x := range names {
			w.Gauge("node64_cdn64_online_name", "Name switched on at srv07/srv08 (always 1, mode in the label)", 1,
				"host_id", strconv.FormatInt(x.HostID, 10), "name", x.Name, "mode", strconv.Itoa(x.Mode))
		}
	}
	m.online.mu.Lock()
	cl := m.online.client
	m.online.mu.Unlock()
	if cl != nil {
		for _, e := range cl.Status() {
			w.Gauge("node64_cdn64_online_edge_connected", "1 tunnel to this server connected, 0 not", metrics.Bool(e.Connected), "edge", e.Name)
			if e.Connected {
				w.Gauge("node64_cdn64_online_edge_rtt_seconds", "Round trip time of the tunnel", e.RTTms/1000, "edge", e.Name, "transport", e.Transport)
				w.Gauge("node64_cdn64_online_edge_streams", "Open visitor streams through the tunnel", float64(e.Streams), "edge", e.Name)
			}
			w.Counter("node64_cdn64_online_edge_streams_total", "Visitor streams since node start", float64(e.Total), "edge", e.Name)
			w.Counter("node64_cdn64_online_edge_reconnects_total", "Tunnel reconnects since node start", float64(e.Reconnects), "edge", e.Name)
		}
	}
	r := m.online.remote.Load()
	if r == nil || r.Data == nil {
		return
	}
	w.Gauge("node64_cdn64_online_last_sync_seconds", "Last sync with ipv64 (Unix time)", float64(r.At.Unix()))
	w.Gauge("node64_cdn64_online_sync_ok", "1 last sync with ipv64 ok, 0 error", metrics.Bool(r.Err == ""))
	q := r.Data.Quota
	w.Gauge("node64_cdn64_online_domains_used", "CDN domains used by the account (old CDN included)", float64(q.Domains.Used))
	w.Gauge("node64_cdn64_online_domains_limit", "CDN domains allowed by the account class", float64(q.Domains.Limit))
	w.Gauge("node64_cdn64_online_traffic_used_bytes", "CDN traffic of the account this month", q.TrafficMB.Used*1048576)
	w.Gauge("node64_cdn64_online_traffic_limit_bytes", "CDN traffic allowed per month", float64(q.TrafficMB.Limit)*1048576)
	for _, h := range r.Data.Hosts {
		w.Gauge("node64_cdn64_online_host_status", "State at ipv64 (always 1, state in the label: active, pending, blocked)", 1,
			"name", h.FQDN, "mode", strconv.Itoa(h.Mode), "status", h.Status)
		w.Gauge("node64_cdn64_online_host_traffic_month_bytes", "Traffic through srv07/srv08 this month (in + out)",
			float64(h.TrafficMonth.BytesIn+h.TrafficMonth.BytesOut), "name", h.FQDN)
	}
}
