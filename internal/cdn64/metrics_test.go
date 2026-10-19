package cdn64

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/metrics"
)

// Kennzahlen: je Host Zaehler, Ziel erreichbar mit Antwortzeit; CDN64 online mit Name und Kontingent.
func TestMetrics(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"app.test"}, "192.168.1.10", 8080
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	st := e.m.statsOf(h.ID)
	st.requests.Add(5)
	st.blocked.Add(2)
	e.m.reach.set(h.ID, Reach{State: ReachUp, Ms: 12, Checked: time.Now()})
	if _, err := e.m.core.Writer().ExecContext(ctx, `INSERT INTO cdn_online (name, host_id, remote_id, mode, created_at) VALUES ('app.test', ?, 7, 1, '2026-01-01T00:00:00Z')`, h.ID); err != nil {
		t.Fatal(err)
	}
	ov := &ipv64api.CDN64Overview{Hosts: []ipv64api.CDN64Host{{ID: 7, FQDN: "app.test", Mode: 1, Status: "active"}}}
	ov.Quota.Domains.Used, ov.Quota.Domains.Limit, ov.Quota.TrafficMB.Limit = 1, 5, 1024
	ov.Hosts[0].TrafficMonth.BytesIn, ov.Hosts[0].TrafficMonth.BytesOut = 100, 200
	e.m.onlineSetRemote(ov, nil)

	w := metrics.New()
	e.m.Metrics(ctx, w)
	var sb strings.Builder
	_, _ = w.WriteTo(&sb)
	out := sb.String()
	id := `host_id="` + strconv.FormatInt(h.ID, 10) + `",host="app.test",kind="proxy"`
	for _, want := range []string{
		"node64_cdn64_hosts 1",
		`node64_cdn64_host_enabled{` + id + `} 1`,
		`node64_cdn64_host_requests_total{` + id + `} 5`,
		`node64_cdn64_host_blocked_total{` + id + `} 2`,
		`node64_cdn64_host_requests_24h{` + id + `,status="2xx"} 0`,
		`node64_cdn64_host_target_up{` + id + `} 1`,
		`node64_cdn64_host_target_latency_seconds{` + id + `} 0.012`,
		`node64_cdn64_online_name{host_id="` + strconv.FormatInt(h.ID, 10) + `",name="app.test",mode="1"} 1`,
		"node64_cdn64_online_domains_limit 5",
		"node64_cdn64_online_traffic_limit_bytes 1.073741824e+09",
		`node64_cdn64_online_host_status{name="app.test",mode="1",status="active"} 1`,
		`node64_cdn64_online_host_traffic_month_bytes{name="app.test"} 300`,
		"node64_cdn64_online_sync_ok 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "node64_cdn64_online_edge_connected") { // ohne Tunnel kein Server-Zustand
		t.Errorf("edge metrics without tunnel:\n%s", out)
	}
}
