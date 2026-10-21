package cdn64

import (
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
)

// Startseiten-Karte: Domains und Traffic als x / y mit Balken, Farbe und Prognose-Hinweis.
func TestCardQuotaStats(t *testing.T) {
	var q ipv64api.CDN64Quota
	q.Domains.Used, q.Domains.Limit = 1, 5
	q.TrafficMB.Limit = 100 * 1024 // 100 GB
	q.TrafficMB.Used = 400         // 0,4 GB: Balken trotzdem sichtbar
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	st := quotaStats(newOnlineQuota(q, now))
	if len(st) != 2 {
		t.Fatalf("stats: %+v", st)
	}
	d, tr := st[0], st[1]
	if d.Value != 1 || d.Max != 5 || !d.Bar || d.BarPct != 20 || d.BarClass != "bg-success" || d.Class != "" {
		t.Fatalf("domains: %+v", d)
	}
	if !tr.Bytes || tr.Value != 400<<20 || tr.Max != 100<<30 || tr.BarPct != 1 || tr.BarClass != "bg-success" || tr.HintKey != "" {
		t.Fatalf("traffic klein: %+v", tr)
	}
	q.Domains.Used = 4           // 80 %
	q.TrafficMB.Used = 50 * 1024 // halb verbraucht nach 10 von 31 Tagen: reicht nicht
	st = quotaStats(newOnlineQuota(q, now))
	if d := st[0]; d.BarClass != "bg-warning" || d.Class != "text-warning-emphasis" {
		t.Fatalf("domains 80 %%: %+v", d)
	}
	if tr := st[1]; tr.BarPct != 50 || tr.BarClass != "bg-warning" || tr.HintKey != "cdn64.online.q_short" || tr.HintDate.Day() != 21 || tr.HintBytes <= tr.Max {
		t.Fatalf("traffic Prognose: %+v", tr)
	}
	q.Domains.Used, q.TrafficMB.Used = 5, 100*1024
	st = quotaStats(newOnlineQuota(q, now))
	if st[0].BarClass != "bg-danger" || st[1].BarClass != "bg-danger" || st[1].Class != "text-danger" || st[1].BarPct != 100 {
		t.Fatalf("voll: %+v", st)
	}
	q.Domains.Limit = 0 // nicht im Tarif, aber belegt
	if d := quotaStats(newOnlineQuota(q, now))[0]; d.BarPct != 100 || d.BarClass != "bg-danger" {
		t.Fatalf("ohne Limit: %+v", d)
	}
}
