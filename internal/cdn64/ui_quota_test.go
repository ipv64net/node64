package cdn64

import (
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
)

// Kontingent: Fuellstand und Prognose (linear, ab dem zweiten Tag).
func TestOnlineQuotaForecast(t *testing.T) {
	var q ipv64api.CDN64Quota
	q.Domains.Used, q.Domains.Limit = 1, 5
	q.TrafficMB.Limit = 10 * 1024                        // 10 GB
	q.TrafficMB.Used = 5 * 1024                          // 5 GB
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC) // 10 von 31 Tagen vorbei
	o := newOnlineQuota(q, now)
	if o.DomPct != 20 || o.TrafficPct != 50 || !o.Short || o.EmptyAt.Day() != 21 {
		t.Fatalf("forecast short: %+v", o)
	}
	q.TrafficMB.Used = 1024 // 1 GB in 10 Tagen -> 3,1 GB im Monat
	if o := newOnlineQuota(q, now); o.Short || o.Projected/(1<<20) != 3174 {
		t.Fatalf("forecast ok: %+v", o)
	}
	if o := newOnlineQuota(q, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)); o.Projected != 0 {
		t.Fatal("no forecast on the first day")
	}
}

// Subdomains (seit 2026-11-17): aelteres ipv64 ohne Feld zeigt nichts, -1 = unbegrenzt.
func TestOnlineQuotaSubdomains(t *testing.T) {
	var q ipv64api.CDN64Quota
	now := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	if o := newOnlineQuota(q, now); o.HasSub {
		t.Fatal("subdomains shown without the field")
	}
	q.Subdomains = &struct {
		Used  int `json:"used"`
		Limit int `json:"limit"`
	}{Used: 3, Limit: -1}
	if o := newOnlineQuota(q, now); !o.HasSub || o.Sub != 3 || o.SubLimit != -1 {
		t.Fatalf("subdomains: %+v", o)
	}
}
