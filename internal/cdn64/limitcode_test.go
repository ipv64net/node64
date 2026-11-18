package cdn64

import (
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
)

var testNowQuota = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

// limit_reached mit Angabe der Grenze: eigener Text je Art (vorher hiess jede Grenze "CDN-Domains belegt").
func TestOnlineCodeLimit(t *testing.T) {
	for _, c := range []struct{ limit, want string }{
		{"domains", "limit_reached_domains"}, {"subdomains", "limit_reached_subdomains"}, {"mappings", "limit_reached_mappings"},
		{"tunnels", "limit_reached_tunnels"}, {"", "limit_reached"}, {"sonstwas", "limit_reached"},
	} {
		if got := onlineCode(&ipv64api.APIError{Status: 403, Code: "limit_reached", Limit: c.limit}); got != c.want {
			t.Errorf("%q: %q, want %q", c.limit, got, c.want)
		}
	}
}

// Startseiten-Karte mit Subdomains: x / y mit Balken, unbegrenzt nur die Zahl.
func TestCardQuotaSubdomains(t *testing.T) {
	var q ipv64api.CDN64Quota
	q.Domains.Used, q.Domains.Limit = 1, 5
	q.TrafficMB.Limit = 1024
	q.Subdomains = &struct {
		Used  int `json:"used"`
		Limit int `json:"limit"`
	}{Used: 4, Limit: 5}
	st := quotaStats(newOnlineQuota(q, testNowQuota))
	if len(st) != 3 || st[1].LabelKey != "cdn64.online.q_subdomains" || st[1].Value != 4 || st[1].Max != 5 || st[1].BarClass != "bg-warning" {
		t.Fatalf("subdomains: %+v", st)
	}
	q.Subdomains.Limit = -1
	st = quotaStats(newOnlineQuota(q, testNowQuota))
	if s := st[1]; s.Value != 4 || s.Max != 0 || s.Bar {
		t.Fatalf("unbegrenzt: %+v", s)
	}
}
