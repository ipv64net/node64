package web

import (
	"testing"

	"github.com/ipv64net/node64/internal/i18n"
)

func TestPlanValueUnits(t *testing.T) {
	bundle, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	v := &View{s: &Server{Deps: Deps{I18n: bundle}}, Lang: "de"}
	n := func(x int) *int { return &x }
	cases := map[string][2]any{"cdn_traffic_gb": {n(100), "100 GB"}, "vpn_traffic_gb": {n(20480), "20 TB"}, "cdn_bandwidth_mbit": {n(1000), "1 Gbit/s"},
		"dyndns_ttl_s": {n(60), "60 s"}, "log_days": {n(14), "14 Tage"}, "own_domains": {n(0), "–"}, "sms_24h": {(*int)(nil), "∞"}}
	for k, c := range cases {
		if got := planValue(v, k, c[0].(*int)); got != c[1] {
			t.Errorf("%s: %q, want %q", k, got, c[1])
		}
	}
}
