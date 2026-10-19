package dyndns

import (
	"context"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/metrics"
)

func TestMetrics(t *testing.T) {
	ctx := context.Background()
	m, _ := newTargetModule(t, true)
	for _, tg := range []*Target{
		{Domain: "home.ipv64.net", Host: "nas", TokenKind: "record", Token: tokA, Mode4: Mode4Auto, Mode6: Mode6Off, Enabled: true},
		{Domain: "home.ipv64.net", Host: "aus", TokenKind: "record", Token: tokAAAA, Mode4: Mode4Auto, Mode6: Mode6Off},
	} {
		if err := m.InsertTarget(ctx, tg); err != nil {
			t.Fatal(err)
		}
	}
	w := metrics.New()
	m.Metrics(ctx, w)
	var sb strings.Builder
	_, _ = w.WriteTo(&sb)
	out := sb.String()
	for _, want := range []string{
		`node64_dyndns_target_status{target="nas.home.ipv64.net",status="new"} 1`,
		`node64_dyndns_target_status{target="aus.home.ipv64.net",status="off"} 1`,
		`node64_dyndns_targets{status="new"} 1`,
		`node64_dyndns_targets{status="off"} 1`,
		"node64_dyndns_updates_24h 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "node64_dyndns_target_ok") { // nur fuer aktive Ziele mit Ergebnis
		t.Errorf("unexpected _ok:\n%s", out)
	}
}
