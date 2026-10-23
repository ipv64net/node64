package healthchecks

import (
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/checks"
)

func TestCheckDailyCost(t *testing.T) {
	cases := []struct {
		c       Check
		accLocs int
		want    int
	}{
		{Check{Type: checks.TypeHTTP, Execution: "online", Interval: 30 * time.Second}, 2, 5760},                           // leer = beide Standorte
		{Check{Type: checks.TypeHTTP, Execution: "both", Interval: 60 * time.Second, Locations: []string{"fsn"}}, 2, 1440}, // ein Standort
		{Check{Type: checks.TypeICMP, Execution: "online", Interval: 30 * time.Second}, 1, 2880},                           // Standard: hoechstens 1
		{Check{Type: checks.TypeHTTP, Execution: "local", Interval: 30 * time.Second}, 2, 0},                               // lokal
		{Check{Type: checks.TypePush, Execution: "online", Interval: 60 * time.Second}, 2, 0},                              // Push zaehlt beim Eingang
		{Check{Type: checks.TypeHTTP, Execution: "online", Interval: 60 * time.Second, Paused: true}, 2, 0},                // pausiert
	}
	for i, tc := range cases {
		if got := CheckDailyCost(&tc.c, tc.accLocs); got != tc.want {
			t.Errorf("case %d: got %d, want %d", i, got, tc.want)
		}
	}
}

// Mindestintervall: lokal ab 5 s (Wiederholung wird auf das Intervall gekuerzt), online und hybrid ab 20 s.
func TestIntervalMinByExecution(t *testing.T) {
	m, srv := newTestModule(t)
	m.SetLinked(func() bool { return true })
	m.SetQuota(func() (int, int, int) { return 0, 100000, 2 })
	m.SetAccount(func() (string, int) { return "Business", 100 })
	mk := func(exec string, iv int) (int, string) {
		code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": exec, "type": "http", "target": "https://example.org", "execution": exec, "interval_seconds": iv})
		return code, string(b)
	}
	if code, b := mk("local", 5); code != 201 || !strings.Contains(b, `"retry_interval_seconds":5`) {
		t.Fatalf("local 5: %d %s", code, b)
	}
	for _, ex := range []string{"online", "both"} {
		if code, b := mk(ex, 10); code != 422 || !strings.Contains(b, "interval_seconds") {
			t.Fatalf("%s 10: %d %s", ex, code, b)
		}
		if code, b := mk(ex, 20); code != 201 {
			t.Fatalf("%s 20: %d %s", ex, code, b)
		}
	}
}

// Karte Tageskontingent: Hochrechnung bis Mitternacht (Europe/Berlin), Zeitpunkt des Erreichens, erreicht.
func TestHCQuotaCard(t *testing.T) {
	now := time.Date(2026, 10, 23, 10, 0, 0, 0, quotaZone) // 14 h bis Mitternacht
	q := newHCQuota(1000, 10000, 8640, now)                // 0,1 je Sekunde -> 5040 bis Mitternacht
	if q.Short || q.Reached || q.Tomorrow || q.AtMidnight != 6040 || q.Pct != 10 {
		t.Fatalf("ok: %+v", q)
	}
	q = newHCQuota(1000, 2000, 8640, now) // 1000 frei bei 0,1/s -> nach 10000 s
	if !q.Short || !q.Tomorrow || !q.EmptyAt.Equal(now.Add(10000*time.Second)) || q.Class != "bg-warning" {
		t.Fatalf("short: %+v", q)
	}
	q = newHCQuota(2000, 2000, 8640, now)
	if !q.Reached || q.Short || q.Pct != 100 || !q.ResetAt.Equal(time.Date(2026, 10, 24, 0, 0, 0, 0, quotaZone)) {
		t.Fatalf("reached: %+v", q)
	}
	if q = newHCQuota(0, 1000, 0, now); q.Short || q.Bar != 0 || q.AtMidnight != 0 {
		t.Fatalf("none: %+v", q)
	}
}
