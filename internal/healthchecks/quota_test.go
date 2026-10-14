package healthchecks

import (
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
