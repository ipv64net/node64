package checker

import (
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/hub/store"
	"github.com/ipv64net/node64/internal/scheduler"
)

// Ping: gesendete und verlorene Pakete aus den Details (v4 und v6 zusammen), Ergebnis aus dem Messpunkt.
func TestObservePing(t *testing.T) {
	c := &Checker{st: &store.Store{Metrics: store.NewMetrics()}}
	ck := scheduler.Check{Def: checks.Definition{Type: checks.TypeICMP}}
	c.observe(ck, scheduler.Measurement{Status: checks.Down, Results: []checks.Result{
		{Details: map[string]any{"sent": 3, "received": 3}},
		{Details: map[string]any{"sent": 3, "received": 1}},
	}}, time.Second)
	c.observe(scheduler.Check{Def: checks.Definition{Type: checks.TypeHTTP}}, scheduler.Measurement{Status: checks.Up}, time.Second)
	d := c.st.Metrics.Detail()
	if d.PingSent != 6 || d.PingLost != 2 || d.Runs["icmp"].Fail != 1 || d.Runs["http"].OK != 1 {
		t.Fatalf("falsch gezaehlt: %+v", d)
	}
}
