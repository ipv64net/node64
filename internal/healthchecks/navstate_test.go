package healthchecks

import (
	"context"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/scheduler"
)

// Punkt neben "Healthchecks": gruen, gelb (eingeschraenkt), rot (gestoert); Wartung und pausiert zaehlen nicht.
func TestNavState(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	m, _ := newStatusModule(t)
	if got := m.navState(ctx, now); got != "" {
		t.Fatalf("ohne Checks: %q", got)
	}
	statusAddCheck(t, m, "A", scheduler.Runtime{State: scheduler.StateUp, LastCheck: now})
	statusAddCheck(t, m, "neu", scheduler.Runtime{State: scheduler.StatePending})
	if got := m.navState(ctx, now); got != module.NavOK {
		t.Fatalf("alles ok: %q", got)
	}
	statusAddCheck(t, m, "B", scheduler.Runtime{State: scheduler.StateDegraded, LastCheck: now})
	if got := m.navState(ctx, now); got != module.NavWarn {
		t.Fatalf("eingeschraenkt: %q", got)
	}
	c := statusAddCheck(t, m, "C", scheduler.Runtime{State: scheduler.StateDown, LastCheck: now})
	if got := m.navState(ctx, now); got != module.NavCrit {
		t.Fatalf("gestoert: %q", got)
	}
	// Wartung: der gestoerte Check zaehlt nicht
	if err := m.st.MaintenanceInsert(ctx, &Maintenance{Name: "Umbau", StartAt: now.Add(-time.Hour), EndAt: now.Add(time.Hour), Tokens: []string{c.Token}, Active: true}); err != nil {
		t.Fatal(err)
	}
	if got := m.navState(ctx, now); got != module.NavWarn {
		t.Fatalf("gestoert in Wartung: %q", got)
	}
	// Zwischenstand: NavState rechnet hoechstens alle navStateEvery neu
	if a, b := m.NavState(), m.NavState(); a != b || a == "" {
		t.Fatalf("NavState: %q %q", a, b)
	}
}
