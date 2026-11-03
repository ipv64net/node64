package healthchecks

import (
	"context"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/scheduler"
)

// TestIPv64GapKeepsLastState: liefert ipv64 keine Daten (hub ohne Datenbank, keine Sitzung), bleiben Online-Checks
// beim letzten Zustand mit Hinweis statt "nicht ueberwacht"; lange nach dem Ausfall und bei hier gemessenen Checks
// gilt wieder "nicht ueberwacht".
func TestIPv64GapKeepsLastState(t *testing.T) {
	m, _ := newStatusModule(t)
	ctx := context.Background()
	last := time.Now().Add(-20 * time.Minute)
	on := statusAddCheck(t, m, "online", scheduler.Runtime{State: "up", LastCheck: last})
	if _, err := m.st.w.Exec(`UPDATE hc_checks SET execution = 'online', owner = 'online' WHERE token = ?`, on.Token); err != nil {
		t.Fatal(err)
	}
	local := statusAddCheck(t, m, "local", scheduler.Runtime{State: "up", LastCheck: last})
	oc, _ := m.st.Check(ctx, on.Token)
	lc, _ := m.st.Check(ctx, local.Token)

	// ohne Ausfall: beide nicht ueberwacht
	if r := m.rowOf(ctx, "de", oc, nil); r.State != "unchecked" || r.Delayed {
		t.Fatalf("no outage: state=%q delayed=%v", r.State, r.Delayed)
	}
	var down bool
	var at time.Time
	m.SetIPv64Outage(func() (bool, time.Time) { return down, at })

	down, at = true, time.Now()
	r := m.rowOf(ctx, "de", oc, nil)
	if r.State != "up" || r.Stale || !r.Delayed {
		t.Fatalf("outage: state=%q stale=%v delayed=%v, want up/false/true", r.State, r.Stale, r.Delayed)
	}
	if m.unchecked(oc, last, "up", time.Now()) {
		t.Fatal("outage: online check counted as unchecked")
	}
	if r := m.rowOf(ctx, "de", lc, nil); r.State != "unchecked" || r.Delayed {
		t.Fatalf("outage, local check: state=%q delayed=%v", r.State, r.Delayed)
	}
	info, err := m.Dashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Unchecked != 1 || info.OK != 1 {
		t.Fatalf("dashboard unchecked=%d ok=%d, want 1/1", info.Unchecked, info.OK)
	}

	// Ausfall kurz vorbei: Ergebnisse kommen noch nach
	down, at = false, time.Now().Add(-2*time.Minute)
	if r := m.rowOf(ctx, "de", oc, nil); !r.Delayed {
		t.Fatal("shortly after outage: want delayed")
	}
	// Ausfall lange vorbei: wirklich nicht ueberwacht
	at = time.Now().Add(-time.Hour)
	if r := m.rowOf(ctx, "de", oc, nil); r.State != "unchecked" || r.Delayed {
		t.Fatalf("old outage: state=%q delayed=%v", r.State, r.Delayed)
	}
}
