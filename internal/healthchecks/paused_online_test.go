package healthchecks

import (
	"context"
	"testing"

	"github.com/ipv64net/node64/internal/scheduler"
)

// TestPausedOnlineCheckShowsPaused: eine pausierte Kopie eines Online-Checks laeuft nicht im lokalen Scheduler und hat
// den Zustand "pending" – Liste und Dashboard zeigen sie trotzdem als pausiert, nicht als "Wartet".
func TestPausedOnlineCheckShowsPaused(t *testing.T) {
	m, _ := newStatusModule(t)
	c := statusAddCheck(t, m, "CDN09", scheduler.Runtime{State: "pending"})
	c.Execution, c.Owner, c.Paused = "online", "online", true
	if _, err := m.st.w.Exec(`UPDATE hc_checks SET execution = 'online', owner = 'online', paused = 1, state = 'pending' WHERE token = ?`, c.Token); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	nc, err := m.st.Check(ctx, c.Token)
	if err != nil {
		t.Fatal(err)
	}
	if r := m.rowOf(ctx, "de", nc, nil); r.State != "paused" {
		t.Fatalf("row state = %q, want paused", r.State)
	}
	info, err := m.Dashboard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Paused != 1 || info.Other != 0 {
		t.Fatalf("dashboard paused=%d other=%d, want 1/0", info.Paused, info.Other)
	}
}
