package healthchecks

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/scheduler"
	"github.com/ipv64net/node64/internal/wire"
)

// Gesamtzustand der Gruppe fuer einen Check, den diese Node mit einer anderen misst.
func TestGroupVerdict(t *testing.T) {
	m, srv := newTestModule(t)
	ctx := context.Background()
	if selfNodeID() == "" {
		_ = m.core.SetSetting(ctx, "node.id", "node-a-0123456789abcdef")
	}
	code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": "beide", "type": "icmp", "target": "192.0.2.1", "interval_seconds": 60,
		"policy": "all", "paused": true})
	if code != 201 && code != 200 {
		t.Fatalf("create: %d %s", code, b)
	}
	var cr struct{ Token string }
	_ = json.Unmarshal(b, &cr)
	c, _ := m.st.Check(ctx, cr.Token)
	w := m.WireCheck(c, nil)
	w.Nodes, w.Paused = []string{selfNodeID(), "node-b"}, false
	if ok, err := m.ApplyPeerCheck(ctx, w, time.Now().Add(time.Second), "node-b", selfNodeID()); !ok || err != nil {
		t.Fatalf("apply: %v %v", ok, err)
	}
	if c, _ = m.st.Check(ctx, cr.Token); !c.MeasuredHere() || len(c.Nodes) != 2 {
		t.Fatalf("check must be measured here by both nodes: %+v", c.Nodes)
	}
	me := true
	m.SetGroupRole(func(context.Context, []string) (bool, bool, bool) { return true, me, true })
	set := func(state scheduler.State) {
		_, _ = m.st.w.ExecContext(ctx, `UPDATE hc_checks SET state = ? WHERE token = ?`, string(state), cr.Token)
	}
	peer := func(state string) {
		_, _ = m.ApplyPeerData(ctx, "node-b", "B", []wire.State{{Token: cr.Token, State: state, LastStatus: map[string]string{"up": "up", "down": "down"}[state], LastCheckAt: time.Now().UTC()}}, nil)
	}
	got := func() scheduler.State {
		s, _ := m.groupState(ctx, cr.Token)
		return s
	}
	if m.scheduler() != nil { // eigener Zustand ueber den Scheduler: fuer den Test aus der Datenbank
		m.scheduler().Remove(cr.Token)
	}
	set(scheduler.StateUp)
	peer("up")
	c, _ = m.st.Check(ctx, cr.Token)
	m.groupVerdict(ctx, c)
	if got() != scheduler.StateUp {
		t.Fatalf("both up: %s", got())
	}
	// nur B gestoert, Regel "alle": teilweise gestoert
	peer("down")
	m.groupVerdict(ctx, c)
	if got() != scheduler.StateDegraded {
		t.Fatalf("B down: %s", got())
	}
	// meldet eine andere Node, bleibt der gemeldete Stand hier unveraendert (er kommt von ihr)
	me = false
	set(scheduler.StateDown)
	c, _ = m.st.Check(ctx, cr.Token)
	m.groupVerdict(ctx, c)
	if got() != scheduler.StateDegraded {
		t.Fatalf("other node notifies: %s", got())
	}
	m.ApplyPeerGroups(ctx, []GroupState{{Token: cr.Token, State: "down", Since: time.Now().UTC().Add(time.Second)}})
	if got() != scheduler.StateDown {
		t.Fatalf("adopted from notifying node: %s", got())
	}
	me = true
	// B nicht erreichbar: zaehlt nicht mehr, Zustand der eigenen Messung
	_, _ = m.st.w.ExecContext(ctx, `UPDATE hc_sources SET updated_at = ? WHERE token = ?`, ft(time.Now().Add(-10*time.Minute)), cr.Token)
	set(scheduler.StateUp)
	c, _ = m.st.Check(ctx, cr.Token)
	m.groupVerdict(ctx, c)
	if got() != scheduler.StateUp {
		t.Fatalf("B stale, self up: %s", got())
	}
	// keine Gruppe: nichts
	m.SetGroupRole(nil)
	set(scheduler.StateDown)
	c, _ = m.st.Check(ctx, cr.Token)
	m.groupVerdict(ctx, c)
	if got() != scheduler.StateUp {
		t.Fatalf("no group: %s", got())
	}
}

// Meldungen der Gruppe wie am hub: nach down -> teilweise gestoert -> up kommt "wieder erreichbar".
func TestGroupKind(t *testing.T) {
	type step struct {
		to   scheduler.State
		kind notify.Kind
	}
	run := func(name string, steps ...step) {
		old, open := scheduler.StatePending, false
		for i, s := range steps {
			kind, o, ok := groupKind(old, s.to, open)
			if !ok {
				kind = ""
			}
			if kind != s.kind {
				t.Errorf("%s step %d (%s -> %s): got %q want %q", name, i, old, s.to, kind, s.kind)
			}
			old, open = s.to, o
		}
	}
	run("down degraded up", step{scheduler.StateUp, ""}, step{scheduler.StateDown, notify.KindDown}, step{scheduler.StateDegraded, notify.KindDegraded}, step{scheduler.StateUp, notify.KindUp})
	run("degraded only", step{scheduler.StateUp, ""}, step{scheduler.StateDegraded, notify.KindDegraded}, step{scheduler.StateUp, notify.KindDegradedEnd})
	run("down up", step{scheduler.StateUp, ""}, step{scheduler.StateDown, notify.KindDown}, step{scheduler.StateUp, notify.KindUp})
	run("down paused up", step{scheduler.StateDown, notify.KindDown}, step{scheduler.StatePaused, ""}, step{scheduler.StateUp, notify.KindUp})
	run("flapping", step{scheduler.StateUp, ""}, step{scheduler.StateFlapping, notify.KindFlappingStart}, step{scheduler.StateUp, notify.KindFlappingEnd})
}

// Nicht geprueft: letzte Messung aelter als 3 Intervalle (mind. 5 min); pausiert und nie gemessen zaehlen nicht.
func TestStale(t *testing.T) {
	c := &Check{Interval: time.Minute}
	now := time.Now()
	cases := []struct {
		last  time.Time
		state string
		want  bool
	}{
		{now.Add(-4 * time.Minute), "up", false}, // unter 5 min
		{now.Add(-6 * time.Minute), "up", true},
		{now.Add(-16 * time.Hour), "up", true},
		{time.Time{}, "pending", false},
		{now.Add(-6 * time.Minute), "paused", false},
	}
	for i, k := range cases {
		if got := stale(c, k.last, k.state); got != k.want {
			t.Errorf("case %d: got %v want %v", i, got, k.want)
		}
	}
	c.Interval = time.Hour // 3 h Fenster
	if stale(c, now.Add(-2*time.Hour), "up") || !stale(c, now.Add(-4*time.Hour), "up") {
		t.Error("window must follow the interval")
	}
}

// Zeilenfarbe der Liste: nicht geprueft vor gestoert vor instabil/teilweise gestoert.
func TestRowClass(t *testing.T) {
	cases := map[string]row{
		"hc-row-stale": {State: "down", Stale: true},
		"hc-row-down":  {State: "down"},
		"hc-row-warn":  {State: "flapping"},
		"":             {State: "up"},
	}
	for want, r := range cases {
		if got := r.RowClass(); got != want {
			t.Errorf("%+v: got %q want %q", r.State, got, want)
		}
	}
	if (row{State: "degraded"}).RowClass() != "hc-row-warn" {
		t.Error("degraded")
	}
}
