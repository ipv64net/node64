package healthchecks

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// hub-Daten, weitergereicht von einer verknuepften Node der Gruppe, fuer einen Check, den kein Mitglied misst.
func TestPeerRelay(t *testing.T) {
	m, srv := newTestModule(t)
	ctx := context.Background()
	code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": "Pi misst", "type": "icmp", "target": "192.0.2.1", "interval_seconds": 60})
	if code != 201 && code != 200 {
		t.Fatalf("create: %d %s", code, b)
	}
	var cr struct{ Token string }
	_ = json.Unmarshal(b, &cr)
	c, _ := m.st.Check(ctx, cr.Token)
	w := m.WireCheck(c, nil)
	w.Nodes, w.Execution, w.Locations = []string{"node-pi"}, "both", []string{"fsn"}
	if ok, err := m.ApplyPeerCheck(ctx, w, time.Now().Add(time.Second), "node-b", "node-a"); !ok || err != nil {
		t.Fatalf("apply check: %v %v", ok, err)
	}
	t0 := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Second)
	states := []RelayState{{Token: cr.Token, State: "down", Since: t0, LastCheck: t0, Status: "down", Reason: "timeout",
		Sources: []RelaySource{{Source: "loc:fsn", Label: "Falkenstein", State: "down", LastCheck: t0, Status: "down", UpdatedAt: time.Now()}}}}
	pts := []RelayPoint{{Token: cr.Token, Source: "loc:fsn", Time: t0, Status: 0}, {Token: cr.Token, Source: "node:node-pi", Time: t0, Status: 0}}
	// wie im Betrieb fragt overall die Datenbank (Schreibverbindung); haengt das, haengt die Node
	all := func([]string) bool {
		qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		var x int
		if err := m.st.w.QueryRowContext(qctx, `SELECT 1`).Scan(&x); err != nil {
			t.Errorf("overall must not wait for the database: %v", err)
		}
		return true
	}
	for i := 0; i < 2; i++ { // zweimal: keine doppelten Punkte
		if n, err := m.ApplyPeerRelay(ctx, states, pts, all); err != nil || n != 2 {
			t.Fatalf("apply relay: %d %v", n, err)
		}
	}
	var n int
	_ = m.st.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM hc_measurements WHERE token = ? AND flags = 8`, cr.Token).Scan(&n)
	if n != 2 {
		t.Fatalf("points = %d", n)
	}
	c, _ = m.st.Check(ctx, cr.Token)
	list, _ := m.st.Incidents(ctx, cr.Token, 10)
	if c.Runtime.State != "down" || len(list) != 1 || !list[0].Open {
		t.Fatalf("state %s incidents %+v", c.Runtime.State, list)
	}
	if rows := m.sources(ctx, c, "self"); len(rows) == 0 || rows[0].Source != "loc:fsn" {
		t.Fatalf("sources: %+v", rows)
	}
	// misst eine Node der Gruppe mit, bestimmt die Gruppe den Gesamtzustand: weitergereichter bleibt aussen vor
	states[0].State = "up"
	_, _ = m.ApplyPeerRelay(ctx, states, nil, func([]string) bool { return false })
	if c, _ = m.st.Check(ctx, cr.Token); c.Runtime.State != "down" {
		t.Fatalf("group decides, state must stay: %s", c.Runtime.State)
	}
}
