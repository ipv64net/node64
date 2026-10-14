package healthchecks

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/wire"
)

// Check einer anderen Node der Gruppe: Zustaende und Messpunkte uebernehmen, Gesamtzustand ohne hub.
func TestPeerData(t *testing.T) {
	m, srv := newTestModule(t)
	ctx := context.Background()
	code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": "auf B", "type": "icmp", "target": "192.0.2.1", "interval_seconds": 60})
	if code != 201 && code != 200 {
		t.Fatalf("create: %d %s", code, b)
	}
	var cr struct{ Token string }
	_ = json.Unmarshal(b, &cr)
	c, _ := m.st.Check(ctx, cr.Token)
	w := m.WireCheck(c, nil)
	w.Nodes = []string{"node-b"} // B misst, diese Node (node-a) nicht
	if ok, err := m.ApplyPeerCheck(ctx, w, time.Now().Add(time.Second), "node-b", "node-a"); !ok || err != nil {
		t.Fatalf("apply check: %v %v", ok, err)
	}
	if c, _ = m.st.Check(ctx, cr.Token); c.MeasuredHere() {
		t.Fatal("check of node B must not be measured here")
	}
	t0 := time.Now().UTC().Add(-3 * time.Minute).Truncate(time.Second)
	ms := []wire.Measurement{
		{Seq: 1, Token: cr.Token, Time: t0, Status: "up", LatencyMS: 1.5},
		{Seq: 2, Token: cr.Token, Time: t0.Add(time.Minute), Status: "down", Reason: "timeout"},
		{Seq: 3, Token: "unbekannt", Time: t0, Status: "up"},
	}
	down := []wire.State{{Token: cr.Token, State: "down", LastStatus: "down", Reason: "timeout", Since: t0.Add(time.Minute), LastCheckAt: t0.Add(time.Minute)}}
	for i := 0; i < 2; i++ { // zweimal: keine doppelten Punkte
		if n, err := m.ApplyPeerData(ctx, "node-b", "Node B", down, ms); err != nil || n != 2 {
			t.Fatalf("apply data: %d %v", n, err)
		}
	}
	var pts int
	_ = m.st.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM hc_measurements WHERE token = ? AND flags = 8 AND details = 'node:node-b'`, cr.Token).Scan(&pts)
	if pts != 2 {
		t.Fatalf("points = %d, want 2", pts)
	}
	all := func([]string) bool { return true }
	m.PeerVerdicts(ctx, all)
	c, _ = m.st.Check(ctx, cr.Token)
	open := func() bool {
		list, _ := m.st.Incidents(ctx, cr.Token, 10)
		return len(list) > 0 && list[0].Open
	}
	if c.Runtime.State != "down" || !open() {
		t.Fatalf("after down: state=%s open=%v", c.Runtime.State, open())
	}
	// Node B nicht mehr erreichbar: Zustand unbekannt, Stoerung bleibt offen, letzte Messung bleibt
	_, _ = m.st.w.ExecContext(ctx, `UPDATE hc_sources SET updated_at = ? WHERE token = ?`, ft(time.Now().Add(-10*time.Minute)), cr.Token)
	m.PeerVerdicts(ctx, all)
	c, _ = m.st.Check(ctx, cr.Token)
	if c.Runtime.State != "pending" || !open() || c.Runtime.LastCheck.IsZero() {
		t.Fatalf("stale: state=%s open=%v last=%v", c.Runtime.State, open(), c.Runtime.LastCheck)
	}
	// wieder erreichbar und gesund: Stoerung endet
	up := []wire.State{{Token: cr.Token, State: "up", LastStatus: "up", Since: time.Now().UTC(), LastCheckAt: time.Now().UTC()}}
	_, _ = m.ApplyPeerData(ctx, "node-b", "Node B", up, nil)
	m.PeerVerdicts(ctx, all)
	c, _ = m.st.Check(ctx, cr.Token)
	if c.Runtime.State != "up" || open() {
		t.Fatalf("after up: state=%s open=%v", c.Runtime.State, open())
	}
	// entscheidet der hub, bleibt der Zustand unangetastet
	_, _ = m.ApplyPeerData(ctx, "node-b", "Node B", down, nil)
	m.PeerVerdicts(ctx, func([]string) bool { return false })
	if c, _ = m.st.Check(ctx, cr.Token); c.Runtime.State != "up" {
		t.Fatalf("hub decides: state=%s", c.Runtime.State)
	}
}
