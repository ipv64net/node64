package peer

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/wire"
)

// fakeData ergaenzt fakeChecks um eigene Messpunkte und Zustaende (wie das Healthchecks-Modul).
type fakeData struct {
	*fakeChecks
	ms     []wire.Measurement
	states []wire.State
}

func (f *fakeData) PeerMeasurements(_ context.Context, since int64, limit int) ([]wire.Measurement, int64, bool, error) {
	var out []wire.Measurement
	last := since
	for _, x := range f.ms {
		if x.Seq > since && len(out) < limit {
			out, last = append(out, x), x.Seq
		}
	}
	return out, last, len(out) == limit, nil
}
func (f *fakeData) PeerStartSeq(context.Context, time.Time) int64 { return 0 }
func (f *fakeData) MaxMeasurementSeq(context.Context) int64 {
	if len(f.ms) == 0 {
		return 0
	}
	return f.ms[len(f.ms)-1].Seq
}
func (f *fakeData) Snapshot(context.Context) []wire.State { return f.states }
func (f *fakeData) ApplyPeerData(context.Context, string, string, []wire.State, []wire.Measurement) (int, error) {
	return 0, nil
}
func (f *fakeData) PeerGroups(context.Context) []healthchecks.GroupState       { return nil }
func (f *fakeData) ApplyPeerGroups(context.Context, []healthchecks.GroupState) {}
func (f *fakeData) PeerVerdicts(context.Context, func(nodes []string) bool)    {}

// fakeHub nimmt Stellvertreter-Nodes an wie der hub.
type fakeHub struct {
	mu     sync.Mutex
	reg    [][]wire.ProxyNode
	points map[string]int
	states map[string]int
}

func (h *fakeHub) ProxyReady() bool { return true }
func (h *fakeHub) RegisterProxies(_ context.Context, items []wire.ProxyNode) (map[string]int64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reg = append(h.reg, items)
	acks := map[string]int64{}
	for _, p := range items {
		acks[p.ID] = 0
	}
	return acks, nil
}
func (h *fakeHub) ProxyData(_ context.Context, node string, states []wire.State, batch []wire.Measurement) (int64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.points[node] += len(batch)
	h.states[node] += len(states)
	var ack int64
	for _, x := range batch {
		ack = max(ack, x.Seq)
	}
	return ack, nil
}

func TestProxyNodes(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522)
	fa, fb := &fakeData{fakeChecks: newFake(a)}, &fakeData{fakeChecks: newFake(b)}
	a.m.d.Checks = func() Checks { return fa }
	b.m.d.Checks = func() Checks { return fb }
	now := time.Now().UTC()
	fb.ms = []wire.Measurement{{Seq: 1, Token: "t1", Time: now, Status: "up"}, {Seq: 2, Token: "t1", Time: now, Status: "up"}, {Seq: 3, Token: "t1", Time: now, Status: "down"}}
	fb.states = []wire.State{{Token: "t1", State: "down"}}
	code, _, _ := a.m.StartPairing()
	if err := b.m.Join(ctx, a.srv.URL, code, b.srv.URL); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B")
	a.m.pingAll(ctx)
	// A ist verknuepft und reicht weiter, B nicht
	var fwd []string
	hub := &fakeHub{points: map[string]int{}, states: map[string]int{}}
	a.m.d.Linked = func() bool { return true }
	a.m.d.HubNotifies = func() bool { return true }
	a.m.d.Hub = hub
	a.m.d.Forward = func(_ context.Context, entity, id, op string) { fwd = append(fwd, entity+":"+id+":"+op) }
	both := []string{"node-a", "node-b"}
	if a.m.hubKnows(ctx, both) || a.m.hubDecides(ctx, both) {
		t.Fatal("hub must not know B yet")
	}
	fa.chk["t1"] = wire.Check{Token: "t1", Name: "Web", Nodes: both}                         // bisher nur in der Gruppe (Revision 0)
	fa.chk["t2"] = wire.Check{Token: "t2", Name: "GW", Nodes: both, Revision: 7}             // beim hub, B nur in der Gruppe ergaenzt
	fa.chk["t3"] = wire.Check{Token: "t3", Name: "Nur A", Nodes: []string{"node-a"}}         // ohne B: bleibt
	fa.chk["t4"] = wire.Check{Token: "t4", Name: "Online", Nodes: both, Execution: "online"} // Online-Check: bleibt

	a.m.pushProxies(ctx, mustMembers(t, a))
	if len(hub.reg) != 1 || len(hub.reg[0]) != 1 || hub.reg[0][0].ID != "node-b" || !hub.reg[0][0].Online {
		t.Fatalf("registration: %+v", hub.reg)
	}
	if hub.points["node-b"] != 3 || hub.states["node-b"] != 1 {
		t.Fatalf("data: points %d states %d", hub.points["node-b"], hub.states["node-b"])
	}
	if len(fwd) != 0 {
		t.Fatalf("hub does not list B yet, nothing to forward: %v", fwd)
	}
	// der hub fuehrt B jetzt (Liste der Nodes des Accounts): Checks mit B gehen an den hub, melden tut die Gruppe
	_ = a.m.d.Core.SetSetting(ctx, healthchecks.SettingPeers, `[{"id":"node-a","name":"A"},{"id":"node-b","name":"B","via":"node-a"}]`)
	if !a.m.hubKnows(ctx, both) || a.m.hubDecides(ctx, both) {
		t.Fatal("hub knows B as proxy but must not decide")
	}
	a.m.ready.Store(true)
	if g, me, _ := a.m.NotifyRole(ctx, both); !g || !me {
		t.Fatalf("group must notify: %v %v", g, me)
	}
	fb.ms = append(fb.ms, wire.Measurement{Seq: 4, Token: "t1", Time: now, Status: "up"})
	a.m.pushProxies(ctx, mustMembers(t, a))
	if hub.points["node-b"] != 4 {
		t.Fatalf("only the new point: %d", hub.points["node-b"])
	}
	sort.Strings(fwd)
	if len(fwd) != 2 || fwd[0] != "check:t1:upsert" || fwd[1] != "check:t2:upsert" {
		t.Fatalf("held checks not forwarded: %v", fwd)
	}
	a.m.pushProxies(ctx, mustMembers(t, a)) // einmal je Mitglied
	if len(fwd) != 2 {
		t.Fatalf("forwarded twice: %v", fwd)
	}
	// B ist inzwischen selbst verknuepft: keine Stellvertreter-Node mehr
	_, _ = a.m.db.ExecContext(ctx, `UPDATE peer_members SET linked = 1 WHERE node_id = 'node-b'`)
	a.m.pushProxies(ctx, mustMembers(t, a))
	if last := hub.reg[len(hub.reg)-1]; len(last) != 0 {
		t.Fatalf("linked member still registered: %+v", last)
	}
	// B ist wieder Stellvertreter (z. B. Cluster verlassen und neu gekoppelt): seine Checks gehen erneut an den hub,
	// auch ohne Neustart (Test 2026-10-29: Aenderungen aus der Trennzeit blieben sonst in der Gruppe)
	_, _ = a.m.db.ExecContext(ctx, `UPDATE peer_members SET linked = 0 WHERE node_id = 'node-b'`)
	a.m.pushProxies(ctx, mustMembers(t, a))
	if len(fwd) != 4 {
		t.Fatalf("returning member: held checks must be forwarded again: %v", fwd)
	}
}

func mustMembers(t *testing.T, n *testNode) []Member {
	t.Helper()
	list, err := n.m.Members(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return list
}
