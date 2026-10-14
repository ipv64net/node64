package peer

import (
	"context"
	"testing"
	"time"
)

func TestNotifyRole(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522)
	newFake(a)
	newFake(b)
	code, _, _ := a.m.StartPairing()
	if err := b.m.Join(ctx, a.srv.URL, code, b.srv.URL); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B")
	a.m.pingAll(ctx)
	role := func(nodes ...string) [2]bool {
		g, me, _ := a.m.NotifyRole(ctx, nodes)
		return [2]bool{g, me}
	}
	// vor dem ersten Abgleich nach dem Start bewertet die Node noch nicht
	if _, _, ready := a.m.NotifyRole(ctx, []string{"node-a", "node-b"}); ready {
		t.Fatal("must not be ready before the first pull")
	}
	a.m.ready.Store(true)
	if r := role("node-a", "node-b"); r != [2]bool{true, true} {
		t.Fatalf("owner A: %v", r)
	}
	if r := role("node-b", "node-a"); r != [2]bool{true, false} {
		t.Fatalf("owner B online: %v", r)
	}
	if r := role("node-a"); r != [2]bool{false, false} {
		t.Fatalf("only A measures: %v", r)
	}
	if r := role("node-a", "box-elsewhere"); r != [2]bool{false, false} {
		t.Fatalf("no group member measures: %v", r)
	}
	// B faellt aus: A uebernimmt
	_, _ = a.m.db.ExecContext(ctx, `UPDATE peer_members SET last_seen = ? WHERE node_id = 'node-b'`, fmtTime(time.Now().Add(-time.Hour)))
	if r := role("node-b", "node-a"); r != [2]bool{true, true} {
		t.Fatalf("B offline: %v", r)
	}
	// verknuepft, hub bestaetigt und kennt alle messenden Nodes: der hub meldet
	a.m.d.Linked = func() bool { return true }
	a.m.d.HubNotifies = func() bool { return true }
	_, _ = a.m.db.ExecContext(ctx, `UPDATE peer_members SET linked = 1 WHERE node_id = 'node-b'`)
	if r := role("node-a", "node-b"); r != [2]bool{false, false} {
		t.Fatalf("hub notifies: %v", r)
	}
	// B nicht verknuepft: der hub kennt den Check nicht, die Gruppe meldet
	_, _ = a.m.db.ExecContext(ctx, `UPDATE peer_members SET linked = 0 WHERE node_id = 'node-b'`)
	if r := role("node-a", "node-b"); r != [2]bool{true, true} {
		t.Fatalf("hub does not know B: %v", r)
	}
	// hub bestaetigt nicht (z. B. Datenbank weg): die Gruppe meldet
	_, _ = a.m.db.ExecContext(ctx, `UPDATE peer_members SET linked = 1 WHERE node_id = 'node-b'`)
	a.m.d.HubNotifies = func() bool { return false }
	if r := role("node-a", "node-b"); r != [2]bool{true, true} {
		t.Fatalf("hub not confirming: %v", r)
	}
}
