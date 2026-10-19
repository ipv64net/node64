package peer

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/notify"
)

type alerts struct {
	mu   sync.Mutex
	list []notify.Alert
}

func (a *alerts) add(x notify.Alert) { a.mu.Lock(); a.list = append(a.list, x); a.mu.Unlock() }
func (a *alerts) kinds() []notify.Kind {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []notify.Kind
	for _, x := range a.list {
		out = append(out, x.Kind)
	}
	return out
}

// setSeen setzt den letzten Kontakt eines Mitglieds (wie nach Pings).
func setSeen(t *testing.T, n *testNode, id string, at time.Time) {
	t.Helper()
	if _, err := n.m.db.Exec(`UPDATE peer_members SET last_seen = ?, last_error = ? WHERE node_id = ?`, fmtTime(at), "connection refused", id); err != nil {
		t.Fatal(err)
	}
}

func TestWatchMembers(t *testing.T) {
	ctx := context.Background()
	a, b, c := newNode(t, "node-a", "A", 0), newNode(t, "node-b", "B", 0), newNode(t, "node-c", "C", 0)
	code, _, _ := a.m.StartPairing()
	if err := b.m.Join(ctx, a.srv.URL, code, b.srv.URL); err != nil {
		t.Fatal(err)
	}
	code, _, _ = a.m.StartPairing()
	if err := c.m.Join(ctx, a.srv.URL, code, c.srv.URL); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B", "C")
	waitMembers(t, b, "A", "C")
	var na, nb alerts
	a.m.d.Notify, b.m.d.Notify = na.add, nb.add
	now := time.Now()

	// C seit 10 min weg: A (kleinste erreichbare Kennung) meldet, B nicht
	for _, n := range []*testNode{a, b} {
		setSeen(t, n, "node-c", now.Add(-10*time.Minute))
	}
	setSeen(t, a, "node-b", now)
	setSeen(t, b, "node-a", now)
	a.m.watchMembers(ctx)
	b.m.watchMembers(ctx)
	a.m.watchMembers(ctx) // nur einmal
	if k := na.kinds(); len(k) != 1 || k[0] != notify.KindClusterDown {
		t.Fatalf("A alerts: %v", k)
	}
	if k := nb.kinds(); len(k) != 0 {
		t.Fatalf("B must not alert too: %v", k)
	}
	// erst 1 min weg: noch keine Meldung (Neustart, Update)
	setSeen(t, a, "node-b", now.Add(-time.Minute))
	a.m.watchMembers(ctx)
	if k := na.kinds(); len(k) != 1 {
		t.Fatalf("grace: %v", k)
	}
	// C wieder da: Entwarnung von A
	setSeen(t, a, "node-c", time.Now())
	setSeen(t, a, "node-b", time.Now())
	a.m.watchMembers(ctx)
	if k := na.kinds(); len(k) != 2 || k[1] != notify.KindClusterUp {
		t.Fatalf("up: %v", k)
	}
	if x, _ := a.m.member(ctx, "node-c"); x.MemberDown(time.Now()) {
		t.Fatal("C is back")
	}
}
