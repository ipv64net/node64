package peer

import (
	"context"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/wire"
)

// #194: Kennt die liefernde Node die Bereiche der abholenden noch nicht richtig (Stand beim letzten Ping veraltet,
// z. B. kurz nach dem Beitritt), gelten die Bereiche, die die abholende Node mitschickt - sonst liefe deren Zeiger
// ueber Eintraege hinweg, die sie nie bekommt, und vorhandene Checks fehlten dort dauerhaft.
func TestChangesTrustAskedItems(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522)
	fa, fb := newFake(a), newFake(b)
	code, _, _ := a.m.StartPairing()
	if err := b.m.Join(ctx, a.srv.URL, code, b.srv.URL); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B")
	syncRound(a, b)
	// A haelt B fuer eine Node ohne Healthchecks (alter Ping); der Check steht schon im Protokoll von A
	if _, err := a.m.db.ExecContext(ctx, `UPDATE peer_members SET sync = ? WHERE node_id = 'node-b'`, SwitchCap); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	fa.mu.Lock()
	fa.chk["tok1"], fa.upd["tok1"] = wire.Check{Token: "tok1", Name: "vorher", Nodes: []string{"node-a"}}, at
	fa.mu.Unlock()
	if _, err := a.m.db.ExecContext(ctx, `INSERT INTO peer_log (entity, entity_id, op, origin, changed_at) VALUES ('check', 'tok1', 'upsert', 'node-a', ?)`, fmtTime(at)); err != nil {
		t.Fatal(err)
	}
	b.m.bg.Wait()
	b.m.pullAll(ctx, "node-a")
	if fb.name("tok1") != "vorher" {
		t.Fatal("existing check skipped because of the stale member caps on the sending node")
	}
}
