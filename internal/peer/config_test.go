package peer

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/wire"
)

// fakeChecks ist ein Healthchecks-Modul im Speicher mit derselben Regel (juengere Aenderung gewinnt).
type fakeChecks struct {
	mu   sync.Mutex
	m    *Manager
	chk  map[string]wire.Check
	upd  map[string]time.Time
	del  map[string]time.Time
	fwd  []string
	self string
	seen []wire.Check // alle angebotenen Checks (auch nicht uebernommene)
}

func newFake(n *testNode) *fakeChecks {
	f := &fakeChecks{m: n.m, chk: map[string]wire.Check{}, upd: map[string]time.Time{}, del: map[string]time.Time{}, self: n.m.d.NodeID()}
	n.m.d.Checks = func() Checks { return f }
	n.m.d.Linked = func() bool { return false }
	return f
}

// set aendert lokal (wie ueber die Oberflaeche).
func (f *fakeChecks) set(name, token string, at time.Time) {
	f.mu.Lock()
	f.chk[token], f.upd[token] = wire.Check{Token: token, Name: name, Nodes: []string{f.self}}, at
	delete(f.del, token)
	f.mu.Unlock()
	f.m.LogChange(healthchecks.WithPeer(context.Background(), f.self, at), "check", token, "upsert")
}

func (f *fakeChecks) remove(token string, at time.Time) {
	f.mu.Lock()
	delete(f.chk, token)
	f.del[token] = at
	f.mu.Unlock()
	f.m.LogChange(healthchecks.WithPeer(context.Background(), f.self, at), "check", token, "delete")
}

func (f *fakeChecks) name(token string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.chk[token]; ok {
		return c.Name
	}
	return ""
}

func (f *fakeChecks) PeerCheck(_ context.Context, token, _ string) (*wire.Check, time.Time, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.chk[token]; ok {
		return &c, f.upd[token], time.Time{}, nil
	}
	return nil, time.Time{}, f.del[token], nil
}

func (f *fakeChecks) ApplyPeerCheck(_ context.Context, w wire.Check, at time.Time, origin, _ string) (bool, error) {
	f.mu.Lock()
	f.seen = append(f.seen, w)
	if _, ok := f.chk[w.Token]; ok && !at.After(f.upd[w.Token]) {
		f.mu.Unlock()
		return false, nil
	}
	if d, ok := f.del[w.Token]; ok && !at.After(d) {
		f.mu.Unlock()
		return false, nil
	}
	f.chk[w.Token], f.upd[w.Token] = w, at
	delete(f.del, w.Token)
	f.mu.Unlock()
	f.m.LogChange(healthchecks.WithPeer(context.Background(), origin, at), "check", w.Token, "upsert")
	return true, nil
}

func (f *fakeChecks) DeletePeerCheck(_ context.Context, token string, at time.Time, origin string) (bool, error) {
	f.mu.Lock()
	_, had := f.chk[token]
	if had && f.upd[token].After(at) {
		f.mu.Unlock()
		return false, nil
	}
	delete(f.chk, token)
	f.del[token] = at
	f.mu.Unlock()
	if had {
		f.m.LogChange(healthchecks.WithPeer(context.Background(), origin, at), "check", token, "delete")
	}
	return had, nil
}

func (f *fakeChecks) PeerTokens(context.Context) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for t := range f.chk {
		out = append(out, t)
	}
	return out
}

func syncRound(nodes ...*testNode) {
	for i := 0; i < 3; i++ { // mehrere Runden: Weiterreichen ueber Zwischenstationen
		for _, n := range nodes {
			n.m.pullAll(context.Background(), "")
		}
	}
}

func TestConfigSync(t *testing.T) {
	ctx := context.Background()
	a, b, c := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522), newNode(t, "node-c", "C", 522)
	fa, fb, fc := newFake(a), newFake(b), newFake(c)
	t0 := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)

	// A hat schon einen Check, bevor die Gruppe entsteht (erster Abgleich ueber seed)
	fa.chk["tok1"], fa.upd["tok1"] = wire.Check{Token: "tok1", Name: "vorher", Nodes: []string{"node-a"}}, t0
	a.m.seed(ctx)
	code, _, _ := a.m.StartPairing()
	if err := b.m.Join(ctx, a.srv.URL, code, b.srv.URL); err != nil {
		t.Fatal(err)
	}
	code, _, _ = b.m.StartPairing()
	if err := c.m.Join(ctx, b.srv.URL, code, c.srv.URL); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B", "C")
	syncRound(a, b, c)
	for _, f := range []*fakeChecks{fb, fc} {
		if f.name("tok1") != "vorher" {
			t.Fatalf("%s: initial check missing", f.self)
		}
	}

	// Aenderung auf B erreicht A und C
	fb.set("auf B geaendert", "tok1", t0.Add(time.Minute))
	syncRound(a, b, c)
	if fa.name("tok1") != "auf B geaendert" || fc.name("tok1") != "auf B geaendert" {
		t.Fatalf("update: a=%q c=%q", fa.name("tok1"), fc.name("tok1"))
	}

	// gleichzeitig geaendert: die juengere Aenderung gewinnt ueberall
	fa.set("A juenger", "tok1", t0.Add(3*time.Minute))
	fc.set("C aelter", "tok1", t0.Add(2*time.Minute))
	syncRound(a, b, c)
	for _, f := range []*fakeChecks{fa, fb, fc} {
		if f.name("tok1") != "A juenger" {
			t.Fatalf("%s: last writer must win, got %q", f.self, f.name("tok1"))
		}
	}

	// Loeschen auf C: ueberall weg, eine aeltere Aenderung holt den Check nicht zurueck
	fc.remove("tok1", t0.Add(4*time.Minute))
	syncRound(a, b, c)
	for _, f := range []*fakeChecks{fa, fb, fc} {
		if f.name("tok1") != "" {
			t.Fatalf("%s: check must be deleted", f.self)
		}
	}
	if ok, _ := fb.ApplyPeerCheck(ctx, wire.Check{Token: "tok1", Name: "alt"}, t0.Add(3*time.Minute+time.Second), "node-a", "node-b"); ok {
		t.Fatal("older change must not revive a deleted check")
	}

	// neuer Check auf C
	fc.set("neu auf C", "tok2", t0.Add(5*time.Minute))
	syncRound(a, b, c)
	if fa.name("tok2") != "neu auf C" || fb.name("tok2") != "neu auf C" {
		t.Fatal("new check must reach all nodes")
	}
}

func TestHubKnows(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522)
	newFake(a)
	newFake(b)
	code, _, _ := a.m.StartPairing()
	if err := b.m.Join(ctx, a.srv.URL, code, b.srv.URL); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B")
	a.m.d.Linked = func() bool { return true }
	a.m.pingAll(ctx) // B meldet sich als nicht verknuepft
	if a.m.hubKnows(ctx, []string{"node-b"}) {
		t.Fatal("an unlinked group member is unknown to the hub")
	}
	if !a.m.hubKnows(ctx, []string{"node-a", "box-elsewhere"}) {
		t.Fatal("self and nodes outside the group are known to the hub")
	}
	a.m.d.Forward = func(context.Context, string, string, string) {}
	if !a.m.forwardFor(ctx, "node-b") || a.m.forwardFor(ctx, "hub") || a.m.forwardFor(ctx, "node-a") {
		t.Fatal("the only linked node forwards changes of unlinked nodes")
	}
}

// Weiterreichen und Anzeige (Forwarder) nach derselben Regel: nur verknuepfte Mitglieder mit Healthchecks-Abgleich,
// die kleinste Kennung gewinnt. A (kleinste Kennung, verknuepft, Abgleich aus) reicht nicht weiter; B schon, und die
// nicht verknuepfte U sieht B (vorher sah U B, B hielt aber A fuer zustaendig und niemand reichte weiter).
func TestForwarderRule(t *testing.T) {
	ctx := context.Background()
	a, b, u := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522), newNode(t, "node-u", "U", 522)
	for _, n := range []*testNode{a, b, u} {
		newFake(n)
	}
	pair(t, a, b)
	pair(t, a, u)
	waitMembers(t, a, "B", "U")
	waitMembers(t, b, "A", "U")
	a.m.d.Linked = func() bool { return true }
	b.m.d.Linked = func() bool { return true }
	if err := a.m.SetSync(ctx, "healthchecks", "checks", false); err != nil {
		t.Fatal(err)
	}
	for _, n := range []*testNode{a, b, u} {
		n.m.pingAll(ctx)
	}
	if a.m.forwarder(ctx) {
		t.Fatal("A has the healthchecks area off and must not forward")
	}
	if !b.m.forwarder(ctx) {
		t.Fatal("B is the linked member with the area on and must forward")
	}
	if id, _, self := u.m.Forwarder(ctx); id != "node-b" || self {
		t.Fatalf("U must see B as forwarder, got %q", id)
	}
	if id, _, self := a.m.Forwarder(ctx); id != "" || self {
		t.Fatalf("A (area off) shows no forwarder, got %q", id)
	}
}
