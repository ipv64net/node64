package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/snmp/trap"
)

// trapPair: zwei Nodes mit demselben Host; zustaendig ist B, Traps kommen bei A an.
type trapPair struct {
	a, b   *busNode
	ra, rb *trapRec
	uid    string
	cut    atomic.Bool
}

func newTrapPair(t *testing.T) *trapPair {
	t.Helper()
	ctx := context.Background()
	bus := newBus(t)
	p := &trapPair{a: bus.newNode("node-a", "A", 1, false), b: bus.newNode("node-b", "B", 2, false)}
	h := &Host{Name: "sw", Address: "192.0.2.80", IntervalSec: 60, PreferredNode: "node-b"}
	if err := p.a.m.store.SaveHost(ctx, h, testActor); err != nil {
		t.Fatal(err)
	}
	p.uid = h.UID
	if _, err := p.b.m.st.Writer().Exec(`INSERT INTO m64_hosts (uid, name, address, kind, group_name, tags, interval_sec, owner_node, preferred_node,
		backup_nodes, agent_autoupd, paused, notes, created_at, created_by, updated_at, updated_by)
		VALUES (?, 'sw', '192.0.2.80', '', '', '[]', 60, 'node-b', 'node-b', '[]', 0, 0, '', ?, '{}', ?, '{}')`, h.UID, tsNow(), tsNow()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.a.m.st.Writer().Exec(`UPDATE m64_hosts SET owner_node = 'node-b' WHERE uid = ?`, h.UID); err != nil {
		t.Fatal(err)
	}
	nodes := map[string]*busNode{"node-a": p.a, "node-b": p.b}
	for _, n := range []*busNode{p.a, p.b} {
		n.m.SetCluster(ClusterHooks{Self: func() string { return n.id }, Call: func(ctx context.Context, node, name string, in, out any) error {
			o := nodes[node]
			if o == nil || p.cut.Load() {
				return errors.New("not reachable")
			}
			body, _ := json.Marshal(in)
			var res any
			var err error
			if name == callTrap { // bis HandleClusterCall die Anfrage kennt: direkt
				res, err = o.m.handleTrapCall(ctx, n.id, body)
			} else {
				res, err = o.m.HandleClusterCall(ctx, n.id, name, body)
			}
			if err != nil {
				return err
			}
			raw, _ := json.Marshal(res)
			if out != nil {
				return json.Unmarshal(raw, out)
			}
			return nil
		}})
		hh, err := n.m.store.Host(ctx, h.UID)
		if err != nil {
			t.Fatal(err)
		}
		n.m.rtMu.Lock()
		n.m.rts = map[string]*hostRT{h.UID: {host: hh}}
		n.m.rtMu.Unlock()
		n.m.traps.mu.Lock()
		n.m.traps.known = map[string]bool{h.UID: true}
		n.m.traps.ownerOf = n.m.trapOwner
		n.m.traps.mu.Unlock()
	}
	p.ra, p.rb = fakeTraps(p.a.m), fakeTraps(p.b.m)
	p.a.m.cl.snap.Store(snapOf("node-a", map[string]bool{"node-b": true}))
	p.b.m.cl.snap.Store(snapOf("node-b", map[string]bool{"node-a": true}))
	fctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); p.a.m.trapForwardLoop(fctx) }()
	t.Cleanup(func() { cancel(); <-done })
	return p
}

func waitTraps(t *testing.T, m *Module, uid string, ok func(*hostTraps) bool) *hostTraps {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s := m.traps.snapshot(uid, true)
		if ok(s) {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("trap state not reached: %+v", s)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestTrapClusterForward: ein Trap an eine nicht zustaendige Node landet als Eintrag bei der zustaendigen (dort
// Warnung, Runde, Zuruecksetzen); Anzeige und Zuruecksetzen auf der empfangenden Node gehen an die zustaendige; ist
// sie nicht erreichbar, bleibt der Trap hier.
func TestTrapClusterForward(t *testing.T) {
	ctx := context.Background()
	p := newTrapPair(t)
	from := netip.MustParseAddr("192.0.2.80")
	if r, o := p.a.m.roleOf(p.a.m.rts[p.uid].host); r != roleIdle || o != "node-b" {
		t.Fatalf("setup: A role %d owner %s", r, o)
	}
	p.a.m.traps.onEvent(trap.Event{From: from, HostID: p.uid, Known: true, Version: "2c", TrapOID: ".1.3.6.1.4.1.9999.0.1",
		Varbinds: []trap.Varbind{{OID: ".1.3.6.1.4.1.9999.1", Type: "OctetString", Value: "Tuer offen"}}})
	s := waitTraps(t, p.b.m, p.uid, func(s *hostTraps) bool { return s != nil && s.Pending == 1 })
	if s.List[0].Varbinds[0].Value != "Tuer offen" || p.rb.count(p.uid) != 1 {
		t.Fatalf("entry at owner: %+v runs %d", s, p.rb.count(p.uid))
	}
	if svc := p.b.m.traps.service(p.uid); len(svc.Facts) != 1 || svc.Facts[0].Code != factTrapReceived {
		t.Fatalf("owner service: %+v", svc)
	}
	if s := p.a.m.traps.snapshot(p.uid, false); s != nil || p.ra.count(p.uid) != 0 {
		t.Fatalf("receiving node kept the trap: %+v", s)
	}
	// bekannte Art: dort eingetragen, Runde dort (entprellt: Nachzuegler)
	p.a.m.traps.onEvent(trap.Event{From: from, HostID: p.uid, Known: true, Version: "2c", Kind: "link_down", TrapName: "linkDown"})
	waitTraps(t, p.b.m, p.uid, func(s *hostTraps) bool { return s != nil && s.Total == 2 && s.Pending == 1 })
	// Anzeige auf A: Stand von B
	if v := p.a.m.hostTrapsView(ctx, p.uid); v.Pending != 1 || len(v.List) != 2 || v.List[0].TrapName != "linkDown" {
		t.Fatalf("view on A: %+v", v)
	}
	// Zuruecksetzen auf A setzt B zurueck
	p.a.m.resetTraps(ctx, p.uid)
	if s := p.b.m.traps.snapshot(p.uid, false); s.Pending != 0 {
		t.Fatalf("reset from A: %+v", s)
	}
	// B nicht erreichbar (Anfrage scheitert): Trap bleibt auf A
	p.cut.Store(true)
	p.a.m.traps.onEvent(trap.Event{From: from, HostID: p.uid, Known: true, Version: "2c", TrapOID: ".1.3.6.1.4.1.9999.0.3"})
	waitTraps(t, p.a.m, p.uid, func(s *hostTraps) bool { return s != nil && s.Pending == 1 })
	if v := p.a.m.hostTrapsView(ctx, p.uid); v.Pending != 1 { // Anzeige: hiesiger Stand
		t.Fatalf("view without owner: %+v", v)
	}
	// B laut Cluster offline: gleich hier
	p.cut.Store(false)
	p.a.m.cl.snap.Store(snapOf("node-a", map[string]bool{"node-b": false}))
	p.a.m.traps.onEvent(trap.Event{From: from, HostID: p.uid, Known: true, Version: "2c", TrapOID: ".1.3.6.1.4.1.9999.0.4"})
	if s := p.a.m.traps.snapshot(p.uid, false); s.Pending != 2 {
		t.Fatalf("owner offline: %+v", s)
	}
	if s := p.b.m.traps.snapshot(p.uid, false); s.Total != 2 {
		t.Fatalf("owner got traps while offline: %+v", s)
	}
}

// TestTrapClusterCall: Pruefungen der Anfrage "trap" (nicht zustaendig, Host ohne Traps, Eintrag bereinigt).
func TestTrapClusterCall(t *testing.T) {
	ctx := context.Background()
	p := newTrapPair(t)
	add := func(n *busNode, e trapEntry) error {
		body, _ := json.Marshal(trapCallReq{Op: "add", Host: p.uid, Entry: &e})
		_, err := n.m.handleTrapCall(ctx, "node-x", body)
		return err
	}
	if err := add(p.a, trapEntry{Version: "2c"}); err == nil {
		t.Fatal("non-responsible node accepted an entry")
	}
	if _, err := p.b.m.handleTrapCall(ctx, "node-a", []byte(`{"op":"add","host":"../x"}`)); err == nil {
		t.Fatal("bad host accepted")
	}
	if _, err := p.b.m.handleTrapCall(ctx, "node-a", []byte(`{"op":"nope","host":"`+p.uid+`"}`)); err == nil {
		t.Fatal("bad op accepted")
	}
	junk := trapEntry{Time: time.Now().Add(48 * time.Hour), Version: "9", Kind: "x\x00y", TrapOID: strings.Repeat("1", 2000), Handled: true}
	for i := 0; i < 100; i++ {
		junk.Varbinds = append(junk.Varbinds, trap.Varbind{OID: ".1.3", Type: "OctetString", Value: "<b>\x01" + strings.Repeat("x", 1000)})
	}
	if err := add(p.b, junk); err != nil {
		t.Fatal(err)
	}
	s := p.b.m.traps.snapshot(p.uid, true)
	e := s.List[0]
	if len(e.Varbinds) != trap.DefaultMaxVarbinds || !e.Truncated || len([]rune(e.Varbinds[0].Value)) > trap.DefaultMaxValueLen ||
		strings.ContainsRune(e.Varbinds[0].Value, 1) || len(e.TrapOID) > 512 || e.Version != "" || e.Handled || s.Pending != 1 ||
		e.Time.After(p.b.m.traps.now().Add(time.Minute)) {
		t.Fatalf("entry not cleaned: varbinds %d trunc %v oid %d version %q kind %q handled %v time %v pending %d", len(e.Varbinds), e.Truncated,
			len(e.TrapOID), e.Version, e.Kind, e.Handled, e.Time, s.Pending)
	}
	p.b.m.traps.mu.Lock()
	p.b.m.traps.known = map[string]bool{}
	p.b.m.traps.mu.Unlock()
	if err := add(p.b, trapEntry{Version: "2c"}); err == nil {
		t.Fatal("entry for host without traps accepted")
	}
}
