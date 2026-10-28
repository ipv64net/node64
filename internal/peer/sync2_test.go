package peer

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/wire"
)

// fakeProv ist ein Modul mit zwei Bereichen (a, b), Eintraege als Text.
type fakeProv struct {
	n     *testNode
	mod   string
	items []ItemInfo
	mu    sync.Mutex
	data  map[string]string // "bereich/id" -> Wert
}

func newProv(n *testNode) *fakeProv {
	p := &fakeProv{n: n, mod: "demo", items: []ItemInfo{{ID: "a"}, {ID: "b"}}, data: map[string]string{}}
	n.m.RegisterProvider(p)
	return p
}

// newHCProv: Bereiche des Healthchecks-Moduls ueber v2 (Proxmox VE, Docker) wie healthchecks/hccluster.
func newHCProv(n *testNode) *fakeProv {
	p := &fakeProv{n: n, mod: "healthchecks", items: []ItemInfo{{ID: "proxmox"}, {ID: "docker"}}, data: map[string]string{}}
	n.m.RegisterProvider(p)
	return p
}

// newNFProv: Bereich der Benachrichtigungen ueber v2 (Kanaele) wie notify/nfcluster.
func newNFProv(n *testNode) *fakeProv {
	p := &fakeProv{n: n, mod: "notifications", items: []ItemInfo{{ID: "channels"}}, data: map[string]string{}}
	n.m.RegisterProvider(p)
	return p
}

func (p *fakeProv) ClusterModule() ModuleInfo {
	return ModuleInfo{ID: p.mod, TitleKey: p.mod, Items: p.items}
}

func (p *fakeProv) ClusterIDs(_ context.Context, item string) ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for k := range p.data {
		if id, ok := strings.CutPrefix(k, item+"/"); ok {
			out = append(out, id)
		}
	}
	return out, nil
}

func (p *fakeProv) ClusterGet(_ context.Context, item, id string) (json.RawMessage, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.data[item+"/"+id]
	if !ok {
		return nil, false, nil
	}
	b, _ := json.Marshal(v)
	return b, true, nil
}

func (p *fakeProv) ClusterApply(ctx context.Context, item, id string, data json.RawMessage, deleted bool) error {
	p.mu.Lock()
	if deleted {
		delete(p.data, item+"/"+id)
	} else {
		var v string
		_ = json.Unmarshal(data, &v)
		p.data[item+"/"+id] = v
	}
	p.mu.Unlock()
	p.n.m.ClusterChange(ctx, p.mod, item, id, deleted) // Hook wie im echten Modul (Herkunft steckt in ctx)
	return nil
}

// set aendert lokal (mit Hook).
func (p *fakeProv) set(item, id, v string) {
	p.mu.Lock()
	if v == "" {
		delete(p.data, item+"/"+id)
	} else {
		p.data[item+"/"+id] = v
	}
	p.mu.Unlock()
	p.n.m.ClusterChange(context.Background(), p.mod, item, id, v == "")
}

func (p *fakeProv) get(item, id string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.data[item+"/"+id]
}

func round2(nodes ...*testNode) {
	ctx := context.Background()
	for _, n := range nodes {
		n.m.pingAll(ctx) // Bereiche der anderen
	}
	syncRound(nodes...)
}

func TestClusterSync2(t *testing.T) {
	ctx := context.Background()
	a, b, c := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522), newNode(t, "node-c", "C", 522)
	pa, pb, pc := newProv(a), newProv(b), newProv(c)
	pa.data["a/1"] = "vorher" // schon vor dem Cluster vorhanden (seed)
	code, _, _ := a.m.StartPairing()
	if err := b.m.Join(ctx, a.srv.URL, code, b.srv.URL); err != nil {
		t.Fatal(err)
	}
	code, _, _ = b.m.StartPairing()
	if err := c.m.Join(ctx, b.srv.URL, code, c.srv.URL); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B", "C")

	// ohne Schalter: nichts
	round2(a, b, c)
	if pb.get("a", "1") != "" {
		t.Fatal("module is off by default")
	}
	// A und B schalten demo/a ein, C nur das Modul ohne Bereich a
	for _, n := range []*testNode{a, b, c} {
		if err := n.m.SetSync(ctx, "demo", "", true); err != nil {
			t.Fatal(err)
		}
		if err := n.m.SetSync(ctx, "demo", "a", n != c); err != nil {
			t.Fatal(err)
		}
	}
	round2(a, b, c)
	if pb.get("a", "1") != "vorher" {
		t.Fatalf("seeded entry must reach B, got %q", pb.get("a", "1"))
	}
	if pc.get("a", "1") != "" {
		t.Fatal("C has item a off")
	}
	// Bereich b ist aus: bleibt lokal
	pa.set("b", "9", "geheim")
	round2(a, b, c)
	if pb.get("b", "9") != "" {
		t.Fatal("item b is off")
	}

	// Aenderung auf B erreicht A; Loeschen auf A erreicht B
	pb.set("a", "1", "auf B")
	round2(a, b, c)
	if pa.get("a", "1") != "auf B" {
		t.Fatalf("update from B: %q", pa.get("a", "1"))
	}
	pa.set("a", "1", "")
	round2(a, b, c)
	if pb.get("a", "1") != "" {
		t.Fatal("delete must reach B")
	}

	// C schaltet a spaeter ein: holt von vorn ab, auch was vorher vorbeiging
	pa.set("a", "2", "neu")
	round2(a, b, c)
	if err := c.m.SetSync(ctx, "demo", "a", true); err != nil {
		t.Fatal(err)
	}
	round2(a, b, c)
	if pc.get("a", "2") != "neu" || pc.get("a", "1") != "" {
		t.Fatalf("late enable: a/2=%q a/1=%q", pc.get("a", "2"), pc.get("a", "1"))
	}

	// unbekannter Bereich wird abgelehnt
	if err := a.m.SetSync(ctx, "demo", "zz", true); err != ErrUnknownSync {
		t.Fatalf("unknown item: %v", err)
	}
}

func TestSyncModulesDefaults(t *testing.T) {
	ctx := context.Background()
	a := newNode(t, "node-a", "A", 522)
	newProv(a)
	mods := a.m.SyncModules(ctx)
	if len(mods) != 3 || mods[0].ID != "healthchecks" || mods[1].ID != "notifications" || mods[2].ID != "demo" {
		t.Fatalf("modules: %+v", mods)
	}
	if mods[0].Available { // ohne Healthchecks-Modul nicht verfuegbar
		t.Fatal("healthchecks must be unavailable without the module")
	}
	if !mods[0].Enabled || !mods[0].Items[0].Enabled || !mods[1].Enabled || mods[2].Enabled {
		t.Fatal("healthchecks and notifications on by default, others off")
	}
	newFake(a)
	if caps := a.m.syncCaps(ctx); len(caps) != 3 {
		t.Fatalf("caps: %v", caps)
	}
	_ = a.m.SetSync(ctx, "healthchecks", "maintenance", false)
	if a.m.syncOn(ctx, "healthchecks", "maintenance") || !a.m.syncOn(ctx, "healthchecks", "checks") {
		t.Fatal("item switch")
	}
}

// Healthchecks ueber den Cluster abschaltbar; wieder an = von vorn abgeholt.
func TestHealthchecksSwitch(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522)
	fa, fb := newFake(a), newFake(b)
	code, _, _ := a.m.StartPairing()
	if err := b.m.Join(ctx, a.srv.URL, code, b.srv.URL); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B")
	if err := b.m.SetSync(ctx, "healthchecks", "", false); err != nil {
		t.Fatal(err)
	}
	fa.set("nur A", "tok1", time.Now().Add(-time.Minute))
	round2(a, b)
	if fb.name("tok1") != "" {
		t.Fatal("healthchecks off on B: nothing may arrive")
	}
	if len(a.m.hcMembers(ctx)) != 0 {
		t.Fatal("B must not count as healthchecks member of A")
	}
	_ = b.m.SetSync(ctx, "healthchecks", "", true)
	round2(a, b)
	if fb.name("tok1") != "nur A" {
		t.Fatalf("after switching on: %q", fb.name("tok1"))
	}
}

// Wegen alter Version ausgesetzt (gestaffeltes Update): nach dem Update der anderen Node von selbst wieder aktiv.
func TestVersionSuspendAutoResume(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522)
	code, _, _ := a.m.StartPairing()
	if err := b.m.Join(ctx, a.srv.URL, code, b.srv.URL); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B")
	x, _ := a.m.member(ctx, "node-b")
	a.m.suspend(ctx, *x, ReasonVersionTooOld, "test")
	if x, _ = a.m.member(ctx, "node-b"); !x.Suspended() {
		t.Fatal("must be suspended")
	}
	a.m.pingAll(ctx)
	if x, _ = a.m.member(ctx, "node-b"); x.Suspended() {
		t.Fatalf("version suspension must clear by itself, reason=%q", x.Reason)
	}
	// andere Gruende bleiben (nur von Hand wieder aufnehmen)
	a.m.suspend(ctx, *x, ReasonIdentityChanged, "test")
	a.m.pingAll(ctx)
	if x, _ = a.m.member(ctx, "node-b"); !x.Suspended() {
		t.Fatal("identity suspension must stay")
	}
}

// Proxmox VE und Docker: Bereiche des eingebauten Healthchecks-Moduls, aber ueber /peer/v2/sync (ohne Einstellung aus);
// der eigene Weg (v1) sieht sie nicht, die Liste der Module bleibt ohne doppeltes Healthchecks.
func TestClusterHealthchecksV2Items(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522)
	newFake(a)
	newFake(b)
	pa, pb := newHCProv(a), newHCProv(b)
	code, _, _ := a.m.StartPairing()
	if err := b.m.Join(ctx, a.srv.URL, code, b.srv.URL); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B")
	mods := a.m.SyncModules(ctx)
	if len(mods) != 2 || mods[0].ID != "healthchecks" || len(mods[0].Items) != 5 || mods[0].Items[2].ID != "proxmox" || mods[0].Items[2].Enabled {
		t.Fatalf("modules: %+v", mods)
	}
	pa.data["proxmox/u1"] = "pve"
	round2(a, b)
	if pb.get("proxmox", "u1") != "" || len(a.m.HCItemMembers(ctx, "proxmox")) != 0 {
		t.Fatal("proxmox is off by default")
	}
	for _, n := range []*testNode{a, b} {
		if err := n.m.SetSync(ctx, "healthchecks", "proxmox", true); err != nil {
			t.Fatal(err)
		}
	}
	round2(a, b)
	if pb.get("proxmox", "u1") != "pve" {
		t.Fatalf("proxmox system must reach B, got %q", pb.get("proxmox", "u1"))
	}
	pb.set("proxmox", "u1", "")
	round2(a, b)
	if pa.get("proxmox", "u1") != "" {
		t.Fatal("delete must reach A")
	}
	x, _ := a.m.member(ctx, "node-b")
	if w := a.m.v1Wants(a.m.syncCaps(ctx), *x); strings.Join(w, ",") != "checks,maintenance,settings" {
		t.Fatalf("v1 items: %v", w)
	}
	if l := a.m.HCItemMembers(ctx, "proxmox"); len(l) != 1 || l[0].NodeID != "node-b" || len(a.m.HCItemMembers(ctx, "docker")) != 0 {
		t.Fatalf("item members: %+v", l)
	}
	// Checks aus: kein Mitmessen, auch wenn der Bereich an ist
	_ = b.m.SetSync(ctx, "healthchecks", "checks", false)
	a.m.pingAll(ctx)
	if len(a.m.HCItemMembers(ctx, "proxmox")) != 0 {
		t.Fatal("without checks no item members")
	}
}

// Kanaele: Bereich notifications/channels ueber v2 (ohne Einstellung aus); die Kennungen der Kanaele an den Checks
// gehen nur mit, wenn er auf beiden Seiten an ist, und beim Einschalten kommen die Checks von vorn.
func TestClusterChannels(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522)
	fa, fb := newFake(a), newFake(b)
	pa, pb := newNFProv(a), newNFProv(b)
	t0 := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	pa.data["channels/u1"] = "kanal"
	fa.chk["tok1"], fa.upd["tok1"] = wire.Check{Token: "tok1", Name: "web", Nodes: []string{"node-a"}, ChannelUIDs: &[]string{"u1"}}, t0
	a.m.seed(ctx)
	code, _, _ := a.m.StartPairing()
	if err := b.m.Join(ctx, a.srv.URL, code, b.srv.URL); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B")
	lastSeen := func() *wire.Check {
		fb.mu.Lock()
		defer fb.mu.Unlock()
		if len(fb.seen) == 0 {
			return nil
		}
		w := fb.seen[len(fb.seen)-1]
		return &w
	}
	round2(a, b)
	if pb.get("channels", "u1") != "" {
		t.Fatal("channels are off by default")
	}
	if w := lastSeen(); w == nil || w.Token != "tok1" || w.ChannelUIDs != nil {
		t.Fatalf("check without channel uids while the area is off: %+v", w)
	}
	x, _ := a.m.member(ctx, "node-b")
	if has(a.m.v1Wants(a.m.syncCaps(ctx), *x), "channels") {
		t.Fatal("channels must not be in v1 wants")
	}
	// nur A an: weiterhin nichts
	_ = a.m.SetSync(ctx, "notifications", "channels", true)
	round2(a, b)
	if pb.get("channels", "u1") != "" {
		t.Fatal("B has channels off")
	}
	_ = b.m.SetSync(ctx, "notifications", "channels", true)
	n := len(fb.seen)
	round2(a, b)
	if pb.get("channels", "u1") != "kanal" {
		t.Fatalf("channel must reach B: %q", pb.get("channels", "u1"))
	}
	if w := lastSeen(); len(fb.seen) == n || w.ChannelUIDs == nil || len(*w.ChannelUIDs) != 1 || (*w.ChannelUIDs)[0] != "u1" {
		t.Fatalf("check must come again with channel uids: %+v", w)
	}
	x, _ = a.m.member(ctx, "node-b")
	if !has(a.m.v1Wants(a.m.syncCaps(ctx), *x), "channels") {
		t.Fatal("channels in v1 wants")
	}
	// B schaltet wieder aus: neue Kanaele bleiben bei A
	_ = b.m.SetSync(ctx, "notifications", "channels", false)
	pa.set("channels", "u2", "neu")
	round2(a, b)
	if pb.get("channels", "u2") != "" {
		t.Fatal("area off on B: nothing may arrive")
	}
}
