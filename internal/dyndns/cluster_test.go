package dyndns

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/secrets"
)

// Cluster im Kleinen: je Node ein Modul mit eigenem update.php (zaehlt die Aufrufe je Node), dazwischen ein Abgleich
// wie /peer/v2/sync (je Eintrag der letzte Stand, der juengere gewinnt, Herkunft bleibt erhalten).

type ddVer struct {
	seq     int64
	origin  string
	deleted bool
}

func (v ddVer) newer(o ddVer) bool { return v.seq > o.seq || v.seq == o.seq && v.origin > o.origin }

type ddOriginKey struct{}

type ddNode struct {
	id    string
	m     *Module
	f     *fakeUpdate
	dns   *dnsView
	ver   map[string]ddVer
	dirty map[string]bool
}

type ddNet struct {
	t       *testing.T
	mu      sync.Mutex
	seq     int64
	now     time.Time
	nodes   []*ddNode
	down    map[string]bool // nicht erreichbar
	areaOff map[string]bool // Bereich auf der Node aus
}

func newDDNet(t *testing.T, ids ...string) *ddNet {
	n := &ddNet{t: t, now: time.Now(), down: map[string]bool{}, areaOff: map[string]bool{}}
	for i, id := range ids {
		m, f, dns := setupUpdater(t)
		if i > 0 { // andere Node, anderer Schluessel
			m.box, _ = secrets.New([]byte("fedcba9876543210fedcba987654321" + string(rune('0'+i))))
		}
		node := &ddNode{id: id, m: m, f: f, dns: dns, ver: map[string]ddVer{}, dirty: map[string]bool{}}
		m.startedAt = n.now.Add(-time.Hour)
		m.cl.now = func() time.Time { n.mu.Lock(); defer n.mu.Unlock(); return n.now }
		m.SetCluster(ClusterHooks{
			Change: func(ctx context.Context, id string, deleted bool) { n.change(ctx, node, id, deleted) },
			Members: func(context.Context) []ClusterPeer {
				n.mu.Lock()
				defer n.mu.Unlock()
				if n.areaOff[node.id] {
					return nil
				}
				var out []ClusterPeer
				for _, o := range n.nodes {
					if o != node && !n.areaOff[o.id] {
						out = append(out, ClusterPeer{ID: o.id, Name: "Node " + o.id, Online: !n.down[o.id]})
					}
				}
				return out
			},
			Self: func() string { return node.id },
		})
		n.nodes = append(n.nodes, node)
	}
	return n
}

func (n *ddNet) change(ctx context.Context, node *ddNode, id string, deleted bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if v, ok := ctx.Value(ddOriginKey{}).(ddVer); ok {
		node.ver[id] = v
		return
	}
	n.seq++
	node.ver[id] = ddVer{seq: n.seq, origin: node.id, deleted: deleted}
	node.dirty[id] = true
}

func (n *ddNet) node(id string) *ddNode {
	for _, x := range n.nodes {
		if x.id == id {
			return x
		}
	}
	n.t.Fatalf("no node %s", id)
	return nil
}

func (n *ddNet) advance(d time.Duration) {
	n.mu.Lock()
	n.now = n.now.Add(d)
	n.mu.Unlock()
}

// seed legt wie der Cluster beim Start alle vorhandenen Eintraege ins Protokoll.
func (n *ddNet) seed() {
	for _, x := range n.nodes {
		ids, err := x.m.ClusterIDs(context.Background(), ClusterItemConfig)
		if err != nil {
			n.t.Fatal(err)
		}
		for _, id := range ids {
			if _, ok := x.ver[id]; !ok {
				n.change(context.Background(), x, id, false)
			}
		}
	}
}

// sync gleicht ab, bis nichts mehr offen ist (nur zwischen erreichbaren Nodes mit eingeschaltetem Bereich).
// errs: Eintraege, die eine Node nicht uebernommen hat.
func (n *ddNet) sync() (errs []error) {
	ctx := context.Background()
	for round := 0; round < 10; round++ {
		moved := false
		for _, src := range n.nodes {
			n.mu.Lock()
			skip := n.down[src.id] || n.areaOff[src.id]
			var ids []string
			for id := range src.dirty {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			n.mu.Unlock()
			if skip {
				continue
			}
			for _, id := range ids {
				later := false // eine Node gerade nicht erreichbar: sie holt es spaeter ab
				for _, dst := range n.nodes {
					n.mu.Lock()
					v, have := src.ver[id], dst.ver[id]
					gone := dst != src && (n.down[dst.id] || n.areaOff[dst.id])
					off := dst == src || gone || !v.newer(have)
					n.mu.Unlock()
					later = later || gone
					if off {
						continue
					}
					data, found, err := src.m.ClusterGet(ctx, ClusterItemConfig, id)
					if err != nil {
						n.t.Fatal(err)
					}
					if err := dst.m.ClusterApply(context.WithValue(ctx, ddOriginKey{}, v), ClusterItemConfig, id, data, v.deleted || !found); err != nil {
						errs = append(errs, err)
						continue
					}
					n.mu.Lock()
					dst.ver[id] = v
					dst.dirty[id] = true // weiterreichen
					n.mu.Unlock()
					moved = true
				}
				if !later {
					n.mu.Lock()
					delete(src.dirty, id)
					n.mu.Unlock()
				}
			}
		}
		if !moved {
			return errs
		}
	}
	return errs
}

// step ist eine Pruefrunde einer Node: zustaendig -> Updates.
func (n *ddNet) step(id string) bool {
	x := n.node(id)
	lead, _ := x.m.clusterLead(context.Background())
	if lead {
		x.m.runUpdates(context.Background())
	}
	n.sync()
	return lead
}

func (n *ddNet) leaderOn(id string) string {
	return n.node(id).m.core.SettingOr(context.Background(), SetLeader, "")
}

func onlyTarget(t *testing.T, m *Module) *Target {
	t.Helper()
	list, err := m.Targets(context.Background())
	if err != nil || len(list) != 1 {
		t.Fatalf("targets: %d %v", len(list), err)
	}
	return list[0]
}

// Namen und Einstellungen gehen samt Token an die anderen; Laufzeitstand, Pause und Verlauf bleiben je Node.
func TestClusterConfigSync(t *testing.T) {
	ctx := context.Background()
	n := newDDNet(t, "node-a", "node-b")
	a, b := n.node("node-a").m, n.node("node-b").m
	tg := addTarget(t, a, "nas", Mode4Auto, Mode6Suffix, "::1:2:3:4")
	if !clusterUIDRe.MatchString(tg.UID) {
		t.Fatalf("uid %q", tg.UID)
	}
	s := a.getSettings(ctx)
	s.Interval, s.NotifyIP = 10, true
	if err := a.saveSettings(ctx, s); err != nil {
		t.Fatal(err)
	}
	if errs := n.sync(); len(errs) > 0 {
		t.Fatal(errs)
	}
	got := onlyTarget(t, b)
	if got.UID != tg.UID || got.Token != tokA || got.Mode6 != Mode6Suffix || got.Suffix6 != "::1:2:3:4" || got.Host != "nas" || !got.Enabled {
		t.Fatalf("target on B: %+v", got)
	}
	var rawA, rawB string
	_ = a.core.Reader().QueryRow(`SELECT token FROM dyn_targets`).Scan(&rawA)
	_ = b.core.Reader().QueryRow(`SELECT token FROM dyn_targets`).Scan(&rawB)
	if rawB == tokA || rawB == rawA {
		t.Fatal("token must be sealed with the key of B")
	}
	if b.interval() != 10*time.Minute || !b.notifyOn(ctx, SetNotifyIP) {
		t.Fatalf("settings on B: %v", b.getSettings(ctx))
	}

	// Laufzeitstand auf B bleibt bei einer Aenderung auf A
	got.LastIP4, got.LastOKAt = "198.51.100.7", time.Now()
	b.saveRuntime(ctx, got)
	b.setPaused(ctx, got, PauseFlapping)
	tg.Mode6 = Mode6Host
	if err := a.UpdateTarget(ctx, tg); err != nil {
		t.Fatal(err)
	}
	n.sync()
	got = onlyTarget(t, b)
	if got.Mode6 != Mode6Host || got.LastIP4 != "198.51.100.7" || got.Paused != PauseFlapping {
		t.Fatalf("after edit on A: %+v", got)
	}
	if err := a.DeleteTarget(ctx, tg.ID); err != nil {
		t.Fatal(err)
	}
	n.sync()
	if list, _ := b.Targets(ctx); len(list) != 0 {
		t.Fatalf("deleted on A, still on B: %d", len(list))
	}
}

// Nur die zustaendige Node ruft update.php auf; faellt sie aus, uebernimmt die andere; kommt sie zurueck, erst nach
// leaderStable (kein Hin und Her). Verschiedene Netze: die Namen zeigen nach der Uebernahme auf den anderen Anschluss.
func TestClusterLeaderFailover(t *testing.T) {
	n := newDDNet(t, "node-a", "node-b")
	na, nb := n.node("node-a"), n.node("node-b")
	nb.m.stMu.Lock()
	nb.m.fam[0].IP = netip.MustParseAddr("198.51.100.20") // B steht in einem anderen Netz
	nb.m.stMu.Unlock()
	addTarget(t, na.m, "nas", Mode4Auto, Mode6Off, "")
	n.sync()

	if n.step("node-b") || nb.f.n() != 0 {
		t.Fatalf("B must not update while A is reachable (calls %d)", nb.f.n())
	}
	if !n.step("node-a") || na.f.n() != 1 || n.leaderOn("node-a") != "node-a" || n.leaderOn("node-b") != "node-a" {
		t.Fatalf("A leads: calls %d leader %q/%q", na.f.n(), n.leaderOn("node-a"), n.leaderOn("node-b"))
	}
	na.dns.A, nb.dns.A = []string{"93.184.216.34"}, []string{"93.184.216.34"}
	n.step("node-a")
	n.step("node-b")
	if na.f.n() != 1 || nb.f.n() != 0 {
		t.Fatalf("calls A %d B %d", na.f.n(), nb.f.n())
	}

	// A faellt aus (Karenz des Clusters vorbei: offline) -> B uebernimmt
	n.down["node-a"] = true
	n.advance(3 * time.Minute)
	if !n.step("node-b") || nb.f.n() != 1 || !strings.Contains(nb.f.last(), "ipv4=198.51.100.20") || n.leaderOn("node-b") != "node-b" {
		t.Fatalf("B takes over: calls %d leader %q", nb.f.n(), n.leaderOn("node-b"))
	}
	nb.dns.A = []string{"198.51.100.20"}

	// A kommt zurueck: bekommt den Stand, aktualisiert nicht; B gibt erst nach leaderStable ab
	n.down["node-a"] = false
	n.sync()
	if n.leaderOn("node-a") != "node-b" {
		t.Fatalf("A must learn the new leader: %q", n.leaderOn("node-a"))
	}
	for i := 0; i < 4; i++ {
		n.advance(time.Minute)
		if n.step("node-a") || !n.step("node-b") {
			t.Fatalf("minute %d: B must stay responsible", i+1)
		}
	}
	if na.f.n() != 1 {
		t.Fatalf("A updated while B was responsible: %d", na.f.n())
	}
	n.advance(2 * time.Minute)
	if n.step("node-b") || n.leaderOn("node-a") != "node-a" {
		t.Fatalf("B hands back to A after %v: leader %q", leaderStable, n.leaderOn("node-a"))
	}
	na.dns.A = []string{"198.51.100.20"} // DNS zeigt noch auf B
	if !n.step("node-a") || na.f.n() != 2 || !strings.Contains(na.f.last(), "ipv4=93.184.216.34") {
		t.Fatalf("A updates again: calls %d", na.f.n())
	}
	if nb.f.n() != 1 {
		t.Fatalf("B calls %d", nb.f.n())
	}
}

// Bereich aus: jede Node aktualisiert fuer sich wie ohne Cluster; nach dem Start wartet eine Node erst ab.
func TestClusterAreaOffAndStartWait(t *testing.T) {
	n := newDDNet(t, "node-a", "node-b")
	addTarget(t, n.node("node-a").m, "nas", Mode4Auto, Mode6Off, "")
	n.sync()
	n.areaOff["node-b"] = true
	if !n.step("node-a") || !n.step("node-b") || n.node("node-a").f.n() != 1 || n.node("node-b").f.n() != 1 {
		t.Fatal("area off: both update on their own")
	}
	if n.node("node-b").m.clusterView(context.Background()).On {
		t.Fatal("no cluster view with the area off")
	}
	n.areaOff["node-b"] = false
	b := n.node("node-b").m
	b.startedAt = n.now
	if n.step("node-b") {
		t.Fatal("no updates right after the start")
	}
}

// Exakt gleiche Namen beider Nodes werden eins (kleinere Kennung); derselbe Name mit anderer Einstellung nicht.
func TestClusterDuplicateMerge(t *testing.T) {
	ctx := context.Background()
	n := newDDNet(t, "node-a", "node-b")
	a, b := n.node("node-a").m, n.node("node-b").m
	ta, tb := addTarget(t, a, "nas", Mode4Auto, Mode6Off, ""), addTarget(t, b, "nas", Mode4Auto, Mode6Off, "")
	ca, cb := addTarget(t, a, "pi", Mode4Auto, Mode6Off, ""), addTarget(t, b, "pi", Mode4Auto, Mode6Host, "")
	for _, x := range n.nodes { // vor dem Beitritt: noch nichts abgeglichen
		x.ver, x.dirty = map[string]ddVer{}, map[string]bool{}
	}
	n.seed()
	errs := n.sync()
	if len(errs) != 2 || !errors.Is(errs[0], errNameConflict) {
		t.Fatalf("conflict expected in both directions: %v", errs)
	}
	want := min(ta.UID, tb.UID)
	for _, m := range []*Module{a, b} {
		list, _ := m.Targets(ctx)
		if len(list) != 2 {
			t.Fatalf("targets: %d", len(list))
		}
		for _, x := range list {
			if x.Host == "nas" && x.UID != want {
				t.Fatalf("nas: uid %q, want %q", x.UID, want)
			}
		}
	}
	if got, _ := b.Target(ctx, cb.ID); got == nil || got.Mode6 != Mode6Host || got.UID != cb.UID {
		t.Fatalf("pi on B must stay: %+v", got)
	}
	if got, _ := a.Target(ctx, ca.ID); got == nil || got.Mode6 != Mode6Off {
		t.Fatalf("pi on A must stay: %+v", got)
	}
}
