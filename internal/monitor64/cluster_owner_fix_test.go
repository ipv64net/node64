package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Regressionstests zum Review Phase 2-4 (Zustaendigkeit/Zustand C2, Kern KE/AP).

// C2-2: ein Mitglied, das aus der Liste verschwindet (entfernt), ist beim Wiederauftauchen erst nach clusterStable
// stabil (vorher blieb "erreichbar seit" stehen und die Rueckgabe kam sofort).
func TestClusterSinceClearedWhenPeerVanishes(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	n := b.newNode("node-c", "C", 1, false)
	var mu sync.Mutex
	peers := []ClusterPeer{{ID: "node-a", Name: "A", Online: true}}
	h := n.m.hooks()
	h.Members = func(context.Context, string) []ClusterPeer {
		mu.Lock()
		defer mu.Unlock()
		return append([]ClusterPeer(nil), peers...)
	}
	n.m.SetCluster(h)
	if s := n.m.clusterRefresh(ctx); !s.Stable["node-a"] {
		t.Fatal("first glance: online peer counts as stable")
	}
	mu.Lock()
	peers = nil
	mu.Unlock()
	n.m.clusterRefresh(ctx)
	b.advance(time.Minute)
	mu.Lock()
	peers = []ClusterPeer{{ID: "node-a", Name: "A", Online: true}}
	mu.Unlock()
	if s := n.m.clusterRefresh(ctx); s.Stable["node-a"] {
		t.Fatal("peer back after vanishing must wait clusterStable")
	}
	b.advance(clusterStable)
	if s := n.m.clusterRefresh(ctx); !s.Stable["node-a"] {
		t.Fatal("peer stable after clusterStable")
	}
}

// C2-3: kurz nach dem Start misst die Node im Cluster nur (erst den Stand der anderen abholen), danach meldet sie.
func TestClusterStartWaitMeasuresOnly(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	clusterStartWait = time.Hour       // newBus stellt den alten Wert am Ende wieder her
	b.newNode("node-b", "B", 2, false) // vor A: A sieht B schon beim Start
	a := b.newNode("node-a", "A", 1, true)
	a.m.clusterRefresh(ctx)
	fake := &fakeCol{svcs: []model.Service{{Key: "raid:md0", Name: "md0", Kind: "raid", Default: true, Facts: []model.Fact{{Code: "raid_degraded", Text: "degraded"}}}}}
	rt := hostWithFake(t, a.m, fake)
	if _, err := a.m.store.UpsertDiscovered(ctx, rt.host.UID, fake.svcs, map[string]bool{"raid:md0": true}, testActor); err != nil {
		t.Fatal(err)
	}
	a.m.poll(ctx, rt)
	if v := rt.getView(); v.State != eval.Crit || v.Cluster == nil || v.Cluster.Reporting {
		t.Fatalf("during the start wait: measure only, got %v %+v", v.State, v.Cluster)
	}
	if a.alertCount() != 0 || len(a.m.loadOpen(ctx, rt.host.UID)) != 0 {
		t.Fatal("no notification and no problem during the start wait")
	}
	b.advance(2 * time.Hour)
	a.m.poll(ctx, rt)
	if v := rt.getView(); !v.Cluster.Reporting || a.alertCount() != 1 {
		t.Fatalf("after the start wait the node reports: %+v, alerts %d", v.Cluster, a.alertCount())
	}
}

// C2-5: Eintrag "owner:" vor dem Host -> Fehler (spaeter erneut), nicht still verloren.
func TestOwnerApplyBeforeHostRetries(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	n := b.newNode("node-c", "C", 1, false)
	data := json.RawMessage(`{"node":"node-a"}`)
	if err := n.m.ownerApply(ctx, "hostmissing01", data, false); !errors.Is(err, errOwnerNoHost) {
		t.Fatalf("owner before host must fail for a retry, got %v", err)
	}
	if err := n.m.ownerApply(ctx, "hostmissing01", nil, true); err != nil {
		t.Fatalf("deleting a missing owner entry: %v", err)
	}
	h := &Host{Name: "h", IntervalSec: 60}
	if err := n.m.store.SaveHost(ctx, h, testActor); err != nil {
		t.Fatal(err)
	}
	_, _ = n.m.st.Writer().Exec(`UPDATE m64_hosts SET uid = 'hostmissing01' WHERE uid = ?`, h.UID)
	if err := n.m.ownerApply(ctx, "hostmissing01", data, false); err != nil {
		t.Fatal(err)
	}
	if got := n.owner(t, "hostmissing01"); got != "node-a" {
		t.Fatalf("owner after retry: %s", got)
	}
}

// C2-5: nach einem Import geht die zustaendige Node als Eintrag "owner:" an den Cluster (leer: die bevorzugte).
func TestImportOwnersReported(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	n := b.newNode("node-c", "C", 1, false)
	h := &Host{Name: "h", IntervalSec: 60, PreferredNode: "node-a"}
	if err := n.m.store.SaveHost(ctx, h, testActor); err != nil {
		t.Fatal(err)
	}
	n.m.importOwners(ctx, []string{h.UID})
	var owner string
	_ = n.m.st.Reader().QueryRow(`SELECT owner_node FROM m64_hosts WHERE uid = ?`, h.UID).Scan(&owner)
	if owner != "node-a" {
		t.Fatalf("owner must be set explicitly: %q", owner)
	}
	n.mu.Lock()
	_, ok := n.log[ClusterItemConfig+"|owner:"+h.UID]
	n.mu.Unlock()
	if !ok {
		t.Fatal("owner entry not reported to the cluster")
	}
}

// idleRT legt einen Host mit Laufzeitstand an, ohne ihn einzuplanen (keine Runde nebenher).
func idleRT(t *testing.T, m *Module) *hostRT {
	t.Helper()
	h := &Host{Name: "h", IntervalSec: 60}
	if err := m.store.SaveHost(context.Background(), h, testActor); err != nil {
		t.Fatal(err)
	}
	rt := &hostRT{host: h}
	rt.initMaps()
	return rt
}

// insState legt den Zustand einer anderen Node in m64_cstate an.
func insState(t *testing.T, m *Module, host string, e stateEntry) {
	t.Helper()
	b, _ := json.Marshal(e)
	if _, err := m.st.Writer().Exec(`INSERT INTO m64_cstate (host_uid, node_id, data, at) VALUES (?, ?, ?, ?)
		ON CONFLICT (host_uid, node_id) DO UPDATE SET data = excluded.data, at = excluded.at`, host, e.Node, string(b), ts(e.At)); err != nil {
		t.Fatal(err)
	}
}

func memJSON(t *testing.T, chans ...string) json.RawMessage {
	t.Helper()
	mem := eval.HostMemory{HostChans: chans, Svcs: map[string]*eval.ServiceMemory{"fs:/": {Name: "fs", Cur: eval.Crit, Sent: eval.Crit, Chans: chans}}}
	b, _ := json.Marshal(mem)
	return b
}

// C2-1: das Gedaechtnis der Meldungen geht mit Kanal-Kennungen in den Cluster und kommt mit den lokalen Nummern der
// uebernehmenden Node zurueck (sonst Entwarnung an einen fremden bzw. keinen Kanal).
func TestAdoptStateMapsChannels(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, false)
	c := b.newNode("node-c", "C", 2, true)
	if _, err := a.m.st.Writer().Exec(`INSERT INTO nf_channels (id, type, name, config, uid, created_at, updated_at) VALUES (5, 'ntfy', 'Handy', '{}', 'chan-uid-1', '', '')`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.m.st.Writer().Exec(`INSERT INTO nf_channels (id, type, name, config, uid, created_at, updated_at) VALUES (9, 'ntfy', 'Handy', '{}', 'chan-uid-1', '', '')`); err != nil {
		t.Fatal(err)
	}
	out := a.m.memToCluster(ctx, memJSON(t, "5", "77", defaultChannels))
	var mem eval.HostMemory
	if err := json.Unmarshal(out, &mem); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(mem.Svcs["fs:/"].Chans, []string{"uid:chan-uid-1", defaultChannels}) || !slices.Equal(mem.HostChans, []string{"uid:chan-uid-1", defaultChannels}) {
		t.Fatalf("published channels: %+v %+v", mem.HostChans, mem.Svcs["fs:/"].Chans)
	}
	rt := idleRT(t, c.m)
	insState(t, c.m, rt.host.UID, stateEntry{Node: "node-a", At: time.Now().UTC(), Reporting: true, Mem: out})
	rt.mu.Lock()
	c.m.adoptState(ctx, rt)
	rt.mu.Unlock()
	c.m.notifyMu.Lock()
	got := c.m.notifier.Hosts[rt.host.UID]
	c.m.notifyMu.Unlock()
	if got == nil || !slices.Equal(got.Svcs["fs:/"].Chans, []string{"9", defaultChannels}) || !slices.Equal(got.HostChans, []string{"9", defaultChannels}) {
		t.Fatalf("adopted channels must be local numbers: %+v", got)
	}
}

// C2-6: ein zu alter Stand einer anderen Node wird nicht uebernommen (sonst alte Probleme erneut bzw. Entwarnungen).
func TestAdoptStateIgnoresOldState(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	c := b.newNode("node-c", "C", 2, true)
	rt := idleRT(t, c.m)
	insState(t, c.m, rt.host.UID, stateEntry{Node: "node-a", At: time.Now().UTC().Add(-time.Hour), Reporting: true, Mem: memJSON(t, defaultChannels),
		RT: json.RawMessage(`{"failures":{"acc1":7}}`)})
	rt.mu.Lock()
	c.m.adoptState(ctx, rt)
	fails := rt.Failures["acc1"]
	rt.mu.Unlock()
	c.m.notifyMu.Lock()
	got := c.m.notifier.Hosts[rt.host.UID]
	c.m.notifyMu.Unlock()
	if got != nil || fails != 0 {
		t.Fatalf("old state must not be adopted: mem %+v failures %d", got, fails)
	}
	// frischer Stand: wird uebernommen
	insState(t, c.m, rt.host.UID, stateEntry{Node: "node-a", At: time.Now().UTC(), Reporting: true, Mem: memJSON(t, defaultChannels)})
	rt.mu.Lock()
	c.m.adoptState(ctx, rt)
	rt.mu.Unlock()
	c.m.notifyMu.Lock()
	got = c.m.notifier.Hosts[rt.host.UID]
	c.m.notifyMu.Unlock()
	if got == nil {
		t.Fatal("fresh state must be adopted")
	}
}

// C2-8: ein zu alter Zustand der zustaendigen Node wird nicht als aktuell gezeigt (Bereich status aus: sonst ewig OK).
func TestIdleViewOldStateUnknown(t *testing.T) {
	b := newBus(t)
	c := b.newNode("node-c", "C", 2, false) // nicht gestartet: kein Blick auf den Cluster nebenher
	h := &Host{UID: "hostidle0001", Name: "h", IntervalSec: 60, PreferredNode: "node-a"}
	rt := &hostRT{host: h}
	c.m.cl.snap.Store(snapOf("node-c", map[string]bool{"node-a": true}, "node-a"))
	view := &HostView{View: eval.ViewOK, State: eval.OK, Services: []SvcView{{Key: "cpu", State: eval.OK}}}
	insState(t, c.m, h.UID, stateEntry{Node: "node-a", At: time.Now().UTC().Add(-time.Hour), Reporting: true, View: view})
	c.m.idleView(rt, "node-a")
	if v := rt.getView(); v.State != eval.Unknown || v.Cluster == nil || v.Cluster.Note != noteNoData {
		t.Fatalf("old remote state must show as no data: %v %+v", v.State, v.Cluster)
	}
	e := stateEntry{Node: "node-a", At: time.Now().UTC(), Reporting: true, View: view}
	c.m.cacheState(h.UID, &e)
	c.m.idleView(rt, "node-a")
	if v := rt.getView(); v.State != eval.OK || v.Cluster.Note != "" {
		t.Fatalf("fresh remote state: %v %+v", v.State, v.Cluster)
	}
}

// C2-4: ein geaendertes Gedaechtnis der Meldungen (Meldung, Erinnerung) wird sofort gespeichert und veroeffentlicht;
// beim Abgeben veroeffentlicht die Node ihren letzten Stand.
func TestStatePublishedOnMemoryChangeAndHandover(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	b.newNode("node-b", "B", 2, false) // vor A: A sieht B schon beim Start
	a := b.newNode("node-a", "A", 1, true)
	a.m.clusterRefresh(ctx)
	cpu := model.Metric{Name: "util", Value: 10, Unit: "%", Rule: model.RuleCPU}
	fake := &fakeCol{svcs: []model.Service{svc("cpu", "cpu", cpu)}}
	rt := hostWithFake(t, a.m, fake)
	uid := rt.host.UID
	a.m.poll(ctx, rt)
	saved := rt.lastSave
	time.Sleep(20 * time.Millisecond) // Uhr unter Windows grob: sonst ist der neue Zeitstempel gleich dem alten
	// gleicher Zustand, aber anderes Gedaechtnis: sofort speichern
	rt.mu.Lock()
	a.m.saveRuntime(ctx, rt, []byte(`{"svcs":{"cpu":{"cur":1,"sent":1}}}`))
	rt.mu.Unlock()
	if !rt.lastSave.After(saved) {
		t.Fatal("changed memory must be saved right away")
	}
	// Abgeben: Rolle report -> idle veroeffentlicht den letzten Stand (als gemeldet)
	if _, err := a.m.st.Writer().Exec(`DELETE FROM m64_cstate WHERE host_uid = ?`, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := a.m.st.Writer().Exec(`UPDATE m64_hosts SET owner_node = 'node-b' WHERE uid = ?`, uid); err != nil {
		t.Fatal(err)
	}
	rt.host.OwnerNode = "node-b"
	a.m.poll(ctx, rt)
	var data string
	if err := a.m.st.Reader().QueryRow(`SELECT data FROM m64_cstate WHERE host_uid = ? AND node_id = 'node-a'`, uid).Scan(&data); err != nil {
		t.Fatalf("final state not published on handover: %v", err)
	}
	var e stateEntry
	_ = json.Unmarshal([]byte(data), &e)
	if !e.Reporting || len(e.Mem) == 0 {
		t.Fatalf("final state must count as reported and carry the memory: %s", data)
	}
}

// KE1: die USV-Restlaufzeit zaehlt nur auf Batterie (Warnung ist "auf Batterie"); im Netzbetrieb OK beobachtet, damit
// der Tracker danach nicht haengt.
func TestUPSRuntimeOnlyOnBattery(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	ups := func(onBat float64, runtime float64) []model.Service {
		s := svc("ups:ups", "ups", model.Metric{Name: "on_battery", Value: onBat}, model.Metric{Name: "runtime", Value: runtime, Unit: "s", Rule: model.RuleUPSRuntime})
		if onBat > 0 {
			s.Facts = []model.Fact{{Code: "ups_on_battery", Text: "auf Batterie"}}
		}
		return []model.Service{s}
	}
	fake := &fakeCol{svcs: ups(0, 300)}
	rt := hostWithFake(t, m, fake)
	m.poll(ctx, rt)
	adoptAll(t, m, rt.host.UID)
	m.poll(ctx, rt)
	if st := svcState(rt, "ups:ups"); st != eval.OK {
		t.Fatalf("mains: short runtime estimate must not alert, got %v", st)
	}
	fake.set(ups(1, 300), nil)
	m.poll(ctx, rt)
	if st := svcState(rt, "ups:ups"); st != eval.Crit {
		t.Fatalf("on battery below 10 min: crit, got %v", st)
	}
	fake.set(ups(1, 900), nil)
	m.poll(ctx, rt)
	if st := svcState(rt, "ups:ups"); st != eval.Warn {
		t.Fatalf("on battery above 10 min: warn (on battery), got %v", st)
	}
	fake.set(ups(0, 300), nil)
	m.poll(ctx, rt)
	if st := svcState(rt, "ups:ups"); st != eval.OK {
		t.Fatalf("back on mains: ok, got %v", st)
	}
}

// KE4: Geraete-APIs (NUT, TrueNAS, Unraid, Redfish) gehen bei gleichen Schluesseln vor SNMP.
func TestAccessRankDeviceAPIsBeforeSNMP(t *testing.T) {
	for _, typ := range []string{"nut", "truenas", "unraid", "redfish", "pve"} {
		if accessRank(typ) != 2 {
			t.Errorf("%s: rank %d, want 2 (before snmp %d)", typ, accessRank(typ), accessRank("snmp"))
		}
	}
}

// KE5: nicht vorgeschlagene Dienste (z. B. einzelne Windows-Dienste) werden als "ignoriert" eingetragen und sind so
// spaeter uebernehmbar; werden sie vorgeschlagen, rutschen sie zu den neuen; vom Benutzer ignorierte bleiben ignoriert.
func TestDiscoveryKeepsNonDefaultAdoptable(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	nd := func(key, kind string) model.Service { return model.Service{Key: key, Name: key, Kind: kind} }
	fake := &fakeCol{svcs: []model.Service{svc("winsvc", "winsvc"), nd("winsvc:Spooler", "winsvc"), nd("if:eth1", "if"), svc("if:eth0", "if")}}
	rt := hostWithFake(t, m, fake)
	uid := rt.host.UID
	m.poll(ctx, rt)
	adopted := func() map[string]int {
		rows, _ := m.store.Services(ctx, uid)
		out := map[string]int{}
		for _, r := range rows {
			out[r.Key] = r.Adopted
		}
		return out
	}
	got := adopted()
	if got["winsvc"] != 0 || got["winsvc:Spooler"] != -1 || got["if:eth1"] != -1 {
		t.Fatalf("after discovery: %v", got)
	}
	if rt.getView().New != 2 {
		t.Fatalf("not proposed services must not count as new: %d", rt.getView().New)
	}
	if err := m.store.SetAdopted(ctx, uid, "winsvc:Spooler", 1, testActor); err != nil {
		t.Fatalf("non-default service must be adoptable: %v", err)
	}
	if err := m.store.SetAdopted(ctx, uid, "if:eth0", -1, testActor); err != nil {
		t.Fatal(err)
	}
	// naechste Erkennung: eth1 jetzt vorgeschlagen (Link), eth0 bleibt vom Benutzer ignoriert
	fake.set([]model.Service{svc("winsvc", "winsvc"), nd("winsvc:Spooler", "winsvc"), svc("if:eth1", "if"), svc("if:eth0", "if")}, nil)
	rt.mu.Lock()
	rt.LastDisc = time.Time{}
	rt.mu.Unlock()
	m.poll(ctx, rt)
	got = adopted()
	if got["if:eth1"] != 0 || got["if:eth0"] != -1 || got["winsvc:Spooler"] != 1 {
		t.Fatalf("after rediscovery: %v", got)
	}
}

// closeCol zaehlt close().
type closeCol struct {
	fakeCol
	mu     sync.Mutex
	closed int
}

func (c *closeCol) close() { c.mu.Lock(); c.closed++; c.mu.Unlock() }

// AP7: Stop schliesst die Sammler (z. B. Redfish-Sitzungen abmelden).
func TestStopClosesCollectors(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	col := &closeCol{}
	h := &Host{Name: "h1", Address: "192.0.2.1", IntervalSec: 60}
	if err := m.store.SaveHost(ctx, h, SystemActor); err != nil {
		t.Fatal(err)
	}
	m.ReloadHost(ctx, h.UID)
	m.rtMu.Lock()
	m.rts[h.UID].accs = []*accRT{{row: &Access{UID: "acc1", HostUID: h.UID, Type: "redfish", Enabled: true}, col: col}}
	m.rtMu.Unlock()
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	col.mu.Lock()
	defer col.mu.Unlock()
	if col.closed != 1 {
		t.Fatalf("collector closed %d times, want 1", col.closed)
	}
}

// Test mit drei Nodes: eine gerade abgetrennte Node (Mitglieder schweigen, gelten aber noch 2 min als online) meldet
// Hosts mit Ersatz-Node nicht, bis klar ist, ob die Mehrheit bleibt; ohne Ersatz meldet sie weiter.
func TestClusterSilentPeersHoldReport(t *testing.T) {
	b := newBus(t)
	n := b.newNode("c", "C", 1, false)
	own := &Host{UID: "host00000001", PreferredNode: "c", BackupNodes: []string{"a"}}
	alone := &Host{UID: "host00000002", PreferredNode: "c"}
	s := snapOf("c", map[string]bool{"a": true, "b": true})
	s.Peers["a"] = ClusterPeer{ID: "a", Online: true, Silent: true}
	s.Peers["b"] = ClusterPeer{ID: "b", Online: true, Silent: true}
	s.Unsure = true
	n.m.cl.snap.Store(s)
	if r, _ := n.m.roleOf(own); r != roleMeasure {
		t.Fatalf("silent peers, host with backup: role %d, want measure", r)
	}
	if r, _ := n.m.roleOf(alone); r != roleReport {
		t.Fatalf("silent peers, host without backup: role %d, want report", r)
	}
}
