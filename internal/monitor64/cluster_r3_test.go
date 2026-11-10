package monitor64

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/module"
)

// Tests zu Runde 3 (bekannte Luecken): Mini-Verlaeufe fremder Hosts, verwaiste Hosts, Fehlschlag beim Schreiben ins
// Cluster-Protokoll, Laufzeit-Luecken auf den Statusseiten, merkbarer Zustand der Sammler (NUT), Traps bei Uebernahme.

// r3Host legt einen Host ohne Zugang an und plant ihn ein.
func r3Host(t *testing.T, m *Module, name, preferred string, backups ...string) *Host {
	t.Helper()
	h := &Host{Name: name, Address: "192.0.2.50", Kind: "ssh", IntervalSec: 60, PreferredNode: preferred, BackupNodes: backups}
	if err := m.store.SaveHost(context.Background(), h, testActor); err != nil {
		t.Fatal(err)
	}
	m.ReloadHost(context.Background(), h.UID)
	return h
}

// Luecke 1: Mini-Verlaeufe eines Hosts, den eine andere Node ueberwacht, kommen gebuendelt von dieser Node - eine
// Anfrage, fuer sparksCacheFor gemerkt; nicht erreichbar bzw. Fehler: leer ohne Fehler.
func TestClusterSparksRemote(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, true)
	bb := b.newNode("node-b", "B", 2, true)
	own := r3Host(t, a.m, "own", "")
	h1 := r3Host(t, bb.m, "remote1", "node-b")
	h2 := r3Host(t, bb.m, "remote2", "node-b")
	b.sync()
	b.tick()
	if role, owner := a.m.roleOf(a.rt(t, h1.UID).host); role != roleIdle || owner != "node-b" {
		t.Fatalf("A must be idle for B's host: %d %s", role, owner)
	}
	at := time.Now().Add(-time.Minute)
	a.m.appendSeries(own.UID, "cpu", "util", at, 11)
	bb.m.appendSeries(h1.UID, "cpu", "util", at, 42.123456)
	bb.m.appendSeries(h2.UID, "cpu", "util", at, 7)
	var calls atomic.Int32
	hooks := a.m.hooks()
	orig := hooks.Call
	hooks.Call = func(ctx context.Context, node, name string, in, out any) error {
		if name == callSparks {
			calls.Add(1)
		}
		return orig(ctx, node, name, in, out)
	}
	a.m.SetCluster(hooks)
	items := []sparkItem{{ID: own.UID, Host: own.UID, Svc: "cpu", Metric: "util"}, {ID: h1.UID, Host: h1.UID, Svc: "cpu", Metric: "util"},
		{ID: h2.UID, Host: h2.UID, Svc: "cpu", Metric: "util"}}
	out, err := a.m.sparks(ctx, "", items)
	if err != nil || len(out[own.UID]) != 1 || out[own.UID][0] != 11 || len(out[h1.UID]) != 1 || out[h1.UID][0] != 42.12 || len(out[h2.UID]) != 1 {
		t.Fatalf("sparks: %v %v", out, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("one request per node, got %d", calls.Load())
	}
	if out, _ = a.m.sparks(ctx, "", items); len(out[h1.UID]) != 1 || calls.Load() != 1 {
		t.Fatalf("second call must come from the cache: %v, %d calls", out, calls.Load())
	}
	b.advance(sparksCacheFor + time.Second)
	if out, _ = a.m.sparks(ctx, "", items); len(out[h1.UID]) != 1 || calls.Load() != 2 {
		t.Fatalf("after the cache time: %v, %d calls", out, calls.Load())
	}
	// B nicht erreichbar: leer, kein Fehler, keine Anfrage; eigene Hosts bleiben
	b.isolate(bb)
	a.m.clusterRefresh(ctx)
	b.advance(sparksCacheFor + time.Second)
	out, err = a.m.sparks(ctx, "", items)
	if err != nil || len(out[h1.UID]) != 0 || len(out[own.UID]) != 1 || calls.Load() != 2 {
		t.Fatalf("unreachable node: %v %v, %d calls", out, err, calls.Load())
	}
	// B erreichbar, aber Monitor64 dort gestoppt (Anfrage scheitert): leer, kein Fehler
	b.join()
	a.m.clusterRefresh(ctx)
	_ = bb.m.Stop(ctx)
	b.advance(sparksCacheFor + time.Second)
	out, err = a.m.sparks(ctx, "", items)
	if err != nil || len(out[h1.UID]) != 0 || len(out[own.UID]) != 1 || calls.Load() != 3 {
		t.Fatalf("failed request: %v %v, %d calls", out, err, calls.Load())
	}
	// Anfrage streng geprueft
	for _, body := range []string{`{"items":[]}`, `{"items":[{"h":"x","s":"cpu","m":"util"}]}`, `{"items":[{"h":"` + own.UID + `","s":"","m":"util"}]}`} {
		if _, err := a.m.HandleClusterCall(ctx, "node-b", callSparks, []byte(body)); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
}

// Luecke 3: scheitert das Eintragen ins Protokoll des Clusters, gilt der Eintrag nicht als gemeldet - der naechste Lauf
// meldet ihn erneut (Suche und direkte Meldungen).
func TestClusterScanRetriesFailedChange(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, false)
	a.m.clusterScan(ctx)
	a.failChange.Store(true)
	h := &Host{Name: "h", Address: "192.0.2.51", Kind: "ssh", IntervalSec: 60}
	if err := a.m.store.SaveHost(ctx, h, testActor); err != nil {
		t.Fatal(err)
	}
	_ = a.m.st.SetSetting(ctx, setInterval, "120")
	a.m.clusterScan(ctx)
	a.m.clusterChange(ctx, ClusterItemConfig, "owner:"+h.UID, false) // direkte Meldung (z. B. Uebernahme)
	if _, ok := a.logged(ClusterItemConfig, "host:"+h.UID); ok {
		t.Fatal("change logged although the log failed")
	}
	if a.m.csyncGet(ctx, "host", h.UID) != "" || a.m.csyncGet(ctx, "setting", setInterval) != "" {
		t.Fatal("entry marked as reported although the log failed")
	}
	a.m.clusterScan(ctx) // weiter gestoert: bleibt offen
	a.failChange.Store(false)
	a.m.clusterScan(ctx)
	for _, id := range []string{"host:" + h.UID, "setting:" + setInterval, "owner:" + h.UID} {
		if _, ok := a.logged(ClusterItemConfig, id); !ok {
			t.Errorf("%s not reported after the log works again", id)
		}
	}
	if a.m.csyncGet(ctx, "host", h.UID) == "" || len(a.m.cl.retry) != 0 {
		t.Fatalf("state after retry: stamp %q, %d pending", a.m.csyncGet(ctx, "host", h.UID), len(a.m.cl.retry))
	}
}

// Luecke 2: verwaiste Hosts (Node nicht mehr im Cluster bzw. keine Kandidatin) auflisten, dieser Node zuweisen und
// entfernen - einzeln und alle, nur fuer Hosts, die gerade verwaist sind.
func TestClusterOrphans(t *testing.T) {
	ctx := context.Background()
	var peers atomic.Pointer[[]ClusterPeer]
	peers.Store(&[]ClusterPeer{{ID: "node-b", Name: "node02", Online: false}})
	e := newEnvWith(t, func(m *Module) {
		_ = m.st.SetSetting(ctx, "node.name", "node01")
		m.SetCluster(ClusterHooks{Self: func() string { return "node-a" }, Members: func(context.Context, string) []ClusterPeer { return *peers.Load() }})
	})
	m := e.m
	own := r3Host(t, m, "own", "")
	foreign := r3Host(t, m, "foreign", "node-b")           // B ist Mitglied (offline): nicht verwaist
	gone := r3Host(t, m, "gone", "node-x", "node-y")       // bevorzugte und Ersatz-Node entfernt
	covered := r3Host(t, m, "covered", "node-x", "node-b") // Ersatz-Node B ist Mitglied: sie uebernimmt
	type resp struct {
		Done    int         `json:"done"`
		Orphans []orphanOut `json:"orphans"`
	}
	list := func() []orphanOut {
		t.Helper()
		var r resp
		rec := e.do("GET", "/api/monitor64/cluster/orphans", nil)
		if rec.Code != 200 {
			t.Fatalf("orphans: %d %s", rec.Code, rec.Body.String())
		}
		decodeBody(t, rec.Body.Bytes(), &r)
		return r.Orphans
	}
	if l := list(); len(l) != 1 || l[0].UID != gone.UID || l[0].Reason != orphanNoCandidate || l[0].Node != "node-x" {
		t.Fatalf("cluster active: %+v", l)
	}
	// ohne Auswahl: Fehler; nicht verwaiste Hosts werden uebergangen
	if rec := e.do("POST", "/api/monitor64/cluster/orphans/remove", map[string]any{}); rec.Code != 400 {
		t.Fatalf("empty selection: %d", rec.Code)
	}
	var r resp
	rec := e.do("POST", "/api/monitor64/cluster/orphans/remove", map[string]any{"uids": []string{own.UID, foreign.UID}})
	decodeBody(t, rec.Body.Bytes(), &r)
	if rec.Code != 200 || r.Done != 0 {
		t.Fatalf("healthy hosts must be skipped: %d %+v", rec.Code, r)
	}
	if _, err := m.store.Host(ctx, own.UID); err != nil {
		t.Fatal("own host removed")
	}
	// zuweisen: diese Node ist bevorzugt und zustaendig, entfernte Ersatz-Node faellt weg, Ereignis im Verlauf
	rec = e.do("POST", "/api/monitor64/cluster/orphans/assign", map[string]any{"uids": []string{gone.UID}})
	decodeBody(t, rec.Body.Bytes(), &r)
	if rec.Code != 200 || r.Done != 1 || len(r.Orphans) != 0 {
		t.Fatalf("assign: %d %+v", rec.Code, r)
	}
	g, _ := m.store.Host(ctx, gone.UID)
	if g.PreferredNode != "node-a" || g.OwnerNode != "node-a" || len(g.BackupNodes) != 0 {
		t.Fatalf("assigned host: %+v", g)
	}
	if role, _ := m.roleOf(g); role != roleReport {
		t.Fatalf("role after assign: %d", role)
	}
	if e.col(`SELECT COUNT(*) FROM m64_events WHERE host_uid = ? AND kind = 'takeover'`, gone.UID) != "1" || !e.audited("monitor64.host.cluster.assign") {
		t.Fatal("takeover event or audit missing")
	}
	// Cluster verlassen: die Hosts der anderen Nodes sind verwaist (auch in den Daten der Uebersicht)
	peers.Store(&[]ClusterPeer{})
	l := list()
	if len(l) != 2 || l[0].UID != covered.UID || l[1].UID != foreign.UID || l[0].Reason != orphanNodeGone || l[1].Node != "node-b" {
		t.Fatalf("without cluster: %+v", l)
	}
	var views clusterViewsOut
	decodeBody(t, e.do("GET", "/api/monitor64/cluster/views", nil).Body.Bytes(), &views)
	if len(views.Orphans) != 2 {
		t.Fatalf("overview data: %+v", views.Orphans)
	}
	mustContain(t, "overview", e.do("GET", "/monitor64", nil).Body.String(), `id="m64-orphans"`, `"orphans":[{"uid":"`+covered.UID+`"`, `"reason":"node_gone"`)
	// alle entfernen: nur die verwaisten
	rec = e.do("POST", "/api/monitor64/cluster/orphans/remove", map[string]any{"all": true})
	decodeBody(t, rec.Body.Bytes(), &r)
	if rec.Code != 200 || r.Done != 2 || len(r.Orphans) != 0 {
		t.Fatalf("remove all: %d %+v", rec.Code, r)
	}
	hosts, _ := m.store.Hosts(ctx)
	var names []string
	for _, h := range hosts {
		names = append(names, h.Name)
	}
	slices.Sort(names)
	if strings.Join(names, ",") != "gone,own" {
		t.Fatalf("remaining hosts: %v", names)
	}
	if m.viewOf(foreign.UID) != nil {
		t.Fatal("removed host still scheduled")
	}
}

// Luecke 4: Zeiten, in denen Monitor64 nicht lief, zaehlen auf den Statusseiten weder als beobachtet noch als
// Stoerung; im Cluster nur, wenn keine Node des Hosts lief. Der Herzschlag macht aus einer Pause ab 5 min eine Luecke.
func TestStatusFeedGaps(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	_ = m.st.SetSetting(ctx, "node.id", "node-a")
	now := time.Now().UTC().Truncate(time.Second)
	hr := func(n int) time.Time { return now.Add(time.Duration(n) * time.Hour) }

	// Herzschlag: 2 min Pause zaehlt nicht, 6 Std. schon (Luecke vom letzten Herzschlag bis jetzt)
	m.uptimeMark(ctx, hr(-9))
	m.uptimeMark(ctx, hr(-9).Add(2*time.Minute))
	m.uptimeMark(ctx, hr(-8))
	var n int
	_ = m.st.Reader().QueryRow(`SELECT COUNT(*) FROM m64_gaps`).Scan(&n)
	if n != 1 { // 9 h -> 8 h: 58 min Pause
		t.Fatalf("gaps after heartbeats: %d", n)
	}
	_, _ = m.st.Writer().Exec(`DELETE FROM m64_gaps`)
	m.uptimeMark(ctx, hr(-2)) // letzter Herzschlag vor 8 Std., Start vor 2 Std.: Luecke -8 h .. -2 h
	var from, to string
	if err := m.st.Reader().QueryRow(`SELECT from_at, to_at FROM m64_gaps WHERE node_id = 'node-a'`).Scan(&from, &to); err != nil || !parseTS(from).Equal(hr(-8)) || !parseTS(to).Equal(hr(-2)) {
		t.Fatalf("gap: %s .. %s (%v)", from, to, err)
	}

	h := statusTestHost(t, m, "nas01", "", false, hr(-60))
	statusTestProblem(t, m, h.UID, "", time.Time{}, false, statusTestEv{hr(-10), "unreachable"}) // offen seit 10 Std.
	q := module.StatusQuery{Sources: []string{StatusSourceHost(h.UID)}, Bounds: []time.Time{hr(-24), now}, History: hr(-24), Now: now}
	res, err := m.StatusSources(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	src := res[StatusSourceHost(h.UID)]
	if src == nil || len(src.Bars) != 1 || src.Bars[0].Observed != 18*time.Hour || src.Bars[0].Down != 4*time.Hour {
		t.Fatalf("bars with gap: %+v", src)
	}
	// die Stoerung laeuft nicht durch die Luecke: -10..-8 h und -2 h..jetzt (laeuft)
	if len(src.Incidents) != 2 || !src.Incidents[0].Start.Equal(hr(-2)) || !src.Incidents[0].End.IsZero() || !src.Incidents[1].Start.Equal(hr(-10)) || !src.Incidents[1].End.Equal(hr(-8)) {
		t.Fatalf("incidents: %+v", src.Incidents)
	}

	// Cluster: Luecke einer anderen Node kommt ueber den Abgleich; sie zaehlt nur, wenn keine Node des Hosts lief
	gb := gapID("node-b", hr(-20))
	if err := m.ClusterApply(ctx, ClusterItemStatus, gb, json.RawMessage(`{"to":"`+ts(hr(-14))+`"}`), false); err != nil {
		t.Fatal(err)
	}
	if err := m.ClusterApply(ctx, ClusterItemStatus, gapID("node-b", hr(-5)), json.RawMessage(`{"to":"`+ts(hr(-3))+`"}`), false); err != nil {
		t.Fatal(err)
	}
	if m.ClusterApply(ctx, ClusterItemStatus, gapID("node-b", hr(-1)), json.RawMessage(`{"to":"`+ts(hr(-2))+`"}`), false) == nil {
		t.Fatal("gap ending before its start accepted")
	}
	onlyB := statusTestHost(t, m, "nur-b", "", false, hr(-60))
	both := statusTestHost(t, m, "b-mit-ersatz", "", false, hr(-60))
	_, _ = m.st.Writer().Exec(`UPDATE m64_hosts SET preferred_node = 'node-b' WHERE uid IN (?, ?)`, onlyB.UID, both.UID)
	_, _ = m.st.Writer().Exec(`UPDATE m64_hosts SET backup_nodes = '["node-a"]' WHERE uid = ?`, both.UID)
	q.Sources = []string{StatusSourceHost(onlyB.UID), StatusSourceHost(both.UID)}
	if res, err = m.StatusSources(ctx, q); err != nil {
		t.Fatal(err)
	}
	// nur B: 6 h + 2 h fehlen; B mit Ersatz A: nur die Zeit, in der beide nicht liefen (-5..-3 h liegt in A's Luecke)
	if o := res[StatusSourceHost(onlyB.UID)].Bars[0].Observed; o != 16*time.Hour {
		t.Fatalf("host of node-b: observed %v", o)
	}
	if o := res[StatusSourceHost(both.UID)].Bars[0].Observed; o != 22*time.Hour {
		t.Fatalf("host with backup node: observed %v", o)
	}

	// eigene Luecken gehen an den Cluster (Kennung, Inhalt), fremde nicht von hier
	ids, err := m.ClusterIDs(ctx, ClusterItemStatus)
	own := gapID("node-a", hr(-8))
	if err != nil || !slices.Contains(ids, own) || slices.Contains(ids, gb) {
		t.Fatalf("ids: %v %v", ids, err)
	}
	data, found, err := m.ClusterGet(ctx, ClusterItemStatus, own)
	if err != nil || !found || !strings.Contains(string(data), ts(hr(-2))) {
		t.Fatalf("get: %s %v %v", data, found, err)
	}
	// Aufbewahrung wie die Probleme; ein Vermerk entfernt die Luecke einer anderen Node
	if err := m.ClusterApply(ctx, ClusterItemStatus, gb, nil, true); err != nil {
		t.Fatal(err)
	}
	m.purgeGaps(ctx, ts(hr(-2).Add(-30*time.Minute)))
	_ = m.st.Reader().QueryRow(`SELECT COUNT(*) FROM m64_gaps`).Scan(&n)
	if n != 1 { // geblieben: A -8..-2 h (B -5..-3 h ist aelter als die Aufbewahrung)
		t.Fatalf("gaps after purge: %d", n)
	}
}

// Luecke 5: der merkbare Zustand eines Sammlers laeuft fuer NUT ueber dieselbe Mechanik wie die SNMP-Ports - "upsd hat
// schon TLS gesprochen" kommt aus dem Laufzeitstand zurueck und gilt nur fuer dieselbe Adresse.
func TestMemoNUT(t *testing.T) {
	m, _, _ := newTestModule(t)
	h := &Host{Address: "192.0.2.71"}
	col, err := m.newAPICollector(&Access{Type: "nut"}, h, accessConfig{}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer col.close()
	if l, ch := memoChanged(col, nil); ch || l != nil {
		t.Fatalf("fresh collector: %v %v", l, ch)
	}
	restoreMemo(col, []string{"tls:192.0.2.99:3493"}) // andere Adresse: gilt nicht
	if _, ch := memoChanged(col, nil); ch {
		t.Fatal("state of another address accepted")
	}
	restoreMemo(col, []string{"tls:192.0.2.71:3493"})
	l, ch := memoChanged(col, nil)
	if !ch || !slices.Equal(l, []string{"tls:192.0.2.71:3493"}) {
		t.Fatalf("restored: %v %v", l, ch)
	}
	if _, ch := memoChanged(col, l); ch {
		t.Fatal("unchanged reported as changed")
	}
}

// Luecke 6: bei einer Uebernahme macht die neue zustaendige Node mit dem Trap-Stand der bisherigen weiter (offene Traps
// bleiben offen, nichts doppelt); die abgebende zaehlt danach keinen mehr als offen.
func TestTrapStateOnTakeover(t *testing.T) {
	t0 := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	e := func(min int, oid string, handled bool) trapEntry {
		return trapEntry{Time: t0.Add(time.Duration(min) * time.Minute), Version: "2c", TrapOID: oid, Handled: handled}
	}
	tm := newTrapMgr(nil)
	// hier: ein alter Eintrag (vor dem Stand der anderen Node, dort bekannt) und zwei neuere, die hier blieben
	tm.hosts["h"] = &hostTraps{List: []trapEntry{e(-10, "1.3.6.1.4.1.1", false), e(1, "1.3.6.1.4.1.3", false), e(2, "1.3.6.1.6.3.1.1.5.3", true)}, Pending: 2, Total: 3}
	from := &hostTraps{List: []trapEntry{e(-10, "1.3.6.1.4.1.1", false), e(-5, "1.3.6.1.4.1.2", false)}, Pending: 2, Total: 5}
	for i := 0; i < 2; i++ { // mehrfach uebernehmen zaehlt nichts doppelt
		tm.adopt("h", from, t0)
		s := tm.snapshot("h", true)
		if s.Pending != 3 || s.Total != 7 || len(s.List) != 4 || s.List[0].TrapOID != "1.3.6.1.4.1.1" || s.List[1].TrapOID != "1.3.6.1.4.1.2" || s.List[3].TrapOID != "1.3.6.1.6.3.1.1.5.3" {
			t.Fatalf("adopt %d: %+v", i, s)
		}
	}
	// die andere Node hat inzwischen zurueckgesetzt (kein Trap offen): ihr Stand gilt
	tm.adopt("h", &hostTraps{Total: 9}, t0.Add(5*time.Minute))
	if s := tm.snapshot("h", true); s.Pending != 0 || s.Total != 9 || len(s.List) != 4 {
		t.Fatalf("adopt after reset: %+v", s)
	}
	tm.hosts["h"].Pending = 2
	if !tm.handedOver("h") || tm.snapshot("h", false).Pending != 0 || tm.handedOver("h") {
		t.Fatal("handed over: nothing may stay open")
	}
	// Anzeige: derselbe Trap von beiden Nodes steht einmal
	out := mergeTrapsOut(hostTrapsOut{List: []trapEntry{e(1, "a", false)}, Pending: 1}, hostTrapsOut{List: []trapEntry{e(1, "a", false), e(0, "b", false)}})
	if len(out.List) != 2 || out.Pending != 1 || out.List[0].TrapOID != "a" {
		t.Fatalf("merged view: %+v", out)
	}

	// im Ablauf: Stand der bisher zustaendigen Node (m64_cstate) -> adoptState uebernimmt die offenen Traps
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, false)
	h := &Host{Name: "sw01", Address: "192.0.2.60", Kind: "snmp", IntervalSec: 60}
	if err := a.m.store.SaveHost(ctx, h, testActor); err != nil {
		t.Fatal(err)
	}
	rtJSON, _ := json.Marshal(&hostRT{Traps: &hostTraps{List: []trapEntry{e(-5, "1.3.6.1.4.1.2", false)}, Pending: 1, Total: 4}})
	st, _ := json.Marshal(stateEntry{Node: "node-b", At: time.Now().UTC(), Reporting: true, RT: rtJSON})
	if _, err := a.m.st.Writer().Exec(`INSERT INTO m64_cstate (host_uid, node_id, data, at) VALUES (?, 'node-b', ?, ?)`, h.UID, string(st), tsNow()); err != nil {
		t.Fatal(err)
	}
	rt := &hostRT{host: h, accs: []*accRT{{row: &Access{UID: "acc", Type: "snmp", Enabled: true, Config: json.RawMessage(`{"traps":true}`)}}}}
	rt.initMaps()
	rt.mu.Lock()
	a.m.adoptState(ctx, rt)
	svc, _, ok := a.m.trapService(rt)
	rt.mu.Unlock()
	if s := a.m.traps.snapshot(h.UID, true); !ok || s == nil || s.Pending != 1 || s.Total != 4 || len(s.List) != 1 || len(svc.Facts) != 1 || rt.Traps == nil || rt.Traps.Pending != 1 {
		t.Fatalf("after takeover: %+v, facts %d", s, len(svc.Facts))
	}
}
