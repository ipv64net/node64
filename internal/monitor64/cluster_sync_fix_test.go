package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/monitor64/eval"
)

// Regressionstests zu den Funden im Cluster-Abgleich (C1-*, SW1, UI5, Hintergrund-Umstellung).

func withOrigin(ctx context.Context, node string, at time.Time) context.Context {
	return context.WithValue(ctx, originKey{}, originVal{node, at})
}

func (n *busNode) logged(item, id string) (busEntry, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	e, ok := n.log[item+"|"+id]
	return e, ok
}

func keyState(t *testing.T, n *busNode) keyInfo {
	t.Helper()
	ki, err := n.m.keyInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return ki
}

// C1-1: Die alten Schluessel bleiben, bis jeder Zugang clusterweit umgestellt ist - auch deaktivierte Zugaenge und
// Hosts, fuer die die Node nur Ersatz ist; Umstellungen und Bestaetigungen anderer Nodes kommen ueber den Cluster.
func TestClusterKeyRetireWaitsForCluster(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, true)
	c := b.newNode("node-c", "C", 2, true)
	fh := &fakeHost{fsUsed: 40}
	port, keysFile := startAgent(t, fh, keyLine(t, a), keyLine(t, c))
	addAgentHost(t, c, "c-host", port, "node-a") // C bevorzugt, A Ersatz
	off := &Host{Name: "off-host", Address: "127.0.0.1", Kind: "linux-agent", IntervalSec: 60, PreferredNode: "node-c"}
	if err := c.m.store.SaveHost(ctx, off, testActor); err != nil {
		t.Fatal(err)
	}
	offAcc := &Access{HostUID: off.UID, Type: "agent", Config: []byte(`{"port":1}`), Enabled: false} // gerade abgeschaltet
	if err := c.m.store.SaveAccess(ctx, offAcc, false, testActor); err != nil {
		t.Fatal(err)
	}
	b.sync()
	b.tick() // A bringt den Cluster-Schluessel ein, C uebernimmt ihn
	if keyOf(keyLine(t, c)) != keyOf(keyLine(t, a)) {
		t.Fatal("C must use the cluster key")
	}
	c.m.switchAgents(ctx, true)
	c.m.cl.bg.Wait()
	if ki := keyState(t, c); len(ki.Pending) != 1 || ki.Pending[0].AccessUID != offAcc.UID || len(ki.OldKeys) != 1 {
		t.Fatalf("disabled access must keep C's old key: %+v", ki)
	}

	// Wechsel auf C: A (nur Ersatz fuer c-host) behaelt den alten Schluessel, bis C den Agent umgestellt hat
	if err := c.m.RotateKey(ctx); err != nil {
		t.Fatal(err)
	}
	c.m.cl.bg.Wait()
	b.sync()
	lineN := keyLine(t, c)
	if keyOf(keyLine(t, a)) != keyOf(lineN) {
		t.Fatal("rotated key must reach A")
	}
	a.m.switchAgents(ctx, true)
	a.m.cl.bg.Wait()
	if ki := keyState(t, a); len(ki.OldKeys) != 1 || len(ki.Pending) != 2 {
		t.Fatalf("backup node must keep its old key while the agent is not switched: %+v", ki)
	}
	c.m.switchAgents(ctx, true)
	c.m.cl.bg.Wait()
	if raw := readFile(t, keysFile); keyOf(raw) != keyOf(lineN) {
		t.Fatalf("agent keys: %q", raw)
	}
	b.sync() // C meldet die Umstellung im Cluster
	a.m.switchAgents(ctx, false)
	a.m.cl.bg.Wait()
	if ki := keyState(t, a); len(ki.Pending) != 1 || ki.Pending[0].AccessUID != offAcc.UID || len(ki.OldKeys) != 1 {
		t.Fatalf("A learns the switch from C, the disabled access stays open: %+v", ki)
	}

	// Bestaetigen auf C (Eintrag verwerfen) gilt clusterweit; danach sind die alten Schluessel ueberall weg
	req := httptest.NewRequest(http.MethodPost, "/api/monitor64/cluster/keys/confirm", strings.NewReader(`{"access_uid":"`+offAcc.UID+`"}`))
	rec := httptest.NewRecorder()
	c.m.apiClusterKeyConfirm(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body.String())
	}
	c.m.cl.bg.Wait()
	if ki := keyState(t, c); len(ki.Pending) != 0 || len(ki.OldKeys) != 0 {
		t.Fatalf("C: all switched, old keys must be gone: %+v", ki)
	}
	b.sync()
	a.m.switchAgents(ctx, false)
	a.m.cl.bg.Wait()
	if ki := keyState(t, a); len(ki.Pending) != 0 || len(ki.OldKeys) != 0 {
		t.Fatalf("A: confirmation from C must arrive: %+v", ki)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// C1-1 (K1/K2, veraltete Liste): ein Lauf, der mit dem vorigen Schluessel begann, verwirft nichts; ein Zugang, der
// nach dem Wechsel dazukam, haelt die alten Schluessel fest.
func TestKeyRetireRace(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, false)
	if _, err := a.m.PublicKeyLine(ctx); err != nil {
		t.Fatal(err)
	}
	k1 := a.m.currentKeyFP(ctx)
	if err := a.m.RotateKey(ctx); err != nil {
		t.Fatal(err)
	}
	a.m.cl.bg.Wait()
	a.m.maybeRetireOldKeys(ctx, k1) // Lauf begann vor dem Wechsel
	if len(a.m.oldKeys(ctx)) != 1 {
		t.Fatal("a run of the previous key must not retire the old keys")
	}
	// Agent kommt nach dem Wechsel dazu (z. B. Import, Uebernahme aus dem Cluster)
	h := &Host{Name: "new", Address: "127.0.0.1", IntervalSec: 60}
	_ = a.m.store.SaveHost(ctx, h, testActor)
	_ = a.m.store.SaveAccess(ctx, &Access{HostUID: h.UID, Type: "agent", Config: []byte(`{"port":1}`), Enabled: true}, false, testActor)
	a.m.switchAgents(ctx, true)
	if len(a.m.oldKeys(ctx)) != 1 || len(a.m.keyPendingList(ctx)) != 1 {
		t.Fatal("a new access after the switch must keep the old keys")
	}
	a.m.markKeyDone(ctx, a.m.currentKeyFP(ctx), a.m.keyPendingListUIDs(t)...) // z. B. von einer anderen Node gemeldet
	a.m.maybeRetireOldKeys(ctx, a.m.currentKeyFP(ctx))
	if len(a.m.oldKeys(ctx)) != 0 {
		t.Fatal("nothing open: old keys must be retired")
	}
}

func (m *Module) keyPendingListUIDs(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, p := range m.keyPendingList(context.Background()) {
		out = append(out, p.AccessUID)
	}
	return out
}

// C1-2: Benachrichtigung im Cluster - Kanaele nur der Empfaengerin bleiben dort, geteilte gelten wie geliefert, die
// gekuerzte Fassung ueberschreibt drueben nichts.
func TestClusterNotifyKeepsLocalChannels(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, false)
	c := b.newNode("node-c", "C", 2, false)
	ch := func(n *busNode, id int, uid string) {
		if _, err := n.m.st.Writer().Exec(`INSERT INTO nf_channels (id, type, name, config, uid, created_at, updated_at) VALUES (?, 'ntfy', ?, '{}', ?, '', '')`, id, uid, uid); err != nil {
			t.Fatal(err)
		}
	}
	ch(a, 5, "chan-shared-0001")
	ch(c, 9, "chan-shared-0001")
	ch(a, 6, "chan-a-only-0001")
	ch(c, 3, "chan-c-sms-00001")
	putNotify := func(n *busNode, routes ...eval.ChannelRoute) {
		nc := eval.DefaultNotifyConfig([]string{defaultChannels})
		nc.Channels = append(nc.Channels, routes...)
		raw, _ := json.Marshal(nc)
		_ = n.m.st.SetSetting(ctx, setNotify, string(raw))
	}
	ids := func(n *busNode) map[string]bool {
		var nc eval.NotifyConfig
		_ = json.Unmarshal([]byte(n.m.st.SettingOr(ctx, setNotify, "")), &nc)
		out := map[string]bool{}
		for _, r := range nc.Channels {
			out[r.ID] = true
		}
		return out
	}
	putNotify(c, eval.ChannelRoute{ID: "3", Crit: true}) // SMS nur auf C
	c.m.clusterScan(ctx)
	time.Sleep(5 * time.Millisecond)
	putNotify(a, eval.ChannelRoute{ID: "5", Crit: true}, eval.ChannelRoute{ID: "6", Warn: true})
	b.sync()
	if got := ids(c); !got["9"] || !got["3"] || !got[defaultChannels] || len(got) != 3 {
		t.Fatalf("C must keep its own channel and map the shared one: %v", got)
	}
	if got := ids(a); !got["5"] || !got["6"] || len(got) != 3 {
		t.Fatalf("A changed by C's merged version: %v", got)
	}
	// Aenderung auf C geht zurueck: A behaelt seinen nur dort bekannten Kanal
	var nc eval.NotifyConfig
	_ = json.Unmarshal([]byte(c.m.st.SettingOr(ctx, setNotify, "")), &nc)
	nc.CritInQuiet = true
	raw, _ := json.Marshal(nc)
	time.Sleep(5 * time.Millisecond)
	_ = c.m.st.SetSetting(ctx, setNotify, string(raw))
	b.sync()
	if got := ids(a); !got["5"] || !got["6"] || got["3"] || len(got) != 3 {
		t.Fatalf("A must keep its local channel after C's change: %v", got)
	}
	// geteilter Kanal auf A entfernt: auf C weg, SMS bleibt
	time.Sleep(5 * time.Millisecond)
	putNotify(a, eval.ChannelRoute{ID: "6", Warn: true})
	b.sync()
	if got := ids(c); got["9"] || !got["3"] {
		t.Fatalf("removed shared route must be removed on C, local one kept: %v", got)
	}

	// Abweichung (Benachrichtigung): lokale Kanaele der Empfaengerin bleiben bei einer Aenderung der anderen Node
	o := &overrideRow{Scope: "notify", TargetType: "group", Target: "Keller", Data: json.RawMessage(`{"channels":[{"id":"5","warn":true,"crit":true}],"replace":true}`)}
	if err := a.m.store.SaveOverride(ctx, o, testActor); err != nil {
		t.Fatal(err)
	}
	b.sync()
	oc := &overrideRow{UID: o.UID, Scope: "notify", TargetType: "group", Target: "Keller", Data: json.RawMessage(`{"channels":[{"id":"9","warn":true,"crit":true},{"id":"3","crit":true}],"replace":true}`)}
	time.Sleep(5 * time.Millisecond)
	if err := c.m.store.SaveOverride(ctx, oc, testActor); err != nil {
		t.Fatal(err)
	}
	b.sync()
	time.Sleep(5 * time.Millisecond)
	o.Data = json.RawMessage(`{"channels":[{"id":"5","warn":true,"crit":true}],"replace":false}`)
	if err := a.m.store.SaveOverride(ctx, o, testActor); err != nil {
		t.Fatal(err)
	}
	b.sync()
	list, _ := c.m.store.Overrides(ctx, "notify")
	if len(list) != 1 || !strings.Contains(string(list[0].Data), `"id":"3"`) || !strings.Contains(string(list[0].Data), `"id":"9"`) ||
		!strings.Contains(string(list[0].Data), `"replace":false`) {
		t.Fatalf("override on C: %+v", list)
	}
}

// C1-3: Ein Loeschvermerk mit kleinerer Kennung verdraengt keinen lebenden Dienst der anderen Node.
func TestClusterDuplicateDeletedRow(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, false)
	c := b.newNode("node-c", "C", 2, false)
	h := &Host{Name: "h", Address: "10.0.0.1", IntervalSec: 60}
	_ = a.m.store.SaveHost(ctx, h, testActor)
	b.sync()
	if _, err := c.m.st.Writer().Exec(`INSERT INTO m64_services (uid, host_uid, key, updated_at, deleted) VALUES ('--------', ?, 'if:eth0', ?, 1)`, h.UID, tsNow()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.m.store.UpsertDiscovered(ctx, h.UID, []Service{{Key: "if:eth0", Kind: "if"}}, map[string]bool{"if:eth0": true}, testActor); err != nil {
		t.Fatal(err)
	}
	b.sync()
	var ua, uc string
	_ = a.m.st.Reader().QueryRow(`SELECT uid FROM m64_services WHERE host_uid = ? AND key = 'if:eth0' AND deleted = 0`, h.UID).Scan(&ua)
	_ = c.m.st.Reader().QueryRow(`SELECT uid FROM m64_services WHERE host_uid = ? AND key = 'if:eth0' AND deleted = 0`, h.UID).Scan(&uc)
	if ua == "" || uc != ua {
		t.Fatalf("living service must replace the deleted one on C: A %q, C %q", ua, uc)
	}
}

// C1-4: Verschieben einer Abweichung aendert die Aenderungszeit aller verschobenen Zeilen (sonst bleibt die
// Reihenfolge drueben falsch); ein Import mit alten Aenderungszeiten geht trotzdem an den Cluster.
func TestClusterMoveOverrideAndImport(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, false)
	c := b.newNode("node-c", "C", 2, false)
	var uids []string
	for _, g := range []string{"X", "Y", "Z"} {
		o := &overrideRow{Scope: "rule", TargetType: "group", Target: g, Kind: "fs.used", Data: json.RawMessage(`{"warn":80}`)}
		if err := a.m.store.SaveOverride(ctx, o, testActor); err != nil {
			t.Fatal(err)
		}
		uids = append(uids, o.UID)
	}
	b.sync()
	time.Sleep(5 * time.Millisecond)
	if err := a.m.store.MoveOverride(ctx, "rule", uids[2], -1, testActor); err != nil { // Z nach oben: X, Z, Y
		t.Fatal(err)
	}
	b.sync()
	order := func(n *busNode) string {
		list, _ := n.m.store.Overrides(ctx, "rule")
		var s []string
		for _, o := range list {
			s = append(s, o.Target)
		}
		return strings.Join(s, ",")
	}
	if order(a) != "X,Z,Y" || order(c) != "X,Z,Y" {
		t.Fatalf("order A %s, C %s", order(a), order(c))
	}

	// Import mit alten Zeiten: der Abgleich findet die Zeilen trotzdem
	a.m.clusterScan(ctx)
	raw := `{"version":1,"tables":{"m64_hosts":[{"uid":"importhost01","name":"alt","address":"10.0.0.9","kind":"","group_name":"","tags":"[]",
		"interval_sec":60,"owner_node":"","preferred_node":"","backup_nodes":"[]","agent_autoupd":1,"paused":0,"notes":"","created_at":"2020-01-01T00:00:00.000Z",
		"created_by":"{}","updated_at":"2020-01-01T00:00:00.000Z","updated_by":"{}","deleted":0}]}}`
	if _, err := a.m.Import(ctx, json.RawMessage(raw)); err != nil {
		t.Fatal(err)
	}
	a.m.clusterScan(ctx)
	if _, ok := a.logged(ClusterItemConfig, "host:importhost01"); !ok {
		t.Fatal("imported host with an old change time not announced")
	}
}

// C1-5 und Umstellung per Knopf: die Umstellung der Agents laeuft im Hintergrund (der Ablauf des Clusters und die API
// warten nicht auf haengende Agents), nie zweimal zugleich; Wuensche waehrend eines Laufs werden zu genau einem
// weiteren Lauf.
func TestKeySwitchBackground(t *testing.T) {
	ctx := context.Background()
	old := keySwitchLimit
	keySwitchLimit = 700 * time.Millisecond
	t.Cleanup(func() { keySwitchLimit = old })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { // nimmt an und schweigt (haengender Agent)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, true)
	h := &Host{Name: "hang", Address: "127.0.0.1", Kind: "linux-agent", IntervalSec: 900}
	_ = a.m.store.SaveHost(ctx, h, testActor)
	acc := &Access{HostUID: h.UID, Type: "agent", Config: []byte(`{"port":` + port + `}`), Enabled: true}
	_ = a.m.store.SaveAccess(ctx, acc, false, testActor)
	a.m.ReloadHost(ctx, h.UID)
	if _, err := a.m.PublicKeyLine(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := a.m.st.Writer().Exec(`INSERT INTO m64_keypending (access_uid, host_uid, type, target_fp, created_at) VALUES (?, ?, 'agent', ?, ?)`,
		acc.UID, h.UID, a.m.currentKeyFP(ctx), tsNow()); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	a.m.clusterKeys(ctx, snapOf("node-a", nil))
	a.m.clusterKeys(ctx, snapOf("node-a", nil))
	req := httptest.NewRequest(http.MethodPost, "/api/monitor64/cluster/keys/retry", nil)
	rec := httptest.NewRecorder()
	a.m.apiClusterKeyRetry(rec, req)
	if d := time.Since(start); d > 400*time.Millisecond {
		t.Fatalf("cluster tick and API must not wait for the agent: %s", d)
	}
	var ki keyInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &ki); err != nil || rec.Code != http.StatusOK || !ki.Running {
		t.Fatalf("retry: %d %s", rec.Code, rec.Body.String())
	}
	a.m.cl.bg.Wait()
	var tries int
	_ = a.m.st.Reader().QueryRow(`SELECT tries FROM m64_keypending WHERE access_uid = ?`, acc.UID).Scan(&tries)
	if tries != 2 { // erster Lauf, danach genau einer (ohne Wartezeit wegen "erneut versuchen")
		t.Fatalf("runs: %d", tries)
	}
	if a.m.keySwitchRunning() {
		t.Fatal("still running")
	}
}

// C1-6: Eine beitretende Node verwirft den Cluster-Schluessel ihres frueheren Clusters (sonst wechselte der ganze
// Cluster auf ihn) und uebernimmt den des Clusters.
func TestClusterJoinedDropsOwnKey(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, false)
	j := b.newNode("node-j", "J", 2, false)
	b.isolate(j)
	bringIn := func(n *busNode, at time.Time) {
		s, err := n.m.nodeSigner(ctx)
		if err != nil {
			t.Fatal(err)
		}
		pem, _ := n.m.box.Decrypt(n.m.st.SettingOr(ctx, setNodeKey, ""))
		if err := n.m.useKey(ctx, pem, s, at, true); err != nil {
			t.Fatal(err)
		}
	}
	bringIn(a, time.Now().Add(-time.Hour))
	time.Sleep(5 * time.Millisecond)
	bringIn(j, time.Now()) // frueherer Cluster von J, juenger als der von A
	lineA, lineJ := keyLine(t, a), keyLine(t, j)
	forget := j.m.ClusterJoined(ctx)
	for _, f := range forget { // wie peer.joined: Vermerke der genannten Eintraege aus dem Protokoll
		item, id, _ := strings.Cut(f, "/")
		if e, ok := j.logged(item, id); ok && e.deleted {
			j.mu.Lock()
			delete(j.log, item+"|"+id)
			j.mu.Unlock()
		}
	}
	b.join()
	b.sync()
	if keyOf(keyLine(t, a)) != keyOf(lineA) {
		t.Fatal("the cluster switched to the key of the joining node")
	}
	if keyOf(keyLine(t, j)) != keyOf(lineA) {
		t.Fatal("joining node must take the cluster key")
	}
	if ki := keyState(t, j); len(ki.OldKeys) != 1 || ki.OldKeys[0] == "" || !ki.Cluster {
		t.Fatalf("joining node keeps its previous key for its agents: %+v", ki)
	}
	_ = lineJ
}

// C1-7: Werte der anderen Node werden vor dem Speichern geprueft (Typ, Bereich, Groesse).
func TestClusterRowValidation(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, false)
	c := b.newNode("node-c", "C", 2, false)
	h := &Host{Name: "h", Address: "10.0.0.1", IntervalSec: 60, Tags: []string{"x"}}
	_ = a.m.store.SaveHost(ctx, h, testActor)
	data, _, err := a.m.ClusterGet(ctx, ClusterItemConfig, "host:"+h.UID)
	if err != nil {
		t.Fatal(err)
	}
	mut := func(k string, v any) json.RawMessage {
		var row map[string]any
		_ = json.Unmarshal(data, &row)
		row[k] = v
		out, _ := json.Marshal(row)
		return out
	}
	octx := withOrigin(ctx, "node-a", time.Now())
	for _, bad := range []json.RawMessage{
		mut("interval_sec", nil), mut("interval_sec", "abc"), mut("interval_sec", 1e9), mut("paused", 7), mut("tags", "kein json"),
		mut("backup_nodes", `["../x"]`), mut("updated_at", "gestern"), mut("name", strings.Repeat("x", 5000)), mut("created_by", 5),
	} {
		if err := c.m.ClusterApply(octx, ClusterItemConfig, "host:"+h.UID, bad, false); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	if hosts, err := c.m.store.Hosts(ctx); err != nil || len(hosts) != 0 {
		t.Fatalf("hosts on C: %v %v", hosts, err)
	}
	if err := c.m.ClusterApply(octx, ClusterItemConfig, "host:"+h.UID, data, false); err != nil {
		t.Fatal(err)
	}
	if hosts, err := c.m.store.Hosts(ctx); err != nil || len(hosts) != 1 {
		t.Fatalf("valid host: %v %v", hosts, err)
	}
}

// C1-8: Eine noch nicht gemeldete, juengere Aenderung hier bleibt und geht an den Cluster; eine aeltere wird
// ueberschrieben.
func TestClusterKeepsNewerLocalChange(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, false)
	c := b.newNode("node-c", "C", 2, false)
	h := &Host{Name: "h", Address: "10.0.0.1", IntervalSec: 60}
	_ = a.m.store.SaveHost(ctx, h, testActor)
	b.sync()
	setNotes := func(n *busNode, s string) {
		hh, err := n.m.store.Host(ctx, h.UID)
		if err != nil {
			t.Fatal(err)
		}
		hh.Notes = s
		if err := n.m.store.SaveHost(ctx, hh, testActor); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	deliver := func() error { // Stand von A kommt bei C an, bevor C seine Aenderung gemeldet hat
		a.m.clusterScan(ctx)
		e, _ := a.logged(ClusterItemConfig, "host:"+h.UID)
		data, _, _ := a.m.ClusterGet(ctx, ClusterItemConfig, "host:"+h.UID)
		return c.m.ClusterApply(withOrigin(ctx, e.origin, e.at), ClusterItemConfig, "host:"+h.UID, data, false)
	}
	notes := func() string { hh, _ := c.m.store.Host(ctx, h.UID); return hh.Notes }

	setNotes(a, "von A")
	setNotes(c, "von C") // juenger, noch nicht gemeldet
	err := deliver()
	var sup interface{ Superseded() bool }
	if !errors.As(err, &sup) || notes() != "von C" {
		t.Fatalf("newer local change lost: %v %q", err, notes())
	}
	if e, ok := c.logged(ClusterItemConfig, "host:"+h.UID); !ok || e.origin != "node-c" {
		t.Fatal("kept local change must be announced")
	}
	b.sync()
	if hh, _ := a.m.store.Host(ctx, h.UID); hh.Notes != "von C" {
		t.Fatalf("A must get C's newer change: %q", hh.Notes)
	}

	setNotes(c, "alt C") // aelter als die folgende Aenderung auf A
	setNotes(a, "neu A")
	if err := deliver(); err != nil || notes() != "neu A" {
		t.Fatalf("older local change must be replaced: %v %q", err, notes())
	}
}

// SW1: Import mit Schluessel der Node wie ein Wechsel - der bisherige bleibt fuer die Agents, der Cluster erfaehrt ihn.
func TestImportNodeKeyKeepsOld(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	src := b.newNode("node-s", "S", 1, false)
	dst := b.newNode("node-d", "D", 2, false)
	b.isolate(src)
	if _, err := src.m.PublicKeyLine(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.m.PublicKeyLine(ctx); err != nil {
		t.Fatal(err)
	}
	before := dst.m.currentKeyFP(ctx)
	sctx := module.WithSecretSealer(ctx, rot13{})
	exp, err := src.m.Export(sctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(exp)
	if _, err := dst.m.Import(sctx, raw); err != nil {
		t.Fatal(err)
	}
	dst.m.cl.bg.Wait()
	ki := keyState(t, dst)
	if ki.Fingerprint != src.m.currentKeyFP(ctx) || len(ki.OldKeys) != 1 || ki.OldKeys[0] != before {
		t.Fatalf("imported key must become current, the previous one stays: %+v", ki)
	}
	if _, ok := dst.logged(ClusterItemConfig, "key:cluster"); !ok {
		t.Fatal("imported key must be announced to the cluster")
	}
}

// UI5: "von allen Nodes testen" - Zugaenge je Node nebeneinander, eigene Pruefung neben den Anfragen.
func TestClusterReachParallel(t *testing.T) {
	ctx := context.Background()
	old := reachTest
	reachTest = func(_ *Module, ctx context.Context, _ *Host, _ Access) testResult {
		select {
		case <-time.After(300 * time.Millisecond):
		case <-ctx.Done():
		}
		return testResult{OK: true, Ms: 300}
	}
	t.Cleanup(func() { reachTest = old })
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, true)
	c := b.newNode("node-c", "C", 2, true)
	h := &Host{Name: "r", Address: "127.0.0.1", Kind: "ssh", IntervalSec: 900, Paused: true}
	_ = a.m.store.SaveHost(ctx, h, testActor)
	for i := 0; i < 3; i++ {
		_ = a.m.store.SaveAccess(ctx, &Access{HostUID: h.UID, Type: "ssh", Config: []byte(`{"port":1,"user":"x"}`), Secret: a.m.box.Encrypt("pw"), Enabled: true}, false, testActor)
	}
	b.sync()
	_ = c
	start := time.Now()
	res, err := a.m.reachHere(ctx, h.UID)
	if err != nil || len(res) != 3 || !res[0].OK || !res[2].OK {
		t.Fatalf("reach: %+v %v", res, err)
	}
	if d := time.Since(start); d > 600*time.Millisecond {
		t.Fatalf("accesses tested one after the other: %s", d)
	}
	a.m.clusterRefresh(ctx)
	req := httptest.NewRequest(http.MethodPost, "/api/monitor64/cluster/hosts/"+h.UID+"/reach", nil)
	req.SetPathValue("uid", h.UID)
	rec := httptest.NewRecorder()
	start = time.Now()
	a.m.apiClusterReach(rec, req)
	if d := time.Since(start); d > 550*time.Millisecond {
		t.Fatalf("own check and peers one after the other: %s", d)
	}
	var out struct {
		Nodes []reachNodeOut `json:"nodes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Nodes) != 2 || !out.Nodes[0].Self || !out.Nodes[0].OK || !out.Nodes[1].OK {
		t.Fatalf("reach answer: %s", rec.Body.String())
	}
}
