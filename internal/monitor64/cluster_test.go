package monitor64

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64agent"
	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/tsdb"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

// Tests des Clusters: ein Schein-Cluster im Prozess (fakeBus) mit getrennten Datenbanken je Node. Er fuehrt wie
// internal/peer je Node ein Protokoll (letzter Stand je Eintrag, juengere Aenderung gewinnt, Herkunft bleibt beim
// Weiterreichen), holt bei verbundenen Nodes ab und beantwortet Anfragen (Call) direkt. Trennen und Wiederverbinden
// ueber cut/join; "offline" heisst hier: nach der Karenz des Clusters (peer: 2 min ohne Antwort).

type originKey struct{}

type originVal struct {
	node string
	at   time.Time
}

func init() {
	SetClusterOrigin(func(ctx context.Context) (string, time.Time, bool) {
		o, ok := ctx.Value(originKey{}).(originVal)
		return o.node, o.at, ok
	})
}

type busEntry struct {
	item, id, origin string
	at               time.Time
	deleted          bool
}

type busNode struct {
	id, name string
	m        *Module
	bus      *fakeBus
	mu       sync.Mutex
	log      map[string]busEntry
	amu      sync.Mutex
	alerts   []notify.Alert
}

type fakeBus struct {
	t     *testing.T
	mu    sync.Mutex
	nodes []*busNode
	cut   map[string]bool
	now   time.Time
}

func newBus(t *testing.T) *fakeBus {
	t.Helper()
	oldScan, oldTick, oldWait, oldKey, oldLag := clusterScanEvery, clusterTick, clusterStartWait, clusterKeyWait, clusterReloadLag
	clusterScanEvery, clusterTick, clusterStartWait, clusterKeyWait, clusterReloadLag = time.Hour, time.Hour, 0, 0, time.Hour
	t.Cleanup(func() {
		clusterScanEvery, clusterTick, clusterStartWait, clusterKeyWait, clusterReloadLag = oldScan, oldTick, oldWait, oldKey, oldLag
	})
	return &fakeBus{t: t, cut: map[string]bool{}, now: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
}

func (b *fakeBus) clock() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.now
}

func (b *fakeBus) advance(d time.Duration) {
	b.mu.Lock()
	b.now = b.now.Add(d)
	b.mu.Unlock()
}

func pairKey(x, y string) string {
	if x > y {
		x, y = y, x
	}
	return x + "|" + y
}

func (b *fakeBus) connected(x, y string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return x == y || !b.cut[pairKey(x, y)]
}

// isolate trennt n von allen anderen; join verbindet alle wieder.
func (b *fakeBus) isolate(n *busNode) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, o := range b.nodes {
		if o != n {
			b.cut[pairKey(n.id, o.id)] = true
		}
	}
}

func (b *fakeBus) join() {
	b.mu.Lock()
	b.cut = map[string]bool{}
	b.mu.Unlock()
}

// list: die Nodes (die Module laufen nebenher und fragen nach den Mitgliedern).
func (b *fakeBus) list() []*busNode {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*busNode(nil), b.nodes...)
}

func (b *fakeBus) node(id string) *busNode {
	for _, n := range b.list() {
		if n.id == id {
			return n
		}
	}
	return nil
}

// newNode legt eine Node mit eigener Datenbank und eigenem Schluessel der Geheimnisse an (gestartet: start).
func (b *fakeBus) newNode(id, name string, boxKey byte, start bool) *busNode {
	t := b.t
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(context.Background(), filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cm, _ := store.CoreMigrations()
	if err := st.Migrate(context.Background(), "core", cm); err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(context.Background(), Name, Migrations()); err != nil {
		t.Fatal(err)
	}
	nm, _ := notify.Migrations()
	if err := st.Migrate(context.Background(), "notify", nm); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_ = st.SetSetting(ctx, "node.id", id)
	_ = st.SetSetting(ctx, "node.name", name)
	box, err := secrets.New(bytes.Repeat([]byte{boxKey}, 32))
	if err != nil {
		t.Fatal(err)
	}
	n := &busNode{id: id, name: name, bus: b, log: map[string]busEntry{}}
	n.m = New(st, log, box, dir, "test")
	n.m.SetNotifier(func(a notify.Alert) { n.amu.Lock(); n.alerts = append(n.alerts, a); n.amu.Unlock() })
	n.m.cl.now = b.clock
	n.m.SetCluster(ClusterHooks{
		Change: func(ctx context.Context, item, eid string, deleted bool) {
			e := busEntry{item: item, id: eid, origin: id, at: time.Now().UTC().Truncate(time.Millisecond), deleted: deleted}
			if o, ok := ctx.Value(originKey{}).(originVal); ok {
				e.origin, e.at = o.node, o.at
			}
			n.mu.Lock()
			n.log[item+"|"+eid] = e
			n.mu.Unlock()
		},
		Members: func(_ context.Context, _ string) []ClusterPeer {
			var out []ClusterPeer
			for _, o := range b.list() {
				if o != n {
					out = append(out, ClusterPeer{ID: o.id, Name: o.name, Online: b.connected(n.id, o.id)})
				}
			}
			return out
		},
		Self: func() string { return id },
		Call: func(ctx context.Context, node, name string, in, out any) error {
			o := b.node(node)
			if o == nil || !b.connected(id, node) {
				return errors.New("not reachable")
			}
			body, _ := json.Marshal(in)
			res, err := o.m.HandleClusterCall(ctx, id, name, body)
			if err != nil {
				return err
			}
			raw, _ := json.Marshal(res)
			if out != nil {
				return json.Unmarshal(raw, out)
			}
			return nil
		},
	})
	b.mu.Lock()
	b.nodes = append(b.nodes, n)
	b.mu.Unlock()
	if start {
		if err := n.m.Start(ctx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = n.m.Stop(context.Background()) })
	}
	return n
}

func newerThan(e busEntry, l busEntry, ok bool) bool {
	return !ok || e.at.After(l.at) || e.at.Equal(l.at) && e.origin > l.origin
}

// sync: alle Nodes melden ihre Aenderungen, verbundene holen voneinander ab (mehrere Runden: Weiterreichen).
func (b *fakeBus) sync() {
	ctx := context.Background()
	for round := 0; round < 3; round++ {
		for _, n := range b.nodes {
			n.m.clusterScan(ctx)
		}
		for _, dst := range b.nodes {
			for _, src := range b.nodes {
				if src == dst || !b.connected(src.id, dst.id) {
					continue
				}
				src.mu.Lock()
				list := make([]busEntry, 0, len(src.log))
				for _, e := range src.log {
					list = append(list, e)
				}
				src.mu.Unlock()
				for _, e := range list {
					if e.origin == dst.id {
						continue
					}
					dst.mu.Lock()
					l, ok := dst.log[e.item+"|"+e.id]
					dst.mu.Unlock()
					if !newerThan(e, l, ok) {
						continue
					}
					data, found, err := src.m.ClusterGet(ctx, e.item, e.id)
					if err != nil {
						continue
					}
					err = dst.m.ClusterApply(context.WithValue(ctx, originKey{}, originVal{e.origin, e.at}), e.item, e.id, data, e.deleted || !found)
					var sup interface{ Superseded() bool }
					switch {
					case err == nil:
						dst.mu.Lock()
						dst.log[e.item+"|"+e.id] = e
						dst.mu.Unlock()
					case errors.As(err, &sup):
					default:
						b.t.Logf("%s: apply %s %s from %s: %v", dst.name, e.item, e.id, src.name, err)
					}
				}
			}
		}
	}
	for _, n := range b.nodes {
		n.m.clusterFlush(ctx)
		n.m.cl.bg.Wait()
	}
}

// tick: Blick auf den Cluster auf allen Nodes, danach abgleichen.
func (b *fakeBus) tick() {
	for _, n := range b.nodes {
		n.m.ClusterTick(context.Background())
	}
	b.sync()
}

func (n *busNode) rt(t *testing.T, uid string) *hostRT {
	t.Helper()
	n.m.rtMu.Lock()
	defer n.m.rtMu.Unlock()
	rt := n.m.rts[uid]
	if rt == nil {
		t.Fatalf("%s: host %s not loaded", n.name, uid)
	}
	return rt
}

func (n *busNode) poll(t *testing.T, uid string) *HostView {
	t.Helper()
	rt := n.rt(t, uid)
	n.m.poll(context.Background(), rt)
	return rt.getView()
}

func (n *busNode) alertCount() int {
	n.amu.Lock()
	defer n.amu.Unlock()
	return len(n.alerts)
}

func (n *busNode) lastAlert() notify.Alert {
	n.amu.Lock()
	defer n.amu.Unlock()
	if len(n.alerts) == 0 {
		return notify.Alert{}
	}
	return n.alerts[len(n.alerts)-1]
}

func (n *busNode) openProblems(t *testing.T, host string) map[string]string { // Dienst -> Node
	t.Helper()
	out := map[string]string{}
	rows, err := n.m.st.Reader().Query(`SELECT service_key, node_id FROM m64_problems WHERE host_uid = ? AND closed_at = '' AND deleted = 0`, host)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var k, node string
		_ = rows.Scan(&k, &node)
		out[k+"@"+node] = node
	}
	return out
}

func (n *busNode) owner(t *testing.T, host string) string {
	t.Helper()
	h, err := n.m.store.Host(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	return ownerOf(h, n.id)
}

var testActor = Actor{Kind: "user", Name: "dennis", Method: "local"}

// startAgent startet einen Agent im Prozess, der den Schluesseln der Nodes vertraut (keys: Zeilen fuer authorized_keys).
func startAgent(t *testing.T, fh *fakeHost, keys ...string) (port string, keysFile string) {
	t.Helper()
	adir := t.TempDir()
	keysFile = filepath.Join(adir, "keys")
	if err := os.WriteFile(keysFile, []byte(strings.Join(keys, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hk, err := m64agent.LoadOrCreateHostKey(filepath.Join(adir, "hostkey"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := m64agent.New(m64agent.Config{HostKey: hk, KeysFile: keysFile, Collector: fh, Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, port, _ = net.SplitHostPort(ln.Addr().String())
	return port, keysFile
}

func keyLine(t *testing.T, n *busNode) string {
	t.Helper()
	l, err := n.m.PublicKeyLine(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// keyOf: Schluessel einer Zeile ohne Kommentar (der Kommentar nennt die Node).
func keyOf(line string) string {
	f := strings.Fields(line)
	if len(f) < 2 {
		return line
	}
	return f[0] + " " + f[1]
}

// addAgentHost legt auf n einen Host mit Agent-Zugang an und uebernimmt alle erkannten Dienste.
func addAgentHost(t *testing.T, n *busNode, name, port string, backups ...string) *Host {
	t.Helper()
	ctx := context.Background()
	h := &Host{Name: name, Address: "127.0.0.1", Kind: "linux-agent", IntervalSec: 60, BackupNodes: backups}
	if err := n.m.store.SaveHost(ctx, h, testActor); err != nil {
		t.Fatal(err)
	}
	if err := n.m.store.SaveAccess(ctx, &Access{HostUID: h.UID, Type: "agent", Config: []byte(`{"port":` + port + `}`), Enabled: true}, false, testActor); err != nil {
		t.Fatal(err)
	}
	n.m.ReloadHost(ctx, h.UID)
	n.poll(t, h.UID)
	rows, _ := n.m.store.Services(ctx, h.UID)
	for _, r := range rows {
		_ = n.m.store.SetAdopted(ctx, h.UID, r.Key, 1, testActor)
	}
	return h
}

// ---------------------------------------------------------------------------------------------------------
// Regeln ohne Netz

func snapOf(self string, peers map[string]bool, stable ...string) *clusterSnap {
	s := &clusterSnap{Self: self, Peers: map[string]ClusterPeer{}, Stable: map[string]bool{}}
	for id, on := range peers {
		s.Peers[id] = ClusterPeer{ID: id, Name: id, Online: on}
	}
	for _, id := range stable {
		s.Stable[id] = true
	}
	s.Active = len(s.Peers) > 0
	s.Total, s.Connected = len(s.Peers)+1, 1
	for _, p := range s.Peers {
		if p.Online {
			s.Connected++
		}
	}
	s.Majority = s.Connected*2 > s.Total || s.Total == 2
	return s
}

func TestClusterOwnerRules(t *testing.T) {
	h := func(pref, owner string, backups ...string) *Host {
		return &Host{UID: "host00000001", PreferredNode: pref, OwnerNode: owner, BackupNodes: backups}
	}
	cases := []struct {
		name      string
		host      *Host
		snap      *clusterSnap
		want, how string
	}{
		{"owner online: nothing", h("a", "", "b"), snapOf("b", map[string]bool{"a": true, "c": true}, "a", "c"), "", ""},
		{"takeover by first backup", h("a", "", "b"), snapOf("b", map[string]bool{"a": false, "c": true}, "c"), "b", "takeover"},
		{"second backup waits for first", h("a", "", "b", "c"), snapOf("c", map[string]bool{"a": false, "b": true}, "b"), "", ""},
		{"second backup when first is gone", h("a", "", "b", "c"), snapOf("c", map[string]bool{"a": false, "b": false, "d": true, "e": true}, "d", "e"), "c", "takeover"},
		{"no takeover without majority (3 nodes, cut off)", h("a", "", "c"), snapOf("c", map[string]bool{"a": false, "b": false}), "", ""},
		{"two nodes: takeover allowed", h("a", "", "b"), snapOf("b", map[string]bool{"a": false}), "b", "takeover"},
		{"not a candidate: no takeover", h("a", ""), snapOf("b", map[string]bool{"a": false, "c": true}, "c"), "", ""},
		{"return when preferred stable", h("a", "b", "b"), snapOf("b", map[string]bool{"a": true, "c": true}, "a", "c"), "a", "handover"},
		{"no return before stable", h("a", "b", "b"), snapOf("b", map[string]bool{"a": true, "c": true}, "c"), "", ""},
		{"owner not candidate any more hands over", h("a", "c", "b"), snapOf("c", map[string]bool{"a": false, "b": true}, "b"), "b", "handover"},
	}
	for _, c := range cases {
		got, how := decideOwner(c.host, c.snap)
		if got != c.want || how != c.how {
			t.Errorf("%s: got %q/%q, want %q/%q", c.name, got, how, c.want, c.how)
		}
	}
}

func TestClusterRoles(t *testing.T) {
	b := newBus(t)
	n := b.newNode("c", "C", 1, false)
	set := func(s *clusterSnap) { n.m.cl.snap.Store(s) }
	own := &Host{UID: "host00000001", PreferredNode: "c", BackupNodes: []string{"a"}}
	alone := &Host{UID: "host00000002", PreferredNode: "c"}
	other := &Host{UID: "host00000003", PreferredNode: "a"}

	set(snapOf("c", map[string]bool{"a": true, "b": true}))
	if r, _ := n.m.roleOf(own); r != roleReport {
		t.Fatalf("with majority: %d", r)
	}
	if r, o := n.m.roleOf(other); r != roleIdle || o != "a" {
		t.Fatalf("other node's host: %d %s", r, o)
	}
	// C abgetrennt (1 von 3): eigener Host mit Ersatz misst nur, ohne Ersatz meldet weiter
	set(snapOf("c", map[string]bool{"a": false, "b": false}))
	if r, _ := n.m.roleOf(own); r != roleMeasure {
		t.Fatalf("cut off with backup must only measure: %d", r)
	}
	if r, _ := n.m.roleOf(alone); r != roleReport {
		t.Fatalf("own host without backup keeps reporting: %d", r)
	}
	// zwei Nodes getrennt: beide melden (Sonderfall)
	set(snapOf("c", map[string]bool{"a": false}))
	if r, _ := n.m.roleOf(own); r != roleReport {
		t.Fatalf("two nodes: owner keeps reporting: %d", r)
	}
	// ohne Cluster: jede Node meldet die Hosts, fuer die sie bevorzugt ist
	set(&clusterSnap{Self: "c"})
	if r, _ := n.m.roleOf(alone); r != roleReport {
		t.Fatalf("without cluster, own host: %d", r)
	}
	if r, o := n.m.roleOf(other); r != roleIdle || o != "a" {
		t.Fatalf("without cluster, host of another node: %d %s", r, o)
	}
}

// Abgleich der Konfiguration: Get/Apply rund, Geheimnis mit dem Schluessel der Empfaengerin, Kanaele ueber ihre
// Kennung, Loeschen, Dienst-Doppel (kleinere Kennung gilt), Einstellungen; uebernommene Staende gehen nicht zurueck.
func TestClusterConfigRoundTrip(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, false)
	c := b.newNode("node-c", "C", 2, false) // anderer Schluessel der Geheimnisse
	// Kanal mit gleicher Kennung, aber anderer Nummer auf beiden Nodes
	if _, err := a.m.st.Writer().Exec(`INSERT INTO nf_channels (id, type, name, config, uid, created_at, updated_at) VALUES (5, 'ntfy', 'Handy', '{}', 'chan-uid-1', '', '')`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.m.st.Writer().Exec(`INSERT INTO nf_channels (id, type, name, config, uid, created_at, updated_at) VALUES (9, 'ntfy', 'Handy', '{}', 'chan-uid-1', '', '')`); err != nil {
		t.Fatal(err)
	}

	h := &Host{Name: "nas01", Address: "10.0.0.5", Kind: "ssh", Group: "Keller", Tags: []string{"nas"}, IntervalSec: 60, BackupNodes: []string{"node-c"}}
	if err := a.m.store.SaveHost(ctx, h, testActor); err != nil {
		t.Fatal(err)
	}
	acc := &Access{HostUID: h.UID, Type: "ssh", Config: json.RawMessage(`{"user":"monitor64"}`), Secret: a.m.box.Encrypt("pw-geheim"), HostKey: "SHA256:abc", Enabled: true}
	if err := a.m.store.SaveAccess(ctx, acc, false, testActor); err != nil {
		t.Fatal(err)
	}
	if _, err := a.m.store.UpsertDiscovered(ctx, h.UID, []Service{{Key: "fs:/", Name: "/", Kind: "fs"}}, map[string]bool{"fs:/": true}, testActor); err != nil {
		t.Fatal(err)
	}
	nc := eval.DefaultNotifyConfig([]string{defaultChannels})
	nc.Channels = append(nc.Channels, eval.ChannelRoute{ID: "5", Crit: true})
	ncb, _ := json.Marshal(nc)
	_ = a.m.st.SetSetting(ctx, setNotify, string(ncb))
	_ = a.m.st.SetSetting(ctx, setWorkers, "99") // nur lokal
	b.sync()

	hc, err := c.m.store.Host(ctx, h.UID)
	if err != nil {
		t.Fatalf("host did not arrive: %v", err)
	}
	if hc.Name != "nas01" || hc.Group != "Keller" || len(hc.Tags) != 1 || hc.PreferredNode != "node-a" || len(hc.BackupNodes) != 1 {
		t.Fatalf("host on C: %+v", hc)
	}
	accs, _ := c.m.store.Accesses(ctx, h.UID)
	if len(accs) != 1 || accs[0].HostKey != "SHA256:abc" {
		t.Fatalf("access on C: %+v", accs)
	}
	if plain, err := c.m.box.Decrypt(accs[0].Secret); err != nil || plain != "pw-geheim" {
		t.Fatalf("secret must be stored with C's key: %q %v", plain, err)
	}
	if _, err := a.m.box.Decrypt(accs[0].Secret); err == nil {
		t.Fatal("secret on C readable with A's key")
	}
	notifyC := c.m.st.SettingOr(ctx, setNotify, "")
	if !strings.Contains(notifyC, `"id":"9"`) || strings.Contains(notifyC, `"id":"5"`) {
		t.Fatalf("channel not mapped to C's number: %s", notifyC)
	}
	if c.m.st.SettingOr(ctx, setWorkers, "") != "" {
		t.Fatal("workers must stay local")
	}
	svcs, _ := c.m.store.Services(ctx, h.UID)
	if len(svcs) != 1 || svcs[0].Adopted != 1 {
		t.Fatalf("services on C: %+v", svcs)
	}
	// nichts kommt als eigene Aenderung von C zurueck
	c.m.clusterScan(ctx)
	c.mu.Lock()
	for _, e := range c.log {
		if e.origin == "node-c" {
			t.Errorf("C re-announced %s %s", e.item, e.id)
		}
	}
	c.mu.Unlock()

	// Aenderung auf C kommt bei A an (juengere gewinnt)
	hc.Notes = "von C"
	if err := c.m.store.SaveHost(ctx, hc, testActor); err != nil {
		t.Fatal(err)
	}
	b.sync()
	if ha, _ := a.m.store.Host(ctx, h.UID); ha.Notes != "von C" {
		t.Fatalf("update from C: %q", ha.Notes)
	}

	// Dienst-Doppel: derselbe Dienst auf beiden Nodes mit eigener Kennung -> die kleinere gilt ueberall
	_, _ = a.m.store.UpsertDiscovered(ctx, h.UID, []Service{{Key: "if:eth0", Kind: "if"}}, nil, SystemActor)
	_, _ = c.m.store.UpsertDiscovered(ctx, h.UID, []Service{{Key: "if:eth0", Kind: "if"}}, nil, SystemActor)
	b.sync()
	uidOf := func(n *busNode) string {
		var u string
		_ = n.m.st.Reader().QueryRow(`SELECT uid FROM m64_services WHERE host_uid = ? AND key = 'if:eth0' AND deleted = 0`, h.UID).Scan(&u)
		return u
	}
	if ua, uc := uidOf(a), uidOf(c); ua == "" || ua != uc {
		t.Fatalf("service duplicate not merged: %q / %q", ua, uc)
	}

	// Loeschen auf A: Host samt Zugang auf C weg
	if err := a.m.store.DeleteHost(ctx, h.UID, testActor); err != nil {
		t.Fatal(err)
	}
	b.sync()
	if _, err := c.m.store.Host(ctx, h.UID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("host still on C: %v", err)
	}
	if accs, _ := c.m.store.Accesses(ctx, h.UID); len(accs) != 0 {
		t.Fatal("access still on C")
	}
}

// Ein Zugang, dessen Geheimnis die liefernde Node nicht lesen kann, geht als "incomplete" und aendert drueben nichts.
func TestClusterIncompleteSecret(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, false)
	h := &Host{Name: "x", IntervalSec: 60}
	_ = a.m.store.SaveHost(ctx, h, testActor)
	other, _ := secrets.New(bytes.Repeat([]byte{9}, 32))
	acc := &Access{HostUID: h.UID, Type: "ssh", Secret: other.Encrypt("fremd"), Enabled: true} // mit einem anderen Schluessel
	_ = a.m.store.SaveAccess(ctx, acc, false, testActor)
	data, found, err := a.m.ClusterGet(ctx, ClusterItemConfig, "access:"+acc.UID)
	if err != nil || !found || string(data) != `{"incomplete":true}` {
		t.Fatalf("got %s %v %v", data, found, err)
	}
}

// Doppelt offene Probleme (Split-Brain) schliesst die nicht zustaendige Node; die zustaendige fuehrt Probleme anderer
// Nodes weiter.
func TestClusterProblemsHandover(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, false)
	h := &Host{Name: "h", IntervalSec: 60, PreferredNode: "node-b"}
	_ = a.m.store.SaveHost(ctx, h, testActor)
	ins := func(uid, node, key string) {
		if _, err := a.m.st.Writer().Exec(`INSERT INTO m64_problems (uid, node_id, host_uid, service_key, state, worst, opened_at, updated_at) VALUES (?, ?, ?, ?, 'crit', 'crit', ?, ?)`,
			uid, node, h.UID, key, tsNow(), tsNow()); err != nil {
			t.Fatal(err)
		}
	}
	ins("prob-a-fs0001", "node-a", "fs:/")
	ins("prob-b-fs0001", "node-b", "fs:/")
	ins("prob-a-cpu001", "node-a", "cpu")
	// A ist nicht zustaendig (B), B erreichbar: das Doppel fs:/ von A wird geschlossen, cpu bleibt (B uebernimmt es)
	a.m.cl.snap.Store(snapOf("node-a", map[string]bool{"node-b": true, "node-c": true}, "node-b", "node-c"))
	a.m.clusterProblems(ctx, a.m.cl.snap.Load())
	open := a.openProblems(t, h.UID)
	if _, ok := open["fs:/@node-a"]; ok {
		t.Fatalf("double of the non-responsible node still open: %v", open)
	}
	if _, ok := open["fs:/@node-b"]; !ok {
		t.Fatalf("responsible node's problem must stay: %v", open)
	}
	if _, ok := open["cpu@node-a"]; !ok {
		t.Fatalf("problem without double must stay for the takeover: %v", open)
	}
	var how string
	_ = a.m.st.Reader().QueryRow(`SELECT closed_how FROM m64_problems WHERE uid = 'prob-a-fs0001'`).Scan(&how)
	if how != "handover" {
		t.Fatalf("closed how %q", how)
	}
	var ev int
	_ = a.m.st.Reader().QueryRow(`SELECT COUNT(*) FROM m64_events WHERE problem_uid = 'prob-a-fs0001' AND kind = 'handover'`).Scan(&ev)
	if ev != 1 {
		t.Fatal("handover event missing")
	}
	// jetzt ist A zustaendig: cpu von A bleibt, fs:/ von B wird weitergefuehrt (gehoert dann A)
	_, _ = a.m.st.Writer().Exec(`UPDATE m64_hosts SET owner_node = 'node-a' WHERE uid = ?`, h.UID)
	a.m.clusterProblems(ctx, a.m.cl.snap.Load())
	open = a.openProblems(t, h.UID)
	if _, ok := open["fs:/@node-a"]; !ok || len(open) != 2 {
		t.Fatalf("responsible node must continue B's problem: %v", open)
	}
}

// Problem im Cluster: Ablauf mit Node-Kennung kommt an, Quittierung auf der anderen Node geht zurueck, ein
// geschlossenes Problem oeffnet keine aeltere Fassung wieder.
func TestClusterProblemSync(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, false)
	c := b.newNode("node-c", "C", 2, false)
	h := &Host{Name: "h", IntervalSec: 60}
	_ = a.m.store.SaveHost(ctx, h, testActor)
	_, _ = a.m.st.Writer().Exec(`INSERT INTO m64_problems (uid, node_id, host_uid, service_key, state, worst, opened_at, updated_at, notified) VALUES ('prob-0000001', 'node-a', ?, 'fs:/', 'warn', 'warn', ?, ?, '["default"]')`,
		h.UID, tsNow(), tsNow())
	a.m.event(ctx, "prob-0000001", h.UID, "fs:/", "warn", "90 %", SystemActor, time.Now())
	b.sync()
	if p := c.m.loadOpen(ctx, h.UID)["fs:/"]; p == nil || p.UID != "prob-0000001" {
		t.Fatalf("problem did not arrive: %+v", p)
	}
	var node string
	_ = c.m.st.Reader().QueryRow(`SELECT node_id FROM m64_events WHERE problem_uid = 'prob-0000001'`).Scan(&node)
	if node != "node-a" {
		t.Fatalf("event node %q", node)
	}
	// Quittieren auf C
	if err := c.m.Ack(ctx, h.UID, "fs:/", "kuemmere mich", testActor); err != nil {
		t.Fatal(err)
	}
	b.sync()
	if p := a.m.loadOpen(ctx, h.UID)["fs:/"]; p == nil || !p.Acked {
		t.Fatal("ack from C did not reach A")
	}
	var acks int
	_ = a.m.st.Reader().QueryRow(`SELECT COUNT(*) FROM m64_events WHERE problem_uid = 'prob-0000001' AND kind = 'ack'`).Scan(&acks)
	if acks != 1 {
		t.Fatalf("ack events on A: %d", acks)
	}
	// C schliesst; eine spaetere Fassung von A ohne Schluss oeffnet es auf C nicht wieder
	if err := c.m.Resolve(ctx, h.UID, "fs:/", "", testActor); err != nil {
		t.Fatal(err)
	}
	c.m.clusterScan(ctx)
	_, _ = a.m.st.Writer().Exec(`UPDATE m64_problems SET state = 'crit', worst = 'crit', updated_at = ? WHERE uid = 'prob-0000001'`, ts(time.Now().Add(time.Second)))
	a.m.clusterScan(ctx)
	data, _, _ := a.m.ClusterGet(ctx, ClusterItemStatus, "problem:prob-0000001")
	err := c.m.ClusterApply(context.WithValue(ctx, originKey{}, originVal{"node-a", time.Now().Add(time.Second)}), ClusterItemStatus, "problem:prob-0000001", data, false)
	var sup interface{ Superseded() bool }
	if !errors.As(err, &sup) {
		t.Fatalf("reopen must be refused as superseded, got %v", err)
	}
	if len(c.m.loadOpen(ctx, h.UID)) != 0 {
		t.Fatal("closed problem reopened")
	}
	var worst string
	_ = c.m.st.Reader().QueryRow(`SELECT worst FROM m64_problems WHERE uid = 'prob-0000001'`).Scan(&worst)
	if worst != "crit" {
		t.Fatalf("worst state must be merged: %q", worst)
	}
	b.sync()
	if len(a.m.loadOpen(ctx, h.UID)) != 0 {
		t.Fatal("A must learn that the problem is closed")
	}
}

// Cluster-Schluessel: die Node mit der kleinsten Kennung bringt ihren ein, die andere uebernimmt ihn, behaelt den alten
// fuer ihre Agents und stellt sie per "keys" um; danach ist der alte weg. Schluessel wechseln: neuer an alle.
func TestClusterKeyTakeover(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, true)
	c := b.newNode("node-c", "C", 2, true)
	lineA, lineC := keyLine(t, a), keyLine(t, c)
	if keyOf(lineA) == keyOf(lineC) {
		t.Fatal("nodes must start with their own keys")
	}
	// Agent eines Hosts von C kennt nur den alten Schluessel von C
	fh := &fakeHost{fsUsed: 40}
	port, keysFile := startAgent(t, fh, lineC)
	hc := addAgentHost(t, c, "c-host", port)
	if v := c.poll(t, hc.UID); v.View != eval.ViewOK {
		t.Fatalf("C reaches its agent: %+v", v.View)
	}
	b.sync()
	b.tick() // A (kleinste Kennung) bringt den Schluessel ein, C uebernimmt ihn
	if got := keyLine(t, c); keyOf(got) != keyOf(lineA) {
		t.Fatalf("C must use the cluster key of A")
	}
	ki, _ := c.m.keyInfo(ctx)
	if !ki.Cluster || len(ki.OldKeys) != 1 || len(ki.Pending) != 1 {
		t.Fatalf("C keeps its old key until the agent is switched: %+v", ki)
	}
	// noch vor dem Umstellen fragt C mit dem alten Schluessel weiter ab
	if v := c.poll(t, hc.UID); v.View != eval.ViewOK {
		t.Fatalf("C must still reach the agent with its old key: %+v %+v", v.View, v.Accesses)
	}
	c.m.switchAgents(ctx, true)
	c.m.cl.bg.Wait()
	raw, _ := os.ReadFile(keysFile)
	if keyOf(string(raw)) != keyOf(lineA) {
		t.Fatalf("agent keys after switch: %q", raw)
	}
	ki, _ = c.m.keyInfo(ctx)
	if len(ki.OldKeys) != 0 || len(ki.Pending) != 0 {
		t.Fatalf("old key must be gone after the switch: %+v", ki)
	}
	if v := c.poll(t, hc.UID); v.View != eval.ViewOK {
		t.Fatalf("C reaches the agent with the cluster key: %+v", v.Accesses)
	}
	// A darf den Agent jetzt auch abfragen (Host kam ueber den Cluster): A zustaendig machen
	_, _ = a.m.st.Writer().Exec(`UPDATE m64_hosts SET owner_node = 'node-a' WHERE uid = ?`, hc.UID)
	a.m.ReloadHost(ctx, hc.UID)
	a.m.clusterRefresh(ctx)
	if v := a.poll(t, hc.UID); v.View != eval.ViewOK || v.Cluster == nil || !v.Cluster.Here {
		t.Fatalf("A must reach the agent with the cluster key: %+v %+v", v.Accesses, v.Cluster)
	}
	_, _ = a.m.st.Writer().Exec(`UPDATE m64_hosts SET owner_node = '' WHERE uid = ?`, hc.UID)
	a.m.ReloadHost(ctx, hc.UID)

	// Schluessel wechseln auf A: C uebernimmt, stellt um (zustaendig/bevorzugt), A behaelt den alten nur bis dahin
	if err := a.m.RotateKey(ctx); err != nil {
		t.Fatal(err)
	}
	a.m.cl.bg.Wait()
	b.sync()
	lineN := keyLine(t, a)
	if keyOf(lineN) == keyOf(lineA) || keyOf(keyLine(t, c)) != keyOf(lineN) {
		t.Fatal("rotated key must reach C")
	}
	c.m.switchAgents(ctx, true)
	c.m.cl.bg.Wait()
	raw, _ = os.ReadFile(keysFile)
	if keyOf(string(raw)) != keyOf(lineN) {
		t.Fatalf("agent keys after rotation: %q", raw)
	}
	// A stellt c-host nicht selbst um (nicht zustaendig), behaelt den alten Schluessel aber, bis C die Umstellung meldet
	if ki, _ := a.m.keyInfo(ctx); len(ki.Pending) != 1 || len(ki.OldKeys) != 1 {
		t.Fatalf("A waits for C's switch: %+v", ki)
	}
	b.sync()
	a.m.switchAgents(ctx, false)
	a.m.cl.bg.Wait()
	if ki, _ := a.m.keyInfo(ctx); len(ki.Pending) != 0 || len(ki.OldKeys) != 0 {
		t.Fatalf("A learns the switch from C and drops its old key: %+v", ki)
	}
}

// Mehr-Node-Ablauf mit Agent: Zustaendigkeit, Gesamtuebersicht, Uebernahme durch die Mehrheit, abgehaengte Node misst
// ohne Meldung, Rueckgabe nach 5 min ohne doppelte Meldung, Verlauf live von der anderen Node, Trap-Anstoss.
func TestClusterMultiNode(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, true)
	bb := b.newNode("node-b", "B", 2, true)
	c := b.newNode("node-c", "C", 3, true)
	fh := &fakeHost{fsUsed: 40}
	port, _ := startAgent(t, fh, keyLine(t, a), keyLine(t, bb), keyLine(t, c))
	h := addAgentHost(t, a, "web01", port, "node-b")
	b.sync()
	b.tick()
	b.sync() // Schluessel, Zustaende
	b.advance(time.Minute)

	// A meldet, B und C zeigen den Zustand von A
	if v := a.poll(t, h.UID); v.State != eval.OK || v.Cluster == nil || !v.Cluster.Here || !v.Cluster.Reporting {
		t.Fatalf("A view: %+v %+v", v.State, v.Cluster)
	}
	b.sync()
	for _, n := range []*busNode{bb, c} {
		v := n.poll(t, h.UID)
		if v.Cluster == nil || v.Cluster.Here || v.Cluster.Node != "node-a" || len(v.Services) == 0 || v.State != eval.OK {
			t.Fatalf("%s must show A's state: %+v %+v", n.name, v.State, v.Cluster)
		}
	}

	// A abgetrennt: B (Ersatz, Mehrheit 2/3) uebernimmt, A misst weiter ohne Meldung
	b.isolate(a)
	b.advance(clusterTick)
	b.tick()
	if bb.owner(t, h.UID) != "node-b" {
		t.Fatalf("B must take over, owner %s", bb.owner(t, h.UID))
	}
	var tk int
	_ = bb.m.st.Reader().QueryRow(`SELECT COUNT(*) FROM m64_events WHERE host_uid = ? AND kind = 'takeover' AND node_id = 'node-b'`, h.UID).Scan(&tk)
	if tk != 1 {
		t.Fatal("takeover event missing")
	}
	if a.owner(t, h.UID) != "node-a" {
		t.Fatal("A must not learn about the takeover while cut off")
	}
	fh.set(96)
	beforeA, beforeB := a.alertCount(), bb.alertCount()
	va := a.poll(t, h.UID)
	vb := bb.poll(t, h.UID)
	if va.State != eval.Crit || va.Cluster == nil || va.Cluster.Reporting || va.Cluster.Note != noteMeasureOnly {
		t.Fatalf("cut-off A must measure without reporting: %s %+v", va.State, va.Cluster)
	}
	if a.alertCount() != beforeA || len(a.m.loadOpen(ctx, h.UID)) != 0 {
		t.Fatal("cut-off A must not notify or open problems")
	}
	if vb.State != eval.Crit || bb.alertCount() != beforeB+1 || bb.lastAlert().Kind != notify.KindMonitorProblem {
		t.Fatalf("B must report: %s, alerts %d -> %d", vb.State, beforeB, bb.alertCount())
	}
	// C kann nicht uebernehmen (nicht Ersatz) und zeigt B
	b.sync()
	if v := c.poll(t, h.UID); v.Cluster == nil || v.Cluster.Node != "node-b" || v.State != eval.Crit {
		t.Fatalf("C must show B's state: %+v", v.Cluster)
	}
	// Verlauf: B hat Werte, A ist nicht erreichbar -> Hinweis
	_ = bb.m.seriesStore().Flush(ctx)
	hc, _ := c.m.store.Host(ctx, h.UID)
	res, src := c.m.clusterSeries(ctx, hc, []string{"fs:/|used"}, []tsdb.Series{{}}, time.Now().Add(-time.Hour), time.Now().Add(time.Minute), 100)
	if len(res) != 1 || len(res[0].Points) == 0 {
		t.Fatalf("series from B missing: %+v", res)
	}
	missingA := false
	for _, s := range src {
		missingA = missingA || s.Node == "node-a" && s.Missing
	}
	if !missingA {
		t.Fatalf("unreachable A must be named: %+v", src)
	}

	// Wiederverbindung: Eintrag der Mehrheit gilt, A ist nicht zustaendig; Rueckgabe erst nach 5 min stabil
	b.join()
	b.advance(clusterTick)
	b.tick()
	if a.owner(t, h.UID) != "node-b" {
		t.Fatalf("after reconnect the majority's entry wins on A: %s", a.owner(t, h.UID))
	}
	if v := a.poll(t, h.UID); v.Cluster == nil || v.Cluster.Here {
		t.Fatalf("A idle after reconnect: %+v", v.Cluster)
	}
	b.advance(2 * time.Minute)
	b.tick()
	if bb.owner(t, h.UID) != "node-b" {
		t.Fatal("no return before 5 min stable")
	}
	b.advance(4 * time.Minute)
	b.tick()
	if bb.owner(t, h.UID) != "node-a" || a.owner(t, h.UID) != "node-a" {
		t.Fatalf("return to preferred A after 5 min stable: B %s, A %s", bb.owner(t, h.UID), a.owner(t, h.UID))
	}
	// A macht mit dem Stand von B weiter: kein zweites "Problem", das offene Problem gehoert jetzt A
	beforeA = a.alertCount()
	if v := a.poll(t, h.UID); v.State != eval.Crit || !v.Cluster.Reporting {
		t.Fatalf("A reports again: %s %+v", v.State, v.Cluster)
	}
	if a.alertCount() != beforeA {
		t.Fatalf("A must not notify again after the return: %+v", a.lastAlert())
	}
	b.tick()
	if open := a.openProblems(t, h.UID); len(open) != 1 || open["fs:/@node-a"] == "" {
		t.Fatalf("open problem continued by A: %v", open)
	}
	// Entwarnung kommt von A
	fh.set(40)
	a.poll(t, h.UID)
	if a.lastAlert().Kind != notify.KindMonitorOK || a.alertCount() != beforeA+1 {
		t.Fatalf("recovery must come from A: %+v", a.lastAlert())
	}

	// Trap an eine nicht zustaendige Node: Anstoss an A (A selbst fragt sofort ab)
	if !c.m.forwardRepoll(h.UID) || a.m.forwardRepoll(h.UID) {
		t.Fatal("trigger must be forwarded by C only")
	}
	if _, err := a.m.HandleClusterCall(ctx, "node-c", callRepoll, []byte(`{"host":"`+h.UID+`"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestMergePoints(t *testing.T) {
	pref := []tsdb.Point{{T: 100, Avg: 1}, {T: 160, Avg: 1}}
	other := []tsdb.Point{{T: 110, Avg: 2}, {T: 400, Avg: 2}, {T: 460, Avg: 2}}
	got := mergePoints([][]tsdb.Point{pref, other}, 60)
	if len(got) != 4 || got[0].Avg != 1 || got[1].T != 160 || got[2].T != 400 || got[3].T != 460 {
		t.Fatalf("merge: %+v", got)
	}
	if got := mergePoints(nil, 0); got == nil || len(got) != 0 {
		t.Fatal("empty merge must be an empty list")
	}
}

// Zwei Nodes getrennt: beide melden (Sonderfall), nach der Wiederverbindung schliesst die nicht zustaendige Node ihr
// doppelt offenes Problem "durch Uebergabe beendet".
func TestClusterTwoNodeSplit(t *testing.T) {
	ctx := context.Background()
	b := newBus(t)
	a := b.newNode("node-a", "A", 1, true)
	bb := b.newNode("node-b", "B", 2, true)
	fh := &fakeHost{fsUsed: 40}
	port, _ := startAgent(t, fh, keyLine(t, a), keyLine(t, bb))
	h := addAgentHost(t, a, "db01", port, "node-b")
	b.sync()
	b.tick()
	b.advance(time.Minute)
	a.poll(t, h.UID)
	b.sync()

	b.isolate(a)
	b.advance(clusterTick)
	b.tick()
	if bb.owner(t, h.UID) != "node-b" {
		t.Fatal("two nodes: B takes over without majority")
	}
	fh.set(97)
	if v := a.poll(t, h.UID); !v.Cluster.Reporting {
		t.Fatal("two nodes: A keeps reporting")
	}
	bb.poll(t, h.UID)
	if a.alertCount() == 0 || bb.alertCount() == 0 {
		t.Fatal("both report in a two-node split (documented)")
	}
	b.join()
	b.tick()
	b.tick()
	if a.owner(t, h.UID) != "node-b" {
		t.Fatalf("newer owner entry (B) wins: %s", a.owner(t, h.UID))
	}
	open := bb.openProblems(t, h.UID)
	if len(open) != 1 || open["fs:/@node-b"] == "" {
		t.Fatalf("only B's problem stays open: %v", open)
	}
	var how string
	_ = bb.m.st.Reader().QueryRow(`SELECT closed_how FROM m64_problems WHERE node_id = 'node-a' AND host_uid = ? AND service_key = 'fs:/'`, h.UID).Scan(&how)
	if how != "handover" {
		t.Fatalf("A's double closed by handover, got %q", how)
	}
	_ = ctx
}
