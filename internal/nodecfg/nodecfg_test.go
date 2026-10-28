package nodecfg

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/selfupdate"
	"github.com/ipv64net/node64/internal/store"
)

type change struct {
	item, id string
	deleted  bool
	at       time.Time
}

type testNode struct {
	st  *store.Store
	box *secrets.Box
	key *ipv64api.Key
	c   *Cluster
	acc int64

	mu      sync.Mutex
	changes []change
}

func (n *testNode) take() []change {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := n.changes
	n.changes = nil
	return out
}

func newTestNode(t *testing.T, acc int64) *testNode {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(ctx, filepath.Join(dir, "n.db"), filepath.Join(dir, "b"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ms, _ := store.CoreMigrations()
	if err := st.Migrate(ctx, "core", ms); err != nil {
		t.Fatal(err)
	}
	box, err := secrets.Load(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	n := &testNode{st: st, box: box, acc: acc}
	// API nie erreichbar: der Abgleich darf ipv64 nicht fragen
	n.key = ipv64api.NewKey(st, box, ipv64api.NewClient("http://127.0.0.1:1", "test"), log)
	n.c = New(Deps{Store: st, Box: box, Key: n.key, Account: func() int64 { return n.acc }, Log: log})
	return n
}

func (n *testNode) attach() {
	n.c.SetCluster(func(_ context.Context, item, id string, deleted bool, at time.Time) {
		n.mu.Lock()
		n.changes = append(n.changes, change{item, id, deleted, at})
		n.mu.Unlock()
	}, func(context.Context) string { return "A" })
}

// transfer: wie der Cluster - Stand bei a holen, bei b uebernehmen.
func transfer(t *testing.T, a, b *testNode, calls []change) error {
	t.Helper()
	ctx := context.Background()
	for _, c := range calls {
		data, found, err := a.c.ClusterGet(ctx, c.item, c.id)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.c.ClusterApply(ctx, c.item, c.id, data, c.deleted || !found); err != nil {
			return err
		}
	}
	return nil
}

func auditActions(t *testing.T, n *testNode) string {
	t.Helper()
	list, err := n.st.AuditList(context.Background(), 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range list {
		out = append(out, e.Action+":"+e.Actor+":"+e.Details)
	}
	return strings.Join(out, "|")
}

const keyA = "AAAAbbbbCCCCdddd1111"

// API-Key: Klartext auf der Leitung, bei B mit dessen Schluessel verschluesselt, gleicher Weg wie die Eingabe
// (Konto, Merker „entfernt“ zurueck), Audit; anderer Account abgelehnt; Entfernen kommt an; ipv64.net-Entfernung nicht.
func TestAPIKeyCluster(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, 522), newTestNode(t, 0)
	a.attach()
	b.attach()
	info := ipv64api.AccountInfo{ID: 522, Account: "dennis", Plan: "Pro", KeyName: "node", CheckedAt: time.Now().UTC().Truncate(time.Second)}
	if err := a.key.SetFromCluster(ctx, keyA, info); err != nil {
		t.Fatal(err)
	}
	calls := a.take()
	if len(calls) != 1 || calls[0].item != ItemAPIKey || calls[0].id != keyID || calls[0].deleted {
		t.Fatalf("key change: %+v", calls)
	}
	if ids, _ := a.c.ClusterIDs(ctx, ItemAPIKey); len(ids) != 1 {
		t.Fatalf("ids: %v", ids)
	}
	_ = b.st.SetSetting(ctx, ipv64api.SetRemoved, "") // nicht entfernt
	if err := transfer(t, a, b, calls); err != nil {
		t.Fatal(err)
	}
	if b.key.Get(ctx) != keyA || !b.key.APIReady() || b.key.Info(ctx).ID != 522 || b.key.Info(ctx).Account != "dennis" {
		t.Fatalf("key on B: ready=%v info=%+v", b.key.APIReady(), b.key.Info(ctx))
	}
	rawA, rawB := a.st.SettingOr(ctx, ipv64api.SetKey, ""), b.st.SettingOr(ctx, ipv64api.SetKey, "")
	if strings.Contains(rawB, keyA) || rawA == rawB {
		t.Fatal("key must be encrypted with B's key")
	}
	if got := auditActions(t, b); !strings.Contains(got, "peer.ipv64_key:node:A:account=dennis") || strings.Contains(got, keyA) {
		t.Fatalf("audit on B: %s", got)
	}
	if c := b.take(); len(c) != 1 || c[0].item != ItemAPIKey { // Hook wie bei der Eingabe (Herkunft steckt in ctx)
		t.Fatalf("B reports the applied key: %+v", c)
	}
	// unveraendert: nichts
	if err := transfer(t, a, b, []change{{item: ItemAPIKey, id: keyID}}); err != nil || len(b.take()) != 0 {
		t.Fatalf("unchanged key: %v", err)
	}

	// anderer Account: abgelehnt
	c := newTestNode(t, 999)
	c.attach()
	if err := transfer(t, a, c, []change{{item: ItemAPIKey, id: keyID}}); !errors.Is(err, ErrAccount) || c.key.Get(ctx) != "" {
		t.Fatalf("other account must be rejected: %v", err)
	}
	// Key ohne Account-Kennung: abgelehnt
	raw, _ := json.Marshal(keyData{Key: "ZZZZzzzzZZZZzzzz9999", Account: ipv64api.AccountInfo{Account: "x"}})
	if err := b.c.ClusterApply(ctx, ItemAPIKey, keyID, raw, false); !errors.Is(err, ErrAccount) || b.key.Get(ctx) != keyA {
		t.Fatalf("key without account: %v", err)
	}

	// Entfernen auf A kommt bei B an
	if err := a.key.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	calls = a.take()
	if len(calls) != 1 || !calls[0].deleted {
		t.Fatalf("clear: %+v", calls)
	}
	if err := transfer(t, a, b, calls); err != nil {
		t.Fatal(err)
	}
	if b.key.Get(ctx) != "" || b.key.APIReady() || !strings.Contains(auditActions(t, b), "peer.ipv64_key_removed") {
		t.Fatal("key must be removed on B")
	}

	// auf ipv64.net entfernt: geht nicht als Loeschen hinaus und nimmt keinen Key an
	_ = a.key.SetFromCluster(ctx, keyA, info)
	a.take()
	if err := a.key.MarkRemoved(ctx); err != nil {
		t.Fatal(err)
	}
	if c := a.take(); len(c) != 0 {
		t.Fatalf("removal by ipv64.net stays local: %+v", c)
	}
	if data, found, _ := a.c.ClusterGet(ctx, ItemAPIKey, keyID); !found || !strings.Contains(string(data), "incomplete") {
		t.Fatalf("removed node keeps the others' key: %s", data)
	}
	_ = b.key.SetFromCluster(ctx, keyA, info)
	if err := transfer(t, b, a, []change{{item: ItemAPIKey, id: keyID}}); err != nil || a.key.Get(ctx) != "" {
		t.Fatalf("node removed on ipv64.net must not take a key: %v", err)
	}
}

// Einstellungen: nur die Whitelist, Geheimnisse neu verschluesselt, Nebenwirkungen wie die Einstellungsseite,
// ungueltige und unbekannte abgelehnt, unveraendert gespeichert zaehlt nicht.
func TestSettingsCluster(t *testing.T) {
	ctx := context.Background()
	old := settings
	settings = append(append([]Setting(nil), settings...), Setting{Key: "test.token", Secret: true})
	t.Cleanup(func() { settings = old })

	a, b := newTestNode(t, 0), newTestNode(t, 0)
	_ = a.st.SetSetting(ctx, "node.timezone", "Europe/Berlin") // schon vor dem Cluster
	a.attach()
	b.attach()
	calls := a.take()
	if len(calls) != 1 || calls[0].id != "node.timezone" || calls[0].at.IsZero() {
		t.Fatalf("startup: existing setting with its time: %+v", calls)
	}
	// erneuter Start: nichts Neues
	a2 := New(Deps{Store: a.st, Box: a.box, Key: a.key})
	var again []string
	a2.SetCluster(func(_ context.Context, _, id string, _ bool, _ time.Time) { again = append(again, id) }, nil)
	if len(again) != 0 {
		t.Fatalf("restart reports nothing: %v", again)
	}
	a.attach() // Hook wieder auf a

	for k, v := range map[string]string{"node.name": "A", "node.id": "x", "web.tls_cert": "self", selfupdate.SetLatest: "{}", "peer.sync": "{}", "updates.check": "1"} {
		_ = a.st.SetSetting(ctx, k, v)
	}
	if c := a.take(); len(c) != 0 {
		t.Fatalf("non-whitelisted settings must not be reported: %+v", c)
	}
	for _, k := range []string{"node.name", "node.id", "web.tls_cert", "peer.sync"} {
		if _, _, err := a.c.ClusterGet(ctx, ItemSettings, k); err == nil {
			t.Fatalf("%s must never be sent", k)
		}
		if err := b.c.ClusterApply(ctx, ItemSettings, k, json.RawMessage(`{"value":"evil"}`), false); err == nil {
			t.Fatalf("%s must never be taken", k)
		}
	}

	_ = a.st.SetSetting(ctx, "mcp.enabled", "1")
	_ = a.st.SetSetting(ctx, "mcp.enabled", "1") // unveraendert gespeichert: nur einmal
	_ = a.st.SetSetting(ctx, selfupdate.SetWindow, "02:00-04:00")
	_ = a.st.SetSetting(ctx, "test.token", a.box.Encrypt("tok-GEHEIM"))
	_ = b.st.SetSetting(ctx, selfupdate.SetLatest, `{"version":"9.9.9"}`)
	_ = b.st.SetSetting(ctx, selfupdate.SetMode, "notify")
	_ = a.st.SetSetting(ctx, selfupdate.SetMode, "off")
	calls = append(calls, a.take()...)
	if len(calls) != 5 {
		t.Fatalf("changes: %+v", calls)
	}
	b.take()
	if err := transfer(t, a, b, calls); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"node.timezone": "Europe/Berlin", "mcp.enabled": "1", selfupdate.SetWindow: "02:00-04:00", selfupdate.SetMode: "off",
		"updates.check": "0", selfupdate.SetLatest: ""} {
		if got := b.st.SettingOr(ctx, k, "?"); got != want {
			t.Fatalf("%s on B = %q, want %q", k, got, want)
		}
	}
	rawB := b.st.SettingOr(ctx, "test.token", "")
	if plain, _ := b.box.Decrypt(rawB); plain != "tok-GEHEIM" || strings.Contains(rawB, "GEHEIM") {
		t.Fatalf("secret must be re-encrypted with B's key: %q", rawB)
	}
	if c := b.take(); len(c) != 0 {
		t.Fatalf("applied settings are not B's own changes: %+v", c)
	}
	if got := auditActions(t, b); !strings.Contains(got, "peer.node_setting:node:A:mcp.enabled=1") || strings.Contains(got, "GEHEIM") {
		t.Fatalf("audit on B: %s", got)
	}
	// ungueltige Werte: abgelehnt
	for k, v := range map[string]string{"node.timezone": "Mars/Base", selfupdate.SetMode: "sometimes", selfupdate.SetWindow: "25:00", "mcp.enabled": "yes"} {
		raw, _ := json.Marshal(settingData{Value: v})
		if err := b.c.ClusterApply(ctx, ItemSettings, k, raw, false); err == nil {
			t.Fatalf("invalid %s=%s taken", k, v)
		}
	}
	// Loeschen: Einstellung bleibt
	if err := b.c.ClusterApply(ctx, ItemSettings, "mcp.enabled", nil, true); err != nil || b.st.SettingOr(ctx, "mcp.enabled", "") != "1" {
		t.Fatal("deleted setting must stay")
	}
	// Aenderung auf B kommt zurueck
	_ = b.st.SetSetting(ctx, "node.timezone", "UTC")
	if err := transfer(t, b, a, b.take()); err != nil || a.st.SettingOr(ctx, "node.timezone", "") != "UTC" {
		t.Fatalf("change on B: %v", err)
	}
}
