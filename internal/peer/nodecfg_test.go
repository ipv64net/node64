package peer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/nodecfg"
)

// nodeProv: das Modul "node" wie nodecfg/nodecluster (das von peer abhaengt und hier nicht importiert werden kann).
type nodeProv struct{ *nodecfg.Cluster }

func (nodeProv) ClusterModule() ModuleInfo {
	mi := ModuleInfo{ID: nodecfg.ModuleID, TitleKey: nodecfg.TitleKey}
	for _, it := range nodecfg.Items() {
		mi.Items = append(mi.Items, ItemInfo{ID: it.ID, TitleKey: it.TitleKey, HintKey: it.HintKey})
	}
	return mi
}

func newNodeCfg(n *testNode, id string) *ipv64api.Key {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	key := ipv64api.NewKey(n.m.d.Core, n.m.d.Box, ipv64api.NewClient("http://127.0.0.1:1", "test"), log) // ipv64 nie gefragt
	c := nodecfg.New(nodecfg.Deps{Store: n.m.d.Core, Box: n.m.d.Box, Key: key, Account: n.m.Account, ClusterAccount: n.m.ClusterAccount, Log: log})
	n.m.RegisterProvider(nodeProv{c})
	c.SetCluster(func(ctx context.Context, item, eid string, deleted bool, at time.Time) {
		if !at.IsZero() {
			ctx = WithClusterOrigin(ctx, id, at)
		}
		n.m.ClusterChange(ctx, nodecfg.ModuleID, item, eid, deleted)
	}, func(context.Context) string { return "" })
	return key
}

// Modul node ueber den Cluster: aus = nichts; API-Key nur mit Bereich apikey (verschluesselt je Node), Entfernen
// kommt an; Einstellungen nur die Whitelist.
func TestNodeCfgCluster(t *testing.T) {
	ctx := context.Background()
	a, b, c := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522), newNode(t, "node-c", "C", 522)
	ka, kb, kc := newNodeCfg(a, "node-a"), newNodeCfg(b, "node-b"), newNodeCfg(c, "node-c")
	stA, stB, stC := a.m.d.Core, b.m.d.Core, c.m.d.Core
	const key = "AAAAbbbbCCCCdddd1111"
	if err := ka.SetFromCluster(ctx, key, ipv64api.AccountInfo{ID: 522, Account: "dennis", Plan: "Pro"}); err != nil {
		t.Fatal(err)
	}
	_ = stA.SetSetting(ctx, "node.timezone", "Europe/Berlin")
	_ = stA.SetSetting(ctx, "node.name", "Name A")
	_ = stB.SetSetting(ctx, "node.name", "Name B")
	_ = stA.SetSetting(ctx, "updates.latest", `{"version":"1.2.3"}`)
	code, _, _ := a.m.StartPairing()
	if err := b.m.Join(ctx, a.srv.URL, code, b.srv.URL); err != nil {
		t.Fatal(err)
	}
	code, _, _ = a.m.StartPairing()
	if err := c.m.Join(ctx, a.srv.URL, code, c.srv.URL); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B", "C")

	// ohne Schalter: nichts
	round2(a, b, c)
	if kb.Get(ctx) != "" || stB.SettingOr(ctx, "node.timezone", "") != "" {
		t.Fatal("module node is off by default")
	}
	// A und B: Modul mit beiden Bereichen; C nur die Einstellungen
	for _, n := range []*testNode{a, b, c} {
		for item, on := range map[string]bool{"": true, nodecfg.ItemAPIKey: n != c, nodecfg.ItemSettings: true} {
			if err := n.m.SetSync(ctx, nodecfg.ModuleID, item, on); err != nil {
				t.Fatal(err)
			}
		}
	}
	round2(a, b, c)
	if kb.Get(ctx) != key || !kb.APIReady() || kb.Info(ctx).ID != 522 {
		t.Fatalf("key on B: info=%+v", kb.Info(ctx))
	}
	if raw := stB.SettingOr(ctx, ipv64api.SetKey, ""); strings.Contains(raw, key) || raw == stA.SettingOr(ctx, ipv64api.SetKey, "") {
		t.Fatal("key must be encrypted with B's key")
	}
	if kc.Get(ctx) != "" {
		t.Fatal("C has the area apikey off")
	}
	for _, st := range []*testNode{b, c} {
		if tz := st.m.d.Core.SettingOr(ctx, "node.timezone", ""); tz != "Europe/Berlin" {
			t.Fatalf("timezone on %s: %q", st.m.d.NodeName(), tz)
		}
	}
	if stB.SettingOr(ctx, "node.name", "") != "Name B" || stC.SettingOr(ctx, "node.name", "x") != "x" || stB.SettingOr(ctx, "updates.latest", "") != "" {
		t.Fatal("non-whitelisted settings must stay per node")
	}

	// Aenderung auf C (nur Einstellungen) erreicht A und B
	_ = stC.SetSetting(ctx, "updates.channel", "stable")
	round2(a, b, c)
	if stA.SettingOr(ctx, "updates.channel", "") != "stable" || stB.SettingOr(ctx, "updates.channel", "") != "stable" {
		t.Fatal("setting from C must reach A and B")
	}

	// Entfernen auf B kommt bei A an, C bleibt ohne
	if err := kb.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	round2(a, b, c)
	if ka.Get(ctx) != "" {
		t.Fatal("removal must reach A")
	}

	// Bereich auf B aus: ein neuer Key auf A bleibt dort
	if err := b.m.SetSync(ctx, nodecfg.ModuleID, nodecfg.ItemAPIKey, false); err != nil {
		t.Fatal(err)
	}
	_ = ka.SetFromCluster(ctx, "ZZZZyyyyXXXXwwww2222", ipv64api.AccountInfo{ID: 522, Account: "dennis"})
	round2(a, b, c)
	if kb.Get(ctx) != "" || kc.Get(ctx) != "" {
		t.Fatal("area off: key must not be exchanged")
	}
}

// Node ohne Account uebernimmt den API-Key (Dennis: gleicher Account oder keiner): danach haben beide den Account
// des Keys, nichts wird ausgesetzt; eine Node mit anderem Account kommt nicht dazu; Entfernen (X→0) laesst alle aktiv.
func TestNodeCfgKeyToNodeWithoutAccount(t *testing.T) {
	ctx := context.Background()
	a, b, y := newNode(t, "node-a", "A", 0), newNode(t, "node-b", "B", 0), newNode(t, "node-y", "Y", 0)
	keys := map[*testNode]*ipv64api.Key{}
	for _, n := range []*testNode{a, b, y} {
		k := newNodeCfg(n, n.m.d.NodeID())
		keys[n] = k
		n.m.d.AccountID = func() int64 { return int64(k.Info(context.Background()).ID) } // wie main.go: Account vom Key
	}
	ka, kb := keys[a], keys[b]
	const key = "AAAAbbbbCCCCdddd1111"
	if err := ka.SetFromCluster(ctx, key, ipv64api.AccountInfo{ID: 522, Account: "dennis"}); err != nil {
		t.Fatal(err)
	}
	_ = keys[y].SetFromCluster(ctx, "YYYYyyyyYYYYyyyy9999", ipv64api.AccountInfo{ID: 999, Account: "other"})
	z := newNode(t, "node-z", "Z", 0) // tritt spaeter mit einem frueher eingetragenen Key bei
	kz := newNodeCfg(z, z.m.d.NodeID())
	z.m.d.AccountID = func() int64 { return int64(kz.Info(context.Background()).ID) }
	const zkey = "ZZZZzzzzZZZZzzzz7777"
	if err := kz.SetFromCluster(ctx, zkey, ipv64api.AccountInfo{ID: 522, Account: "dennis"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond) // Zeitpunkt des Keys auf Z vor dem Entfernen unten
	pair(t, a, b)                    // A (522) und B (ohne)
	waitMembers(t, a, "B")
	for _, n := range []*testNode{a, b} {
		for _, item := range []string{"", nodecfg.ItemAPIKey} {
			if err := n.m.SetSync(ctx, nodecfg.ModuleID, item, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	round2(a, b)
	if kb.Get(ctx) != key || b.m.Account() != 522 {
		t.Fatalf("B must take the key: account=%d", b.m.Account())
	}
	for _, n := range []*testNode{a, b} {
		wantActive(t, n, 1)
	}
	if x := memberOf(t, a, "node-b"); x.AccountID != 522 || x.SelfAccount != 522 {
		t.Fatalf("A sees B: %+v", x)
	}
	if x := memberOf(t, b, "node-a"); x.AccountID != 522 || x.SelfAccount != 522 {
		t.Fatalf("B sees A: %+v", x)
	}
	// eine Node mit anderem Account kommt nicht dazu
	code, _, _ := a.m.StartPairing()
	if err := y.m.Join(ctx, a.srv.URL, code, y.srv.URL); !errors.Is(err, ErrAccountMismatch) {
		t.Fatalf("Y (999) joins: %v", err)
	}
	// Entfernen auf B (X→0 auf beiden): alle bleiben aktiv
	if err := kb.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	round2(a, b)
	if ka.Get(ctx) != "" || a.m.Account() != 0 || b.m.Account() != 0 {
		t.Fatalf("removal must reach A: accounts %d/%d", a.m.Account(), b.m.Account())
	}
	for _, n := range []*testNode{a, b} {
		wantActive(t, n, 1)
	}
	// Z bringt einen Key mit, der vor dem Entfernen eingetragen wurde: beim Beitritt gilt er ab jetzt, A und B
	// uebernehmen ihn (der aeltere Zeitpunkt des Keys verliert sonst gegen den Loeschvermerk)
	if err := z.m.SetSync(ctx, nodecfg.ModuleID, "", true); err != nil {
		t.Fatal(err)
	}
	if err := z.m.SetSync(ctx, nodecfg.ModuleID, nodecfg.ItemAPIKey, true); err != nil {
		t.Fatal(err)
	}
	code, _, _ = a.m.StartPairing()
	if err := z.m.Join(ctx, a.srv.URL, code, z.srv.URL); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B", "Z")
	round2(a, b, z)
	round2(a, b, z)
	if kz.Get(ctx) != zkey || ka.Get(ctx) != zkey || kb.Get(ctx) != zkey {
		t.Fatalf("key of the joining node must win: a=%q b=%q z=%q", ka.Get(ctx), kb.Get(ctx), kz.Get(ctx))
	}
}
