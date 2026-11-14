package healthchecks

import (
	"context"
	"encoding/json"
	"testing"
)

// #134: Die Auswahl "Messende Nodes" zeigt die aktuellen Namen. Die Liste vom hub (sync.account_nodes) ist nur ein
// Zwischenstand (alle 5 Minuten, nach dem Trennen gar nicht mehr erneuert); der eigene Name steht in node.name, die
// Nodes der lokalen Gruppe melden ihren Namen bei jedem Ping selbst.
func TestPeersCurrentNames(t *testing.T) {
	m, _ := newTestModule(t)
	ctx := context.Background()
	me, other, hubOnly := "selfnode0000000000000000000000aa", "othernode000000000000000000000bb", "hubnode00000000000000000000000cc"
	_ = m.core.SetSetting(ctx, "node.id", me)
	self.Lock()
	self.id = ""
	self.Unlock()
	t.Cleanup(func() { self.Lock(); self.id = ""; self.Unlock() })
	_ = m.core.SetSetting(ctx, "node.name", "Neu-Self")
	_ = m.core.SetSetting(ctx, "sync.node_name", "Alt-Self")
	b, _ := json.Marshal([]Peer{{ID: me, Name: "Alt-Self", Online: true}, {ID: other, Name: "Alt-Other", Location: "Berlin"}, {ID: hubOnly, Name: "Hub", Online: true}})
	_ = m.core.SetSetting(ctx, SettingPeers, string(b))
	m.SetGroupPeers(func(context.Context) []Peer {
		return []Peer{{ID: other, Name: "Neu-Other", Location: "LAN", Online: true}}
	})
	got := map[string]Peer{}
	for _, p := range m.peers(ctx) {
		got[p.ID] = p
	}
	if p := got[me]; p.Name != "Neu-Self" || !p.Self {
		t.Errorf("eigene Node: %+v, erwartet Neu-Self", p)
	}
	if p := got[other]; p.Name != "Neu-Other" || !p.Online || p.Location != "Berlin" {
		t.Errorf("Node der Gruppe: %+v, erwartet Neu-Other (online, Standort vom hub)", p)
	}
	if p := got[hubOnly]; p.Name != "Hub" {
		t.Errorf("Node nur beim hub: %+v", p)
	}
	if n := m.nodeNames(ctx, []string{other, me}); len(n) != 2 || n[0] != "Neu-Other" || n[1] != "Neu-Self" {
		t.Errorf("nodeNames = %v", n)
	}

	// ohne Liste vom hub (nie verknuepft): eigener Name aus node.name, nicht der zuletzt mit ipv64 abgeglichene
	_ = m.core.SetSetting(ctx, SettingPeers, "[]")
	if l := m.peers(ctx); len(l) == 0 || l[0].Name != "Neu-Self" {
		t.Errorf("ohne hub-Liste: %+v", l)
	}
}
