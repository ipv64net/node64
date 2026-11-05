package peer

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// Die Schalter "Was wird abgeglichen" gelten fuer den ganzen Cluster: jede Aenderung geht als Eintrag
// cluster/switches ueber /peer/v2/sync an alle Mitglieder (die juengere Aenderung gewinnt, wie bei allen Eintraegen).
// Der Bereich ist immer an (syncCaps), auch wenn ein Modul aus ist, damit auch das Ausschalten ankommt; er steht nicht
// in der Oberflaeche. Aeltere Nodes kennen ihn nicht und behalten ihre Schalter. Kennung des Eintrags: "modul" bzw.
// "modul/bereich", Inhalt {"on": bool}.

const (
	switchModule = "cluster"
	switchItem   = "switches"
	SwitchCap    = switchModule + "/" + switchItem // Bereich der Schalter (steht in Member.Sync, nicht in der Oberflaeche)
)

type switchProvider struct{ m *Manager }

func (switchProvider) ClusterModule() ModuleInfo {
	return ModuleInfo{ID: switchModule, Items: []ItemInfo{{ID: switchItem}}}
}

// ClusterIDs: nichts vorab ins Protokoll (sonst gewaenne beim Update die Node, die zuletzt neu startet). Bei einem
// Beitritt legt die annehmende Node ihre Schalter ins Protokoll (logSwitches).
func (switchProvider) ClusterIDs(context.Context, string) ([]string, error) { return nil, nil }

func (p switchProvider) ClusterGet(ctx context.Context, _, id string) (json.RawMessage, bool, error) {
	on, ok := p.m.switchValue(ctx, id)
	if !ok {
		return nil, false, nil
	}
	b, _ := json.Marshal(map[string]bool{"on": on})
	return b, true, nil
}

func (p switchProvider) ClusterApply(ctx context.Context, _, id string, data json.RawMessage, deleted bool) error {
	if deleted {
		return nil // Schalter werden nie geloescht
	}
	var v struct {
		On bool `json:"on"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	module, item, _ := strings.Cut(id, "/")
	if module == "" || module == switchModule {
		return nil
	}
	// auch Module, die es hier (noch) nicht gibt: der Schalter gilt, sobald das Modul da ist
	if err := p.m.setSyncLocal(ctx, module, item, v.On); err != nil {
		return err
	}
	by, _, _ := ClusterOrigin(ctx)
	if x, err := p.m.member(ctx, by); err == nil && x != nil {
		by = x.Name
	}
	state := "off"
	if v.On {
		state = "on"
	}
	p.m.auditPeer(ctx, by, "peer.sync", id, state)
	return nil
}

// switchValue: Schalter "modul" bzw. "modul/bereich" auf dieser Node (eingestellt oder Vorgabe); ok=false, wenn es
// Modul oder Bereich hier nicht gibt.
func (m *Manager) switchValue(ctx context.Context, id string) (on, ok bool) {
	module, item, _ := strings.Cut(id, "/")
	for _, st := range m.SyncModules(ctx) {
		if st.ID != module {
			continue
		}
		if item == "" {
			return st.Enabled, true
		}
		for _, it := range st.Items {
			if it.ID == item {
				return it.Enabled, true
			}
		}
	}
	return false, false
}

// logSwitches legt alle Schalter dieser Node ins Protokoll, die dort noch fehlen (annehmende Node beim Beitritt:
// die neue Node uebernimmt so die Schalter des Clusters).
func (m *Manager) logSwitches(ctx context.Context) {
	self, now := m.d.NodeID(), fmtTime(time.Now())
	for _, st := range m.SyncModules(ctx) {
		ids := []string{st.ID}
		for _, it := range st.Items {
			ids = append(ids, st.ID+"/"+it.ID)
		}
		for _, id := range ids {
			_, _ = m.db.ExecContext(ctx, `INSERT OR IGNORE INTO cluster_log (module, item, entity_id, deleted, origin, changed_at) VALUES (?,?,?,0,?,?)`,
				switchModule, switchItem, id, self, now)
		}
	}
	m.pokeSoon()
}
