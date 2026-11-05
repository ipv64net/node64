package peer

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Die Schalter "Was wird abgeglichen" gelten fuer den ganzen Cluster: jede Aenderung geht als Eintrag
// cluster/switches ueber /peer/v2/sync an alle Mitglieder (die juengere Aenderung gewinnt, wie bei allen Eintraegen).
// Der Bereich ist immer an (syncCaps), auch wenn ein Modul aus ist, damit auch das Ausschalten ankommt; er steht nicht
// in der Oberflaeche. Aeltere Nodes kennen ihn nicht und behalten ihre Schalter. Kennung des Eintrags: "modul" bzw.
// "modul/bereich", Inhalt {"on": bool}. Eine beitretende Node uebernimmt die Schalter der annehmenden Node direkt
// (adoptSwitches, ohne Protokoll: die anderen Mitglieder behalten ihre).

const (
	switchModule = "cluster"
	switchItem   = "switches"
	SwitchCap    = switchModule + "/" + switchItem // Bereich der Schalter (steht in Member.Sync, nicht in der Oberflaeche)
)

// switchPullEvery: Abstand der regelmaessigen Abholung, wenn mit einem Mitglied nur die Schalter abzugleichen sind
// (jede Aenderung stoesst die anderen ohnehin an; Variable fuer Tests).
var switchPullEvery = 5 * time.Minute

type switchProvider struct{ m *Manager }

func (switchProvider) ClusterModule() ModuleInfo {
	return ModuleInfo{ID: switchModule, Items: []ItemInfo{{ID: switchItem}}}
}

// ClusterIDs: nichts vorab ins Protokoll (sonst gewaenne beim Update die Node, die zuletzt neu startet).
func (switchProvider) ClusterIDs(context.Context, string) ([]string, error) { return nil, nil }

func (p switchProvider) ClusterGet(ctx context.Context, _, id string) (json.RawMessage, bool, error) {
	on, ok := p.m.switchValue(ctx, id)
	if !ok { // Modul gibt es hier nicht: den uebernommenen Stand weiterreichen (sonst ginge er als geloescht weiter)
		on, ok = p.m.switchStored(ctx, id)
	}
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
	changed, err := p.m.setSyncLocal(ctx, module, item, v.On)
	if err != nil || !changed {
		return err
	}
	by, _, _ := ClusterOrigin(ctx)
	if x, err := p.m.member(ctx, by); err == nil && x != nil {
		by = x.Name
	}
	p.m.auditPeer(ctx, by, "peer.sync", id, onOff(v.On))
	return nil
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
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

// switchStored: gespeicherter Schalter (auch fuer Module, die es hier nicht gibt); ok=false, wenn keiner gespeichert ist.
func (m *Manager) switchStored(ctx context.Context, id string) (on, ok bool) {
	module, item, _ := strings.Cut(id, "/")
	c, found := m.syncCfg(ctx)[module]
	if !found {
		return false, false
	}
	if item == "" {
		if c.Enabled == nil {
			return false, false
		}
		return *c.Enabled, true
	}
	on, ok = c.Items[item]
	return on, ok
}

// handleSwitches liefert alle Schalter dieser Node (fuer eine beitretende Node, adoptSwitches).
func (m *Manager) handleSwitches(w http.ResponseWriter, r *http.Request, _ *Member, _ []byte) {
	ctx := r.Context()
	out := map[string]bool{}
	for module, c := range m.syncCfg(ctx) { // auch Module, die es hier nicht gibt
		if c.Enabled != nil {
			out[module] = *c.Enabled
		}
		for item, on := range c.Items {
			out[module+"/"+item] = on
		}
	}
	for _, st := range m.SyncModules(ctx) { // Vorgaben der Module hier
		out[st.ID] = st.Enabled
		for _, it := range st.Items {
			out[st.ID+"/"+it.ID] = it.Enabled
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"switches": out})
}

// adoptSwitches: die beitretende Node uebernimmt die Schalter der annehmenden Node x (nur hier, nicht im Protokoll).
// Eine aeltere Node kennt den Endpunkt nicht: dann bleiben die eigenen.
func (m *Manager) adoptSwitches(ctx context.Context, x Member) {
	var out struct {
		Switches map[string]bool `json:"switches"`
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err := m.call(cctx, x, http.MethodGet, "/peer/v2/switches", nil, &out)
	cancel()
	if err != nil {
		m.d.Log.Debug("cluster switches not adopted", "from", x.Name, "err", err)
		return
	}
	m.pull.s2.apply.Lock()
	defer m.pull.s2.apply.Unlock()
	for id, on := range out.Switches {
		module, item, _ := strings.Cut(id, "/")
		if module == "" || module == switchModule {
			continue
		}
		if changed, err := m.setSyncLocal(ctx, module, item, on); err == nil && changed {
			m.auditPeer(ctx, x.Name, "peer.sync", id, onOff(on))
		}
	}
}

// switchPullDue: regelmaessige Abholung nur der Schalter bei einem Mitglied faellig (merkt den Zeitpunkt).
func (m *Manager) switchPullDue(nodeID string) bool {
	s := &m.pull.s2
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.swPulled == nil {
		s.swPulled = map[string]time.Time{}
	}
	if time.Since(s.swPulled[nodeID]) < switchPullEvery {
		return false
	}
	s.swPulled[nodeID] = time.Now()
	return true
}

// catchUpSwitches holt bei einem Mitglied alle Schalter von vorn, ohne den Stand der anderen Bereiche zurueckzusetzen
// (nach dem Update kommt nur der Bereich der Schalter dazu; sonst holte jede Node einmal alles neu ab).
func (m *Manager) catchUpSwitches(ctx context.Context, x Member) error {
	self, since, applied := m.d.NodeID(), int64(0), 0
	p := m.provider(switchModule)
	for page := 0; page < 100 && p != nil; page++ {
		var out syncOut
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := m.call(cctx, x, http.MethodGet, "/peer/v2/sync?since="+strconv.FormatInt(since, 10)+"&items="+SwitchCap, nil, &out)
		cancel()
		if err != nil {
			return err
		}
		for _, e := range out.Items {
			if e.ID == "" || e.Origin == self || e.Unavailable || e.Module+"/"+e.Item != SwitchCap {
				continue
			}
			m.pull.s2.apply.Lock()
			if l, err := m.syncLocal(e.Module, e.Item, e.ID); err == nil && newer(e.ChangedAt, e.Origin, l) &&
				p.ClusterApply(WithClusterOrigin(ctx, e.Origin, e.ChangedAt), e.Item, e.ID, e.Data, e.Deleted) == nil {
				if _, err := m.logSync(e.Module, e.Item, e.ID, e.Deleted, e.Origin, e.ChangedAt); err == nil {
					applied++
				}
			}
			m.pull.s2.apply.Unlock()
		}
		if !out.More || out.Last <= since {
			break
		}
		since = out.Last
	}
	if applied > 0 {
		m.pokeSoon()
	}
	return nil
}
