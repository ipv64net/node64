package peer

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

// Cluster: die lokale Gruppe als allgemeiner Abgleich zwischen Nodes (Menue „Cluster“). Jedes Modul meldet hier,
// welche Bereiche es abgleichen kann (Provider); je Node wird je Modul und Bereich eingeschaltet, was abgeglichen
// wird. Ausgetauscht wird ein Bereich nur mit Nodes, bei denen er ebenfalls eingeschaltet ist (Ping meldet die
// Bereiche), daher bekommt eine Node nie Eintraege, die sie nicht kennt. Healthchecks laeuft ueber den bisherigen
// Weg (/peer/v1/changes, Messwerte, hub-Daten), alle weiteren Module ueber /peer/v2/sync (sync2.go).

// ItemInfo ist ein abgleichbarer Bereich eines Moduls (z. B. healthchecks/checks, certs/certificates).
type ItemInfo struct {
	ID       string `json:"id"`
	TitleKey string `json:"title_key"`
	Default  bool   `json:"-"` // ohne Einstellung eingeschaltet
}

// ModuleInfo beschreibt ein Modul mit seinen Bereichen.
type ModuleInfo struct {
	ID       string     `json:"id"`
	TitleKey string     `json:"title_key"`
	Items    []ItemInfo `json:"-"`
}

// Provider ist ein Modul, das Eintraege ueber den Cluster abgleicht (ausser Healthchecks, das seinen eigenen Weg hat).
// Der Cluster fuehrt Protokoll und Zeitstempel (die juengere Aenderung gewinnt); das Modul liefert nur Daten.
type Provider interface {
	ClusterModule() ModuleInfo
	// ClusterIDs: alle vorhandenen Eintraege eines Bereichs (fuer den ersten Abgleich).
	ClusterIDs(ctx context.Context, item string) ([]string, error)
	// ClusterGet: aktueller Stand eines Eintrags; found=false, wenn es ihn nicht (mehr) gibt.
	ClusterGet(ctx context.Context, item, id string) (data json.RawMessage, found bool, err error)
	// ClusterApply uebernimmt einen Eintrag einer anderen Node (deleted: loeschen). ctx traegt die Herkunft
	// (ClusterOrigin): Aenderungs-Hooks, die dabei ClusterChange rufen, behalten so Urheberin und Zeitpunkt.
	ClusterApply(ctx context.Context, item, id string, data json.RawMessage, deleted bool) error
}

// ItemState ist ein Bereich mit seinem Schalter auf dieser Node.
type ItemState struct {
	ItemInfo
	Enabled bool `json:"enabled"`
}

// ModuleState ist ein Modul mit Schaltern (Available: Modul laeuft auf dieser Node).
type ModuleState struct {
	ModuleInfo
	Available bool        `json:"available"`
	Enabled   bool        `json:"enabled"`
	Items     []ItemState `json:"items"`
}

const setSync = "peer.sync" // {"module": {"enabled": true, "items": {"item": true}}}

// Healthchecks ist fest eingebaut (eigener Weg), die Bereiche schalten die vorhandenen Eintragsarten.
var healthchecksModule = ModuleInfo{ID: "healthchecks", TitleKey: "cluster.mod.healthchecks", Items: []ItemInfo{
	{ID: "checks", TitleKey: "cluster.item.checks", Default: true},
	{ID: "maintenance", TitleKey: "cluster.item.maintenance", Default: true},
	{ID: "settings", TitleKey: "cluster.item.notify_settings", Default: true},
}}

// ErrUnknownSync: Modul oder Bereich gibt es nicht.
var ErrUnknownSync = errors.New("unknown cluster module or item")

// RegisterProvider meldet ein Modul an (beim Start, vor Run).
func (m *Manager) RegisterProvider(p Provider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.prov == nil {
		m.prov = map[string]Provider{}
	}
	m.prov[p.ClusterModule().ID] = p
}

func (m *Manager) provider(id string) Provider {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.prov[id]
}

type syncModCfg struct {
	Enabled *bool           `json:"enabled,omitempty"`
	Items   map[string]bool `json:"items,omitempty"`
}

func (m *Manager) syncCfg(ctx context.Context) map[string]syncModCfg {
	cfg := map[string]syncModCfg{}
	_ = json.Unmarshal([]byte(m.d.Core.SettingOr(ctx, setSync, "{}")), &cfg)
	return cfg
}

func (m *Manager) modules() []ModuleInfo {
	out := []ModuleInfo{healthchecksModule}
	m.mu.Lock()
	ids := make([]string, 0, len(m.prov))
	for id := range m.prov {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		out = append(out, m.prov[id].ClusterModule())
	}
	m.mu.Unlock()
	return out
}

// SyncModules liefert alle abgleichbaren Module mit ihren Schaltern auf dieser Node. Healthchecks ist ohne
// Einstellung eingeschaltet (wie bisher), alle anderen Module aus.
func (m *Manager) SyncModules(ctx context.Context) []ModuleState {
	cfg := m.syncCfg(ctx)
	var out []ModuleState
	for _, mi := range m.modules() {
		c := cfg[mi.ID]
		st := ModuleState{ModuleInfo: mi, Available: mi.ID != "healthchecks" || m.checks() != nil, Enabled: mi.ID == "healthchecks", Items: []ItemState{}}
		if c.Enabled != nil {
			st.Enabled = *c.Enabled
		}
		for _, it := range mi.Items {
			on, ok := c.Items[it.ID]
			if !ok {
				on = it.Default
			}
			st.Items = append(st.Items, ItemState{ItemInfo: it, Enabled: on})
		}
		out = append(out, st)
	}
	return out
}

// SetSync schaltet ein Modul (item "") oder einen Bereich.
func (m *Manager) SetSync(ctx context.Context, module, item string, on bool) error {
	var mi *ModuleInfo
	for _, x := range m.modules() {
		if x.ID == module {
			mi = &x
			break
		}
	}
	if mi == nil {
		return ErrUnknownSync
	}
	if item != "" {
		found := false
		for _, it := range mi.Items {
			found = found || it.ID == item
		}
		if !found {
			return ErrUnknownSync
		}
	}
	cfg := m.syncCfg(ctx)
	c := cfg[module]
	if item == "" {
		c.Enabled = &on
	} else {
		if c.Items == nil {
			c.Items = map[string]bool{}
		}
		c.Items[item] = on
	}
	cfg[module] = c
	b, _ := json.Marshal(cfg)
	if err := m.d.Core.SetSetting(ctx, setSync, string(b)); err != nil {
		return err
	}
	m.pokeSoon() // andere Nodes erfahren die Bereiche beim naechsten Ping
	return nil
}

// syncCaps: eingeschaltete Bereiche dieser Node als "modul/bereich" (fuer den Ping).
func (m *Manager) syncCaps(ctx context.Context) []string {
	out := []string{}
	for _, st := range m.SyncModules(ctx) {
		if !st.Available || !st.Enabled {
			continue
		}
		for _, it := range st.Items {
			if it.Enabled {
				out = append(out, st.ID+"/"+it.ID)
			}
		}
	}
	return out
}

// syncOn: Bereich auf dieser Node eingeschaltet.
func (m *Manager) syncOn(ctx context.Context, module, item string) bool {
	for _, c := range m.syncCaps(ctx) {
		if c == module+"/"+item {
			return true
		}
	}
	return false
}

// memberSyncOn: Bereich bei einem Mitglied eingeschaltet (laut letztem Ping). Nodes ohne Angabe (aeltere Version)
// gleichen nur die Healthchecks ab.
func memberSyncOn(x Member, module, item string) bool {
	if x.Sync == nil {
		return module == "healthchecks"
	}
	for _, c := range x.Sync {
		if c == module+"/"+item {
			return true
		}
	}
	return false
}

// both: Bereich hier und beim Mitglied eingeschaltet.
func (m *Manager) both(ctx context.Context, x Member, module, item string) bool {
	return m.syncOn(ctx, module, item) && memberSyncOn(x, module, item)
}

type originKey struct{}

type clusterOrigin struct {
	node string
	at   time.Time
}

// WithClusterOrigin markiert eine von einer anderen Node uebernommene Aenderung (Urheberin, Zeitpunkt).
func WithClusterOrigin(ctx context.Context, node string, at time.Time) context.Context {
	return context.WithValue(ctx, originKey{}, clusterOrigin{node, at})
}

// ClusterOrigin liefert Urheberin und Zeitpunkt einer uebernommenen Aenderung.
func ClusterOrigin(ctx context.Context) (string, time.Time, bool) {
	o, ok := ctx.Value(originKey{}).(clusterOrigin)
	return o.node, o.at, ok
}

func joinCaps(c []string) string { return strings.Join(c, ",") }

func splitCaps(s string) []string {
	out := []string{}
	for _, c := range strings.Split(s, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// wants: Bereiche, die hier (own = syncCaps) und beim Mitglied eingeschaltet sind – module "" = alle Module
// ausser Healthchecks als "modul/bereich" (Weg v2), sonst nur die Bereiche dieses Moduls ohne Praefix. Sortiert.
func (m *Manager) wants(own []string, x Member, module string) []string {
	out := []string{}
	for _, c := range own {
		mod, item, _ := strings.Cut(c, "/")
		if module == "" && mod == "healthchecks" || module != "" && mod != module || !memberSyncOn(x, mod, item) {
			continue
		}
		if module != "" {
			c = item
		}
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// hcMembers: Mitglieder, mit denen die Healthchecks abgeglichen werden (nicht ausgesetzt, Checks auf beiden
// Seiten eingeschaltet) – nur diese zaehlen fuer Messwerte, Benachrichtigungen und das Weiterreichen an den hub.
func (m *Manager) hcMembers(ctx context.Context) []Member {
	if !m.syncOn(ctx, "healthchecks", "checks") {
		return nil
	}
	list, _ := m.Members(ctx)
	out := list[:0]
	for _, x := range list {
		if !x.Suspended() && memberSyncOn(x, "healthchecks", "checks") {
			out = append(out, x)
		}
	}
	return out
}
