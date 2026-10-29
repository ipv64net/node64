package peer

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
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
	HintKey  string `json:"hint_key,omitempty"` // kurzer Hinweis unter dem Schalter ("" = keiner)
	Default  bool   `json:"-"`                  // ohne Einstellung eingeschaltet
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

// Joiner kann ein Provider zusaetzlich erfuellen: nach jeder neuen Kopplung auf beiden Seiten aufgerufen (vor dem
// ersten Abgleich), z. B. um Eintraege, die ab dem Beitritt gelten sollen, mit dem jetzigen Zeitpunkt zu melden.
type Joiner interface {
	ClusterJoined(ctx context.Context)
}

// joined ruft ClusterJoined der Provider, die es haben.
func (m *Manager) joined(ctx context.Context) {
	m.mu.Lock()
	list := make([]Provider, 0, len(m.prov))
	for _, p := range m.prov {
		list = append(list, p)
	}
	m.mu.Unlock()
	for _, p := range list {
		if j, ok := p.(Joiner); ok {
			j.ClusterJoined(ctx)
		}
	}
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

// Healthchecks und Benachrichtigungen sind fest eingebaut (eigener Weg /peer/v1/changes), die Bereiche schalten
// die vorhandenen Eintragsarten (check, maintenance; settings = Benachrichtigungs-Einstellungen). Die Systeme der
// Proxmox-VE- und Docker-Ueberwachung (proxmox, docker), die Statusseiten (statuspages) und die
// Benachrichtigungskanaele (channels; alle ohne Einstellung aus) laufen ueber den allgemeinen Weg /peer/v2/sync: die
// Module melden dafuer einen Provider mit der ID "healthchecks" bzw. "notifications" an (v2Item).
var healthchecksModule = ModuleInfo{ID: "healthchecks", TitleKey: "cluster.mod.healthchecks", Items: []ItemInfo{
	{ID: "checks", TitleKey: "cluster.item.checks", Default: true},
	{ID: "maintenance", TitleKey: "cluster.item.maintenance", Default: true},
	{ID: "proxmox", TitleKey: "cluster.item.proxmox"},
	{ID: "docker", TitleKey: "cluster.item.docker"},
	{ID: "statuspages", TitleKey: "cluster.item.statuspages"},
}}

var notificationsModule = ModuleInfo{ID: "notifications", TitleKey: "cluster.mod.notifications", Items: []ItemInfo{
	{ID: "settings", TitleKey: "cluster.item.notify_settings", Default: true},
	{ID: "channels", TitleKey: "cluster.item.notify_channels", HintKey: "cluster.channels_hint"},
}}

// builtin: Module mit eigenem Weg (ohne Einstellung eingeschaltet, laufen mit dem Healthchecks-Modul).
func builtin(id string) bool { return id == "healthchecks" || id == "notifications" }

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

// v2Item: der Bereich laeuft ueber /peer/v2/sync (Provider des Moduls kennt ihn; bei Healthchecks nur die Bereiche
// des Providers, die anderen laufen ueber den eigenen Weg).
func (m *Manager) v2Item(module, item string) bool {
	p := m.provider(module)
	if p == nil {
		return false
	}
	if !builtin(module) {
		return true
	}
	for _, it := range p.ClusterModule().Items {
		if it.ID == item {
			return true
		}
	}
	return false
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
	out := []ModuleInfo{healthchecksModule, notificationsModule}
	m.mu.Lock()
	ids := make([]string, 0, len(m.prov))
	for id := range m.prov {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if !builtin(id) { // Provider eingebauter Module: Bereiche stehen schon oben
			out = append(out, m.prov[id].ClusterModule())
		}
	}
	m.mu.Unlock()
	return out
}

// SyncModules liefert alle abgleichbaren Module mit ihren Schaltern auf dieser Node. Healthchecks und
// Benachrichtigungen sind ohne Einstellung eingeschaltet (wie bisher), alle anderen Module aus.
func (m *Manager) SyncModules(ctx context.Context) []ModuleState {
	cfg := m.syncCfg(ctx)
	var out []ModuleState
	for _, mi := range m.modules() {
		c := cfg[mi.ID]
		st := ModuleState{ModuleInfo: mi, Available: (!builtin(mi.ID) || m.checks() != nil) && m.running(mi.ID), Enabled: builtin(mi.ID), Items: []ItemState{}}
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

// running: ein Provider kann melden, dass sein Modul hier gerade nicht laeuft (ClusterRunning); seine Bereiche sind
// dann aus (z. B. DynDNS: eine Node mit ausgeschaltetem Modul wird nie zustaendig).
func (m *Manager) running(id string) bool {
	r, ok := m.provider(id).(interface{ ClusterRunning() bool })
	return !ok || r.ClusterRunning()
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
// gleichen nur die Checks und Wartungsfenster ab.
func memberSyncOn(x Member, module, item string) bool {
	if x.Sync == nil {
		return module == "healthchecks" && (item == "checks" || item == "maintenance")
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

// wants: Bereiche, die hier (own = syncCaps) und beim Mitglied eingeschaltet sind – module "" = alle Bereiche des
// Wegs v2 als "modul/bereich", sonst nur die Bereiche dieses Moduls ohne Praefix. Sortiert.
func (m *Manager) wants(own []string, x Member, module string) []string {
	out := []string{}
	for _, c := range own {
		mod, item, _ := strings.Cut(c, "/")
		if module == "" && !m.v2Item(mod, item) || module != "" && mod != module || !memberSyncOn(x, mod, item) {
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

// v1Wants: Eintragsbereiche des eigenen Wegs (checks, maintenance, settings), die hier und beim Mitglied an sind.
// "channels": die Kanaele gehen ueber v2, die Zuordnung Check -> Kanal (Kennungen der Kanaele) aber mit den Checks;
// der Eintrag laesst die Checks beim Einschalten von vorn abholen und sagt der liefernden Node, dass sie sie mitschickt.
func (m *Manager) v1Wants(own []string, x Member) []string {
	out := m.wants(own, x, "healthchecks")
	out = slices.DeleteFunc(out, func(item string) bool { return m.v2Item("healthchecks", item) })
	if has(own, "notifications/settings") && memberSyncOn(x, "notifications", "settings") {
		out = append(out, "settings")
	}
	if has(own, "notifications/channels") && memberSyncOn(x, "notifications", "channels") && m.v2Item("notifications", "channels") {
		out = append(out, "channels")
	}
	sort.Strings(out)
	return out
}

// v1Members: Mitglieder, mit denen ueber den eigenen Weg etwas abzugleichen ist (nicht ausgesetzt).
func (m *Manager) v1Members(ctx context.Context) []Member {
	own := m.syncCaps(ctx)
	list, _ := m.Members(ctx)
	out := list[:0]
	for _, x := range list {
		if !x.Suspended() && len(m.v1Wants(own, x)) > 0 {
			out = append(out, x)
		}
	}
	return out
}

// HCItemMembers: Mitglieder, mit denen die Checks und der Healthchecks-Bereich item (proxmox, docker) abgeglichen
// werden (hier und dort eingeschaltet, nicht ausgesetzt) – sie koennen solche Checks mitmessen.
func (m *Manager) HCItemMembers(ctx context.Context, item string) []Member {
	if !m.syncOn(ctx, "healthchecks", item) {
		return nil
	}
	list := m.hcMembers(ctx)
	out := make([]Member, 0, len(list))
	for _, x := range list {
		if memberSyncOn(x, "healthchecks", item) {
			out = append(out, x)
		}
	}
	return out
}

// AreaMembers: Mitglieder, mit denen der Bereich module/item abgeglichen wird (hier und dort eingeschaltet, nicht
// ausgesetzt); nil, wenn er hier aus ist.
func (m *Manager) AreaMembers(ctx context.Context, module, item string) []Member {
	if !m.syncOn(ctx, module, item) {
		return nil
	}
	list, _ := m.Members(ctx)
	out := make([]Member, 0, len(list))
	for _, x := range list {
		if !x.Suspended() && memberSyncOn(x, module, item) {
			out = append(out, x)
		}
	}
	return out
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
