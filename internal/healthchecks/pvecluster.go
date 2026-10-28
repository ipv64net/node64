package healthchecks

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/proxmox"
	"github.com/ipv64net/node64/internal/scheduler"
)

// Proxmox VE und Docker ueber den Cluster (Bereiche healthchecks/proxmox und healthchecks/docker, ohne Einstellung
// aus): die Systeme der Ueberwachung gehen samt Zugang (API-Token bzw. Zugangsdaten des Docker-Hosts) an die Nodes,
// bei denen der Bereich ebenfalls an ist. Dort werden sie mit dem eigenen Schluessel verschluesselt gespeichert und
// ebenfalls abgefragt; die Checks dieser Systeme koennen dann mehrere messende Nodes haben (Abgleich, Bewertung und
// Benachrichtigung wie bei allen Checks des Clusters). Docker nur ueber das Netz (tcp://, http(s)://, ssh://): ein
// lokaler Socket gehoert zu seiner Node. Kennung im Cluster ist System.UID (die ID ist je Node verschieden; ein
// Proxmox-Check traegt sie als params.system_uid). Meldungen der Ueberwachung selbst (Gast gestoppt, Schwellen,
// System nicht erreichbar) schickt nur die Heim-Node (die das System angelegt hat), ist sie nicht erreichbar, die
// Node mit der kleinsten Kennung - die Checks melden wie alle Checks des Clusters.

// Bereiche im Cluster (Modul healthchecks).
const (
	ClusterItemProxmox = "proxmox"
	ClusterItemDocker  = "docker"
)

// ClusterHooks verbinden das Modul mit dem Cluster (main.go ueber healthchecks/hccluster); nil = kein Cluster.
type ClusterHooks struct {
	// Change meldet eine Aenderung eines Systems (id = UID); ctx traegt bei Uebernahmen die Herkunft.
	Change func(ctx context.Context, item, id string, deleted bool)
	// Members: Nodes, mit denen die Checks und der Bereich item abgeglichen werden (ohne diese Node).
	Members func(ctx context.Context, item string) []Peer
}

// SetCluster haengt den Cluster an (vor Start), auch fuer die Statusseiten (statuscluster.go).
func (m *Module) SetCluster(h ClusterHooks) {
	m.cluster = h
	m.st.OnStatusCluster = nil
	if h.Change != nil {
		m.st.OnStatusCluster = func(ctx context.Context, uid string, deleted bool) {
			h.Change(ctx, ClusterItemStatusPages, uid, deleted)
		}
	}
}

// clusterSystem ist ein System im Cluster. Das Secret steht nur im Cluster im Klartext (HTTPS, die Nodes melden sich
// gegenseitig an) und wird auf der empfangenden Node mit ihrem Schluessel verschluesselt gespeichert.
type clusterSystem struct {
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	TokenID   string   `json:"token_id,omitempty"`
	Secret    string   `json:"secret,omitempty"`
	PinSHA256 string   `json:"pin_sha256,omitempty"`
	Interval  int      `json:"interval"`
	Enabled   bool     `json:"enabled"`
	Home      string   `json:"home,omitempty"`
}

// pveClusterItem: Bereich eines Systems und ob es ueber den Cluster geht (lokaler Docker-Socket nie).
func pveClusterItem(sys *proxmox.System) (string, bool) {
	if sys.IsDocker() {
		return ClusterItemDocker, !dockerIsLocal(sys)
	}
	return ClusterItemProxmox, true
}

// checkClusterItem: Bereich, ueber den ein Check mehrere messende Nodes haben kann ("" = nur die Besitzer-Node).
func checkClusterItem(c *Check) string {
	switch c.Type {
	case checks.TypeProxmox:
		return ClusterItemProxmox
	case checks.TypeDocker:
		if h := dockerCheckHost(c); h != checks.DefaultDockerHost() && !proxmox.DockerLocal(h) {
			return ClusterItemDocker
		}
	}
	return ""
}

// clusterMembers: Nodes des Bereichs (nil ohne Cluster bzw. Bereich hier aus).
func (m *Module) clusterMembers(ctx context.Context, item string) []Peer {
	if m.cluster.Members == nil || item == "" {
		return nil
	}
	return m.cluster.Members(ctx, item)
}

// clusterNodesOf: messende Nodes eines Docker- bzw. Proxmox-Checks. Ohne Cluster (bzw. Bereich) nur die
// Besitzer-Node (nil); sonst die Besitzer-Node vorn (bleibt, wie beim hub) und die gewaehlten Nodes, die den Bereich
// abgleichen. prev: bisherige Liste (Besitzerin = erste).
func (m *Module) clusterNodesOf(c *Check, prev []string) []string {
	if len(c.Nodes) == 0 {
		return nil
	}
	members := m.clusterMembers(context.Background(), checkClusterItem(c))
	if len(members) == 0 {
		return nil
	}
	owner := selfNodeID()
	if len(prev) > 0 {
		owner = prev[0]
	}
	ok := map[string]bool{selfNodeID(): true}
	for _, p := range members {
		ok[p.ID] = true
	}
	out := []string{owner}
	for _, id := range c.Nodes {
		if ok[id] && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	if len(out) == 1 {
		return nil
	}
	return out
}

// pveClusterChanged meldet eine Aenderung an den Cluster: geteilte Systeme, und eines, das nicht mehr geteilt wird
// (Docker-Host auf den lokalen Socket umgestellt), als geloescht.
func (m *Module) pveClusterChanged(ctx context.Context, old, sys *proxmox.System, deleted bool) {
	if m.cluster.Change == nil || sys == nil || !proxmox.ValidUID(sys.UID) {
		return
	}
	item, shared := pveClusterItem(sys)
	if !shared && !pveShared(old) {
		return
	}
	m.cluster.Change(ctx, item, sys.UID, deleted || !shared)
}

func pveShared(sys *proxmox.System) bool {
	if sys == nil {
		return false
	}
	_, shared := pveClusterItem(sys)
	return shared
}

// ClusterIDs: Kennungen der geteilten Systeme eines Bereichs (erster Abgleich).
func (m *Module) ClusterIDs(ctx context.Context, item string) ([]string, error) {
	if item == ClusterItemStatusPages {
		return m.statusClusterIDs(ctx)
	}
	list, err := m.pve.st.Systems(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, sys := range list {
		if it, shared := pveClusterItem(sys); it == item && shared && proxmox.ValidUID(sys.UID) {
			out = append(out, sys.UID)
		}
	}
	return out, nil
}

// ClusterGet liefert ein geteiltes System (found=false: gibt es nicht oder nicht mehr geteilt).
func (m *Module) ClusterGet(ctx context.Context, item, id string) (json.RawMessage, bool, error) {
	if item == ClusterItemStatusPages {
		return m.statusClusterGet(ctx, id)
	}
	sys, err := m.pve.st.SystemByUID(ctx, id)
	if errors.Is(err, proxmox.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if it, shared := pveClusterItem(sys); it != item || !shared {
		return nil, false, nil
	}
	home := sys.Home
	if home == "" {
		home = selfNodeID()
	}
	b, err := json.Marshal(clusterSystem{Kind: sys.Kind, Name: sys.Name, Addresses: sys.Addresses, TokenID: sys.TokenID, Secret: sys.Secret,
		PinSHA256: sys.PinSHA256, Interval: sys.Interval, Enabled: sys.Enabled, Home: home})
	return b, err == nil, err
}

var errClusterSystem = errors.New("cluster: system does not match the area")

// ClusterApply uebernimmt ein System einer anderen Node (anlegen, aendern, loeschen). Die Abfrage startet bzw.
// endet wie beim Speichern in der Oberflaeche; die Aenderung geht mit ihrer Herkunft (ctx) weiter an den Cluster.
func (m *Module) ClusterApply(ctx context.Context, item, id string, data json.RawMessage, deleted bool) error {
	if item == ClusterItemStatusPages {
		return m.statusClusterApply(ctx, id, data, deleted)
	}
	if !proxmox.ValidUID(id) || item != ClusterItemProxmox && item != ClusterItemDocker {
		return errClusterSystem
	}
	cur, err := m.pve.st.SystemByUID(ctx, id)
	if err != nil && !errors.Is(err, proxmox.ErrNotFound) {
		return err
	}
	if deleted {
		if cur == nil {
			return nil
		}
		if it, shared := pveClusterItem(cur); it != item || !shared {
			return nil // hier lokal (z. B. eigener Socket): bleibt
		}
		return m.pveDeleteSystemBy(ctx, cur.ID, nil)
	}
	var in clusterSystem
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	sys := &proxmox.System{Kind: in.Kind, Name: in.Name, Addresses: in.Addresses, TokenID: in.TokenID, Secret: in.Secret, PinSHA256: in.PinSHA256,
		Interval: in.Interval, Enabled: in.Enabled, UID: id, Home: in.Home}
	if sys.Home == selfNodeID() {
		sys.Home = ""
	}
	if it, shared := pveClusterItem(sys); it != item || !shared || sys.Kind != proxmox.KindPVE && sys.Kind != proxmox.KindDocker {
		return errClusterSystem
	}
	if sys.IsDocker() && sys.Secret == "" {
		sys.Secret = proxmox.DockerNoCreds // ohne Zugangsdaten (sonst hiesse leer „behalten“)
	}
	if cur == nil { // neu hier: exaktes Doppel unter anderer Kennung zusammenfuehren (die kleinere gilt)
		dup, err := m.pveDup(ctx, item, sys)
		if err != nil {
			return err
		}
		if dup != nil {
			if dup.UID < id {
				return nil // hier gilt die eigene Kennung, die andere Node uebernimmt sie
			}
			if err := m.pveAdoptUID(ctx, item, dup, id, sys.Home); err != nil {
				return err
			}
			cur = dup
		}
	}
	if cur != nil {
		sys.ID = cur.ID
	}
	return m.pveSaveSystemBy(ctx, sys, "cluster")
}

// pveDup sucht ein geteiltes System des Bereichs, das exakt gleich ist (Art, Name, Adressen, Token, Secret, Pin,
// Intervall, an/aus), aber eine andere Kennung hat - z. B. dasselbe Proxmox auf beiden Nodes vor dem Cluster
// angelegt. Die Heim-Node zaehlt nicht zum Inhalt.
func (m *Module) pveDup(ctx context.Context, item string, sys *proxmox.System) (*proxmox.System, error) {
	list, err := m.pve.st.Systems(ctx)
	if err != nil {
		return nil, err
	}
	secret := func(s string) string {
		if s == proxmox.DockerNoCreds {
			return ""
		}
		return s
	}
	for _, s := range list {
		if it, shared := pveClusterItem(s); it != item || !shared || !proxmox.ValidUID(s.UID) || s.UID == sys.UID {
			continue
		}
		if s.Kind == sys.Kind && s.Name == sys.Name && slices.Equal(s.Addresses, sys.Addresses) && s.TokenID == sys.TokenID &&
			secret(s.Secret) == secret(sys.Secret) && s.PinSHA256 == sys.PinSHA256 && s.Interval == sys.Interval && s.Enabled == sys.Enabled {
			return s, nil
		}
	}
	return nil, nil
}

// pveAdoptUID: ein System hier uebernimmt die (kleinere) Kennung seines exakten Doppels einer anderen Node. Die
// lokale Nummer bleibt (Einstellungen, Verlauf, „als Check“); Proxmox-Checks mit der alten Kennung bekommen die neue
// (als Aenderung, sie geht an den Cluster), die alte Kennung geht als geloescht hinaus.
func (m *Module) pveAdoptUID(ctx context.Context, item string, sys *proxmox.System, uid, home string) error {
	old := sys.UID
	if _, err := m.st.w.ExecContext(ctx, `UPDATE pve_systems SET uid = ?, home = ? WHERE id = ?`, uid, home, sys.ID); err != nil {
		return err
	}
	sys.UID, sys.Home = uid, home
	if list, err := m.st.Checks(ctx); err == nil {
		for _, c := range list {
			var p checks.ProxmoxParams
			if c.Type != checks.TypeProxmox || json.Unmarshal(c.Params, &p) != nil || p.SystemUID != old {
				continue
			}
			p.SystemUID = uid
			c.Params, _ = json.Marshal(p)
			c.UpdatedBy = "cluster"
			if err := m.st.Update(context.Background(), c); err != nil {
				m.log.Warn("cluster merge: proxmox check", "err", err)
				continue
			}
			if s := m.scheduler(); s != nil {
				if nc, _ := m.st.Check(ctx, c.Token); nc != nil {
					var rt *scheduler.Runtime // Zustand bleibt, nur die Kennung des Systems ist neu
					if live, ok := s.Runtime(nc.Token); ok {
						rt = &live
					}
					upsertSched(s, nc, rt)
				}
			}
		}
	}
	if m.cluster.Change != nil {
		m.cluster.Change(context.Background(), item, old, true) // neuer Zeitpunkt: die alte Kennung verschwindet ueberall
	}
	return nil
}

// pveNotifiesHere: diese Node schickt die Meldungen der Ueberwachung eines Systems (Heim-Node; ist sie nicht im
// Cluster erreichbar, die erreichbare Node mit der kleinsten Kennung).
func (m *Module) pveNotifiesHere(ctx context.Context, sys *proxmox.System) bool {
	me := selfNodeID()
	if sys == nil || sys.Home == "" || sys.Home == me {
		return true
	}
	item, _ := pveClusterItem(sys)
	first := me
	for _, p := range m.clusterMembers(ctx, item) {
		if !p.Online {
			continue
		}
		if p.ID == sys.Home {
			return false
		}
		if p.ID < first {
			first = p.ID
		}
	}
	return first == me
}

// pveUIDOf: lokale ID eines Systems ueber die Kennung (Check-Typ proxmox, Runner.ProxmoxUID).
func (m *Module) pveUIDOf(uid string) (int64, bool) {
	sys, err := m.pve.st.SystemByUID(context.Background(), uid)
	if err != nil {
		return 0, false
	}
	return sys.ID, true
}

// pveBackfillUIDs traegt die Kennung des Systems in Proxmox-Checks ohne params.system_uid ein (Checks von vor dem
// Cluster-Abgleich; ohne neuen Aenderungszeitpunkt, die Kennung reist mit der naechsten Aenderung).
func (m *Module) pveBackfillUIDs(ctx context.Context) {
	list, err := m.st.Checks(ctx)
	if err != nil {
		return
	}
	for _, c := range list {
		if c.Type != checks.TypeProxmox || (c.Owner != "" && c.Owner != "self") {
			continue
		}
		var p checks.ProxmoxParams
		if json.Unmarshal(c.Params, &p) != nil || p.SystemUID != "" {
			continue
		}
		sys, err := m.pve.st.System(ctx, p.SystemID)
		if err != nil || !proxmox.ValidUID(sys.UID) {
			continue
		}
		p.SystemUID = sys.UID
		b, _ := json.Marshal(p)
		_, _ = m.st.w.ExecContext(ctx, `UPDATE hc_checks SET params = ? WHERE token = ?`, string(b), c.Token)
	}
}

// keepSystemUID: ein Proxmox-Check von aussen ohne Kennung (hub, aeltere Node) behaelt die hier bekannte.
func keepSystemUID(cur *Check, params json.RawMessage) json.RawMessage {
	if cur == nil || cur.Type != checks.TypeProxmox {
		return params
	}
	var old, p checks.ProxmoxParams
	if json.Unmarshal(cur.Params, &old) != nil || old.SystemUID == "" || json.Unmarshal(params, &p) != nil || p.SystemUID != "" {
		return params
	}
	p.SystemUID = old.SystemUID
	b, err := json.Marshal(p)
	if err != nil {
		return params
	}
	return b
}

// pveLinkCheck: ein Check aus dem Cluster gehoert hier zu einem geteilten System - als „auch als Check gefuehrt“
// vermerken (Anzeige beim System, kein zweiter Check beim Einschalten, Intervall und Pause folgen dem System).
func (m *Module) pveLinkCheck(ctx context.Context, c *Check) {
	item := checkClusterItem(c)
	if item == "" || len(m.clusterMembers(ctx, item)) == 0 {
		return
	}
	var sys *proxmox.System
	key := ""
	switch c.Type {
	case checks.TypeProxmox:
		var p checks.ProxmoxParams
		if json.Unmarshal(c.Params, &p) != nil || p.SystemUID == "" {
			return
		}
		s, err := m.pve.st.SystemByUID(ctx, p.SystemUID)
		if err != nil {
			return
		}
		sys, key = s, p.Key
	case checks.TypeDocker:
		list, err := m.pve.st.Systems(ctx)
		if err != nil {
			return
		}
		host := dockerCheckHost(c)
		for _, s := range list {
			if s.IsDocker() && pveShared(s) && dockerSysHost(s) == host {
				sys, key = s, proxmox.TypeDocker+"/"+c.Target
				break
			}
		}
	}
	if sys == nil || !proxmox.ValidKey(key) {
		return
	}
	set, err := m.pve.st.Settings(ctx, sys.ID)
	if err != nil {
		return
	}
	it := set.Item(key)
	if it == nil {
		it = &proxmox.Settings{SystemID: sys.ID, Key: key}
	}
	if it.AsCheck && it.CheckToken == c.Token {
		return
	}
	it.AsCheck, it.CheckToken = true, c.Token
	if err := m.pve.st.SaveSettings(ctx, it); err != nil {
		m.log.Warn("cluster check link", "err", err)
	}
}
