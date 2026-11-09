package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"
)

// Zustaendige Node je Host (Plan "Wer ueberwacht"): genau eine Node fragt ab, speichert den Verlauf und meldet. Je
// Host gibt es eine bevorzugte Node (Standard: die anlegende) und optional Ersatz-Nodes. Die zustaendige Node steht im
// Eintrag "owner:<host>" (lokal m64_hosts.owner_node, leer = die bevorzugte).
//
//   - Uebernahme: zustaendige Node laenger als die Karenz des Clusters nicht erreichbar (2 min, laut peer offline),
//     ausgesetzt oder Monitor64 bzw. der Bereich dort aus -> die erste Kandidatin (bevorzugte, dann Ersatz-Nodes in
//     ihrer Reihenfolge), die seit clusterStable erreichbar ist, traegt sich ein. Uebernehmen darf eine Node nur mit
//     Mehrheit: mehr als die Haelfte aller Mitglieder des Bereichs (sich eingeschlossen) erreichbar; zwei Nodes duerfen
//     immer (sonst gaebe es keine Ausfallsicherheit; doppelte Meldungen im Split-Brain moeglich).
//   - Rueckgabe: die zustaendige Node gibt erst ab, wenn eine Kandidatin vor ihr seit clusterStable erreichbar ist.
//   - Eigene Hosts laufen ohne Mehrheit weiter; hat die Node keine Mehrheit und der Host eine Ersatz-Node, misst sie
//     weiter (Verlauf ohne Luecke), meldet aber nicht (die Mehrheit hat ihn womoeglich uebernommen).
//   - Ohne erreichbare zustaendige Node zeigen die anderen den Host als "zustaendige Node nicht erreichbar"
//     (Unbekannt) und melden nichts.
//
// Jede Uebernahme und Rueckgabe steht als Ereignis im Verlauf des Hosts (Akteur System, Node-Kennung).

var (
	clusterStable    = 5 * time.Minute // so lange erreichbar, bevor eine Node (wieder) zustaendig wird
	clusterStartWait = time.Minute     // nach dem Start: erst den Stand der anderen abholen
)

const (
	roleReport  = iota // fragt ab, speichert, meldet
	roleMeasure        // fragt ab und speichert, meldet nicht (ohne Mehrheit, Ersatz-Node vorhanden)
	roleIdle           // eine andere Node ist zustaendig
)

// clusterSnap ist der Blick auf die Mitglieder des Bereichs config (alle clusterTick neu).
type clusterSnap struct {
	Active    bool
	Self      string
	Peers     map[string]ClusterPeer
	Stable    map[string]bool
	Total     int // Mitglieder des Bereichs mit dieser Node
	Connected int // davon erreichbar (mit dieser Node)
	Majority  bool
	// Unsure: Mehrheit nur, solange schweigende Mitglieder (ClusterPeer.Silent) noch als erreichbar zaehlen
	Unsure bool
	At     time.Time
}

func (s *clusterSnap) online(id string) bool {
	if id == s.Self {
		return true
	}
	p, ok := s.Peers[id]
	return ok && p.Online
}

func (s *clusterSnap) name(id string) string {
	if p, ok := s.Peers[id]; ok && p.Name != "" {
		return p.Name
	}
	return id
}

// clusterRefresh liest die Mitglieder und merkt, seit wann sie ununterbrochen erreichbar sind.
func (m *Module) clusterRefresh(ctx context.Context) *clusterSnap {
	now := m.cl.clock()
	s := &clusterSnap{Self: m.clusterSelf(), Peers: map[string]ClusterPeer{}, Stable: map[string]bool{}, At: now}
	var list []ClusterPeer
	if m.hooks().Members != nil {
		list = m.hooks().Members(ctx, ClusterItemConfig)
	}
	m.cl.mu.Lock()
	if m.cl.since == nil {
		m.cl.since, m.cl.known = map[string]time.Time{}, map[string]bool{}
	}
	for _, p := range list {
		if p.ID == "" || p.ID == s.Self {
			continue
		}
		s.Peers[p.ID] = p
		switch {
		case !p.Online:
			delete(m.cl.since, p.ID)
		case !m.cl.known[p.ID]:
			m.cl.since[p.ID] = time.Time{} // beim ersten Blick erreichbar: gilt als stabil
		default:
			if _, ok := m.cl.since[p.ID]; !ok {
				m.cl.since[p.ID] = now
			}
		}
		m.cl.known[p.ID] = true
		if at, ok := m.cl.since[p.ID]; ok && p.Online && (at.IsZero() || now.Sub(at) >= clusterStable) {
			s.Stable[p.ID] = true
		}
	}
	for id := range m.cl.since { // nicht mehr gemeldet (z. B. entfernt): beim Wiederauftauchen erst nach clusterStable stabil
		if _, ok := s.Peers[id]; !ok {
			delete(m.cl.since, id)
		}
	}
	m.cl.mu.Unlock()
	s.Active = len(s.Peers) > 0 && s.Self != ""
	s.Total, s.Connected = len(s.Peers)+1, 1
	sure := 1
	for _, p := range s.Peers {
		if p.Online {
			s.Connected++
			if !p.Silent {
				sure++
			}
		}
	}
	s.Majority = s.Connected*2 > s.Total || s.Total == 2 // zwei Nodes: Uebernahme erlaubt (Sonderfall)
	s.Unsure = s.Majority && !(sure*2 > s.Total || s.Total == 2)
	if old := m.cl.snap.Swap(s); old == nil || old.Active != s.Active {
		m.cl.mu.Lock()
		m.cl.roles = nil // Cluster an/aus: Rollen neu bestimmen (Zustand gleich melden)
		m.cl.mu.Unlock()
	}
	return s
}

// clusterSnapshot liefert den letzten Blick (beim ersten Mal sofort gelesen).
func (m *Module) clusterSnapshot() *clusterSnap {
	if s := m.cl.snap.Load(); s != nil {
		return s
	}
	if m.hooks().Members == nil {
		s := &clusterSnap{Self: m.clusterSelf()}
		return s
	}
	return m.clusterRefresh(context.Background())
}

// preferredOf: bevorzugte Node (leer = die Node, auf der der Host angelegt wurde; nur dort steht sie leer, uebernommene
// Hosts tragen sie immer).
func preferredOf(h *Host, self string) string {
	if h.PreferredNode != "" {
		return h.PreferredNode
	}
	return self
}

// ownerOf: zustaendige Node (leer = die bevorzugte).
func ownerOf(h *Host, self string) string {
	if h.OwnerNode != "" {
		return h.OwnerNode
	}
	return preferredOf(h, self)
}

// candidatesOf: bevorzugte Node, dann die Ersatz-Nodes (Reihenfolge wie eingetragen, ohne Doppel).
func candidatesOf(h *Host, self string) []string {
	out := []string{preferredOf(h, self)}
	for _, b := range h.BackupNodes {
		if b != "" && !slices.Contains(out, b) {
			out = append(out, b)
		}
	}
	return out
}

// roleOf: was diese Node mit dem Host tut (und wer zustaendig ist).
func (m *Module) roleOf(h *Host) (int, string) {
	s := m.clusterSnapshot()
	if !s.Active { // ohne Cluster (allein, Bereich aus) gehoert ein Host seiner bevorzugten Node
		if p := preferredOf(h, s.Self); p != s.Self {
			return roleIdle, p
		}
		return roleReport, s.Self
	}
	owner := ownerOf(h, s.Self)
	if owner != s.Self {
		return roleIdle, owner
	}
	if s.Majority && !s.Unsure {
		return roleReport, owner
	}
	// ohne (sichere) Mehrheit und mit Ersatz-Node: messen, nicht melden. Schweigen Mitglieder erst kurz (diese Node ist
	// vielleicht selbst abgetrennt), meldet sie erst wieder, wenn klar ist, ob die Mehrheit bleibt - sonst kaeme von
	// einer abgetrennten Node "nicht erreichbar", bevor der Cluster sie nach 2 min als weg sieht
	for _, c := range candidatesOf(h, s.Self) {
		if _, member := s.Peers[c]; member && c != s.Self {
			return roleMeasure, owner // ohne Mehrheit und mit Ersatz-Node: messen, nicht melden
		}
	}
	return roleReport, owner
}

// ClusterNodeUsed: ein Host nennt die Node als bevorzugte, zustaendige oder Ersatz-Node (m64cluster: ein Mitglied mit
// ausgeschaltetem Monitor64 zaehlt dann als nicht erreichbar mit, statt zu fehlen).
func (m *Module) ClusterNodeUsed(ctx context.Context, id string) bool {
	if !reNodeID.MatchString(id) {
		return false
	}
	var one int
	err := m.st.Reader().QueryRowContext(ctx, `SELECT 1 FROM m64_hosts WHERE deleted = 0 AND (preferred_node = ? OR owner_node = ? OR instr(backup_nodes, ?) > 0) LIMIT 1`,
		id, id, `"`+id+`"`).Scan(&one)
	return err == nil
}

// knownNodes: diese Node und die Mitglieder des Bereichs.
func (m *Module) knownNodes(ctx context.Context) map[string]bool {
	known := map[string]bool{m.clusterSelf(): true}
	if f := m.hooks().Members; f != nil {
		for _, p := range f(ctx, ClusterItemConfig) {
			known[p.ID] = true
		}
	}
	return known
}

// importNodes: bevorzugte, zustaendige und Ersatz-Nodes eines importierten Hosts nur, wenn es diese Node oder ein
// Mitglied des Clusters ist; sonst gehoert der Host dieser Node (leer).
func importNodes(row map[string]any, known map[string]bool) {
	for _, c := range []string{"preferred_node", "owner_node"} {
		if v, _ := row[c].(string); v != "" && !known[v] {
			row[c] = ""
		}
	}
	if v, _ := row["backup_nodes"].(string); v != "" {
		var keep []string
		for _, b := range parseList(v) {
			if known[b] {
				keep = append(keep, b)
			}
		}
		row["backup_nodes"] = jsonList(keep)
	}
}

// importOwners meldet nach einem Import die zustaendige Node der importierten Hosts an den Cluster (Eintrag
// "owner:<host>"). Sonst weicht sie hier still von den anderen Nodes ab, und womoeglich ueberwacht niemand den Host.
// Leer wird sie ausdruecklich auf die bevorzugte gesetzt: ein spaeter ankommender Host-Eintrag mit anderer bevorzugter
// Node haelt sonst drueben die alte fest (rowApply).
func (m *Module) importOwners(ctx context.Context, uids []string) {
	if m.hooks().Change == nil {
		return
	}
	self := m.clusterSelf()
	for _, uid := range uids {
		h, err := m.store.Host(ctx, uid)
		if err != nil {
			continue
		}
		owner := ownerOf(h, self)
		if h.OwnerNode == "" {
			if _, err := m.st.Writer().ExecContext(ctx, `UPDATE m64_hosts SET owner_node = ? WHERE uid = ?`, owner, uid); err != nil {
				m.log.Warn("monitor64: import owner", "host", h.Name, "err", err)
				continue
			}
		}
		m.clusterChange(ctx, ClusterItemConfig, "owner:"+uid, false)
	}
}

// decideOwner: neue zustaendige Node fuer h ("" = bleibt).
func decideOwner(h *Host, s *clusterSnap) (string, string) {
	owner := ownerOf(h, s.Self)
	desired := ""
	for _, c := range candidatesOf(h, s.Self) {
		if c == s.Self || s.Stable[c] {
			desired = c
			break
		}
	}
	switch {
	case owner == s.Self:
		if desired != "" && desired != s.Self {
			return desired, "handover" // eine Kandidatin vor dieser Node ist lange genug erreichbar
		}
	case s.online(owner):
	case desired == s.Self && s.Majority:
		return s.Self, "takeover"
	}
	return "", ""
}

// clusterOwners entscheidet fuer alle Hosts ueber Uebernahme und Rueckgabe.
func (m *Module) clusterOwners(ctx context.Context, s *clusterSnap) {
	if !s.Active || m.cl.clock().Sub(m.cl.started) < clusterStartWait {
		return
	}
	hosts, err := m.store.Hosts(ctx)
	if err != nil {
		return
	}
	for _, h := range hosts {
		next, how := decideOwner(h, s)
		if next == "" {
			continue
		}
		m.setOwner(ctx, h, next, how, s)
	}
}

// setOwner traegt eine neue zustaendige Node ein (Ereignis im Verlauf des Hosts, Meldung an den Cluster).
func (m *Module) setOwner(ctx context.Context, h *Host, node, how string, s *clusterSnap) {
	prev := ownerOf(h, s.Self)
	if _, err := m.st.Writer().ExecContext(ctx, `UPDATE m64_hosts SET owner_node = ? WHERE uid = ?`, node, h.UID); err != nil {
		m.log.Warn("monitor64: cluster owner", "host", h.Name, "err", err)
		return
	}
	m.event(ctx, "", h.UID, "", how, i18nText("monitor64.detail.cluster_"+how, "from", s.name(prev), "to", s.name(node)), SystemActor, m.cl.clock())
	m.log.Info("monitor64: host responsibility changed", "host", h.Name, "from", s.name(prev), "to", s.name(node), "how", how)
	m.clusterChange(ctx, ClusterItemConfig, "owner:"+h.UID, false)
	m.ReloadHost(ctx, h.UID)
}

// ownerEntry ist der Eintrag "owner:<host>": zustaendige Node und die letzten Uebernahmen (Verlauf des Hosts).
type ownerEntry struct {
	Node   string       `json:"node"`
	Events []eventEntry `json:"events,omitempty"`
}

// ownerEvents: Ereignisse, die mit der Zustaendigkeit gehen.
var ownerEvents = []any{"takeover", "handover"}

const ownerEventsKeep = 20

var errOwnerNoHost = errors.New("monitor64 cluster: owner entry before its host")

func (m *Module) ownerGet(ctx context.Context, uid string) (json.RawMessage, bool, error) {
	var node string
	err := m.st.Reader().QueryRowContext(ctx, `SELECT owner_node FROM m64_hosts WHERE uid = ? AND deleted = 0`, uid).Scan(&node)
	if err != nil || node == "" {
		return nil, false, nil
	}
	e := ownerEntry{Node: node, Events: m.eventsWhere(ctx, `host_uid = ? AND problem_uid = '' AND kind IN (?, ?) ORDER BY ts DESC, id DESC LIMIT `+strconv.Itoa(ownerEventsKeep),
		append([]any{uid}, ownerEvents...)...)}
	b, err := json.Marshal(e)
	return b, err == nil, err
}

func (m *Module) ownerApply(ctx context.Context, uid string, data json.RawMessage, deleted bool) error {
	var e ownerEntry
	if !deleted {
		if err := json.Unmarshal(data, &e); err != nil {
			return err
		}
		if !reNodeID.MatchString(e.Node) {
			return errClItem
		}
	}
	res, err := m.st.Writer().ExecContext(ctx, `UPDATE m64_hosts SET owner_node = ? WHERE uid = ?`, e.Node, uid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if deleted {
			return nil
		}
		return errOwnerNoHost // Host noch nicht da (Eintrag kam vor dem Host): spaeter erneut, sonst ginge er verloren
	}
	for _, ev := range e.Events {
		if ev.Host != uid || !slices.Contains(ownerEvents, any(ev.Kind)) {
			continue
		}
		m.insertEvent(ctx, ev, "")
	}
	m.clusterDirty("access", uid, uid) // Host neu laden (Rolle)
	return nil
}

// ---------------------------------------------------------------------------------------------------------
// Probleme beim Wechsel der Zustaendigkeit

// clusterProblems: die zustaendige Node fuehrt offene Probleme anderer Nodes weiter (uebernimmt sie, meldet nichts
// doppelt); doppelt offene Probleme (Split-Brain) schliesst die nicht zustaendige Node mit "durch Uebergabe beendet",
// sobald sie die zustaendige erreicht (bzw. die zustaendige, wenn die andere Node nicht mehr Mitglied ist).
func (m *Module) clusterProblems(ctx context.Context, s *clusterSnap) {
	if !s.Active || m.cl.clock().Sub(m.cl.started) < clusterStartWait {
		return
	}
	type prob struct{ uid, node, host, key string }
	rows, err := m.st.Reader().QueryContext(ctx, `SELECT uid, node_id, host_uid, service_key FROM m64_problems WHERE closed_at = '' AND deleted = 0`)
	if err != nil {
		return
	}
	byHost := map[string][]prob{}
	for rows.Next() {
		var p prob
		if rows.Scan(&p.uid, &p.node, &p.host, &p.key) == nil {
			byHost[p.host] = append(byHost[p.host], p)
		}
	}
	rows.Close()
	if len(byHost) == 0 {
		return
	}
	hosts, err := m.store.Hosts(ctx)
	if err != nil {
		return
	}
	for _, h := range hosts {
		list := byHost[h.UID]
		if len(list) == 0 {
			continue
		}
		role, owner := m.roleOf(h)
		has := func(node, key string) bool {
			for _, p := range list {
				if p.node == node && p.key == key {
					return true
				}
			}
			return false
		}
		for _, p := range list {
			switch {
			case role == roleReport && p.node != s.Self && !has(s.Self, p.key):
				// weiterfuehren: das Problem gehoert jetzt dieser Node (Quittierung und "gemeldet an" bleiben)
				_, _ = m.st.Writer().ExecContext(ctx, `UPDATE m64_problems SET node_id = ?, updated_at = ? WHERE uid = ? AND closed_at = '' AND node_id = ?`,
					s.Self, tsNow(), p.uid, p.node)
			case role == roleReport && p.node != s.Self && !s.online(p.node) && !isPeer(s, p.node):
				m.closeHandover(ctx, p.uid, h.UID, p.key) // Doppel einer Node, die nicht mehr Mitglied ist
			case role == roleIdle && p.node == s.Self && s.online(owner) && has(owner, p.key):
				m.closeHandover(ctx, p.uid, h.UID, p.key) // Doppel: die zustaendige Node hat es auch offen
			}
		}
	}
}

func isPeer(s *clusterSnap, id string) bool {
	_, ok := s.Peers[id]
	return ok
}

// closeHandover schliesst ein Problem "durch Uebergabe beendet".
func (m *Module) closeHandover(ctx context.Context, uid, hostUID, key string) {
	res, err := m.st.Writer().ExecContext(ctx, `UPDATE m64_problems SET closed_at = ?, closed_how = 'handover', closed_by = ?, updated_at = ? WHERE uid = ? AND closed_at = ''`,
		tsNow(), SystemActor.json(), tsNow(), uid)
	if err != nil {
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		m.event(ctx, uid, hostUID, key, "handover", i18nText("monitor64.detail.handover"), SystemActor, m.cl.clock())
	}
}

// ---------------------------------------------------------------------------------------------------------
// Ablauf

// clusterLoop sucht eigene Aenderungen und entscheidet regelmaessig ueber Zustaendigkeit, Probleme und Schluessel.
func (m *Module) clusterLoop(ctx context.Context) {
	scan := time.NewTicker(clusterScanEvery)
	defer scan.Stop()
	tick := time.NewTicker(clusterTick)
	defer tick.Stop()
	m.clusterScan(ctx)
	m.clusterRefresh(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-scan.C:
			m.clusterScan(ctx)
		case <-tick.C:
			if m.hooks().Change != nil {
				m.ClusterTick(ctx)
			}
		}
	}
}

// ClusterTick ist ein Blick auf den Cluster (auch fuer Tests): Mitglieder, Uebernahme/Rueckgabe, Probleme,
// Schluessel; danach eigene Aenderungen melden.
func (m *Module) ClusterTick(ctx context.Context) {
	s := m.clusterRefresh(ctx)
	m.clusterOwners(ctx, s)
	m.clusterProblems(ctx, s)
	m.clusterKeys(ctx, s)
	m.clusterRefreshIdle()
	m.clusterScan(ctx)
}

// ---------------------------------------------------------------------------------------------------------
// Ereignisse

// eventEntry ist ein Ereignis im Cluster (gehoert der Node, die es geschrieben hat).
type eventEntry struct {
	UID     string          `json:"uid"`
	Node    string          `json:"node"`
	Problem string          `json:"problem,omitempty"`
	Host    string          `json:"host"`
	Key     string          `json:"key,omitempty"`
	TS      string          `json:"ts"`
	Kind    string          `json:"kind"`
	Text    string          `json:"text,omitempty"`
	Actor   json.RawMessage `json:"actor,omitempty"`
}

func (m *Module) eventsWhere(ctx context.Context, where string, args ...any) []eventEntry {
	rows, err := m.st.Reader().QueryContext(ctx, `SELECT uid, node_id, problem_uid, host_uid, service_key, ts, kind, text, actor FROM m64_events WHERE `+where, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []eventEntry
	for rows.Next() {
		var e eventEntry
		var actor string
		if rows.Scan(&e.UID, &e.Node, &e.Problem, &e.Host, &e.Key, &e.TS, &e.Kind, &e.Text, &actor) == nil {
			e.Actor = json.RawMessage(actor)
			if !json.Valid(e.Actor) {
				e.Actor = json.RawMessage(`{}`)
			}
			out = append(out, e)
		}
	}
	return out
}

// insertEvent uebernimmt ein Ereignis (vorhandene Kennung: nichts). problem: erzwungene Zuordnung ("" = wie geliefert).
func (m *Module) insertEvent(ctx context.Context, e eventEntry, problem string) {
	if !reUID.MatchString(e.UID) || len(e.Text) > 4096 || len(e.Kind) > 32 || parseTS(e.TS).IsZero() {
		return
	}
	if problem != "" {
		e.Problem = problem
	}
	actor := string(e.Actor)
	if actor == "" || !json.Valid(e.Actor) {
		actor = "{}"
	}
	_, _ = m.st.Writer().ExecContext(ctx, `INSERT INTO m64_events (uid, node_id, problem_uid, host_uid, service_key, ts, kind, text, actor) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (uid) DO NOTHING`, e.UID, e.Node, e.Problem, e.Host, e.Key, e.TS, e.Kind, e.Text, actor)
}
