package monitor64

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/eval"
)

// Zustand der Hosts im Cluster (Bereich status, Eintraege "state:<host>:<node>", gehoeren je einer Node): jede Node
// schickt bei jeder Aenderung des Zustands, sonst hoechstens alle saveEvery, ihre Ansicht samt Laufzeitstand und
// Gedaechtnis der Meldungen. Daraus zeigen die anderen Nodes die Gesamtuebersicht ("ueberwacht von node01"), und eine
// Node, die einen Host uebernimmt, macht mit dem Stand der vorigen weiter (meldet nichts doppelt).

// stateEntry ist der Zustand eines Hosts auf einer Node.
type stateEntry struct {
	Node      string          `json:"node"`
	At        time.Time       `json:"at"`
	Reporting bool            `json:"reporting"` // die Node hat gemeldet (zustaendig mit Mehrheit)
	View      *HostView       `json:"view,omitempty"`
	RT        json.RawMessage `json:"rt,omitempty"`
	Mem       json.RawMessage `json:"mem,omitempty"`
}

// ClusterRef sagt, welche Node einen Host ueberwacht (Ansicht der Oberflaeche).
type ClusterRef struct {
	Node      string    `json:"node"`
	Name      string    `json:"name,omitempty"`
	Here      bool      `json:"here"`      // diese Node fragt ab
	Reporting bool      `json:"reporting"` // die ueberwachende Node meldet
	Reachable bool      `json:"reachable"` // die zustaendige Node ist erreichbar
	Note      string    `json:"note,omitempty"`
	At        time.Time `json:"at,omitzero"` // Stand der anderen Node
}

// Hinweise der Ansicht (Texte in der Oberflaeche: monitor64.cluster.note.<code>).
const (
	noteOwnerUnreachable = "owner_unreachable" // zustaendige Node nicht erreichbar (Unbekannt, keine Meldung)
	noteNoData           = "no_data"           // noch kein Zustand der zustaendigen Node
	noteMeasureOnly      = "measure_only"      // ohne Mehrheit: misst, meldet nicht
)

// clusterSelfRef: Hinweis fuer Hosts, die diese Node selbst abfragt (nil ohne Cluster).
func (m *Module) clusterSelfRef(role int) *ClusterRef {
	s := m.clusterSnapshot()
	if !s.Active {
		return nil
	}
	r := &ClusterRef{Node: s.Self, Here: true, Reporting: role == roleReport, Reachable: true}
	if role == roleMeasure {
		r.Note = noteMeasureOnly
	}
	return r
}

// publishState schickt den Zustand eines Hosts an den Cluster (aus saveRuntime; blob = gespeicherter Laufzeitstand).
// final: letzter Stand beim Abgeben (Rolle schon "andere Node zustaendig"), gilt als gemeldet.
func (m *Module) publishState(ctx context.Context, rt *hostRT, blob []byte, final bool) {
	s := m.clusterSnapshot()
	if !s.Active || m.hooks().Change == nil {
		return
	}
	m.cl.mu.Lock()
	role, ok := m.cl.roles[rt.host.UID]
	m.cl.mu.Unlock()
	if final {
		role, ok = roleReport, true
	}
	if !ok || role == roleIdle {
		return
	}
	var saved struct {
		RT  json.RawMessage `json:"rt"`
		Mem json.RawMessage `json:"mem"`
	}
	_ = json.Unmarshal(blob, &saved)
	e := stateEntry{Node: s.Self, At: time.Now().UTC().Truncate(time.Millisecond), Reporting: role == roleReport, RT: saved.RT, Mem: m.memToCluster(ctx, saved.Mem)}
	if v := rt.getView(); v != nil {
		cp := *v
		cp.Host, cp.Cluster = nil, nil
		e.View = &cp
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	if _, err := m.st.Writer().ExecContext(ctx, `INSERT INTO m64_cstate (host_uid, node_id, data, at) VALUES (?, ?, ?, ?)
		ON CONFLICT (host_uid, node_id) DO UPDATE SET data = excluded.data, at = excluded.at`, rt.host.UID, s.Self, string(b), ts(e.At)); err != nil {
		m.log.Warn("monitor64: cluster state", "err", err)
		return
	}
	m.cacheState(rt.host.UID, &e)
	m.clusterChange(ctx, ClusterItemStatus, "state:"+rt.host.UID+":"+s.Self, false)
}

func splitStateID(id string) (host, node string, ok bool) {
	host, node, ok = strings.Cut(id, ":")
	return host, node, ok && reUID.MatchString(host) && reNodeID.MatchString(node)
}

func (m *Module) stateGet(ctx context.Context, id string) (json.RawMessage, bool, error) {
	host, node, ok := splitStateID(id)
	if !ok {
		return nil, false, errClItem
	}
	var data string
	err := m.st.Reader().QueryRowContext(ctx, `SELECT data FROM m64_cstate WHERE host_uid = ? AND node_id = ?`, host, node).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return json.RawMessage(data), true, nil
}

func (m *Module) stateApply(ctx context.Context, id string, data json.RawMessage, deleted bool) error {
	host, node, ok := splitStateID(id)
	if !ok {
		return errClItem
	}
	if node == m.clusterSelf() {
		return nil // eigener Zustand kommt nicht von anderen
	}
	if deleted {
		_, err := m.st.Writer().ExecContext(ctx, `DELETE FROM m64_cstate WHERE host_uid = ? AND node_id = ?`, host, node)
		m.cacheState(host, &stateEntry{Node: node})
		return err
	}
	var e stateEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return err
	}
	if e.Node != node {
		return errClItem
	}
	if _, err := m.st.Writer().ExecContext(ctx, `INSERT INTO m64_cstate (host_uid, node_id, data, at) VALUES (?, ?, ?, ?)
		ON CONFLICT (host_uid, node_id) DO UPDATE SET data = excluded.data, at = excluded.at`, host, node, string(data), ts(e.At)); err != nil {
		return err
	}
	e.RT, e.Mem = nil, nil // im Speicher nur die Ansicht
	m.cacheState(host, &e)
	m.refreshIdle(host)
	return nil
}

// cacheState merkt die Ansicht einer Node fuer einen Host (Node ohne View = entfernen).
func (m *Module) cacheState(host string, e *stateEntry) {
	m.cl.mu.Lock()
	defer m.cl.mu.Unlock()
	if m.cl.views == nil {
		m.cl.views = map[string]map[string]*stateEntry{}
	}
	if e.View == nil && e.At.IsZero() {
		delete(m.cl.views[host], e.Node)
		return
	}
	if m.cl.views[host] == nil {
		m.cl.views[host] = map[string]*stateEntry{}
	}
	cp := *e
	cp.RT, cp.Mem = nil, nil
	m.cl.views[host][e.Node] = &cp
}

// remoteState liefert die zuletzt bekannte Ansicht einer Node (laedt beim ersten Mal aus m64_cstate).
func (m *Module) remoteState(host, node string) *stateEntry {
	m.cl.mu.Lock()
	init := m.cl.viewsInit
	m.cl.viewsInit = true
	m.cl.mu.Unlock()
	if !init {
		if rows, err := m.st.Reader().Query(`SELECT host_uid, data FROM m64_cstate`); err == nil {
			var list []struct {
				h string
				e stateEntry
			}
			for rows.Next() {
				var h, data string
				var e stateEntry
				if rows.Scan(&h, &data) == nil && json.Unmarshal([]byte(data), &e) == nil {
					list = append(list, struct {
						h string
						e stateEntry
					}{h, e})
				}
			}
			rows.Close()
			for i := range list {
				m.cacheState(list[i].h, &list[i].e)
			}
		}
	}
	m.cl.mu.Lock()
	defer m.cl.mu.Unlock()
	return m.cl.views[host][node]
}

// setRole merkt die Rolle der Runde; liefert die vorige (ok=false: erste Runde seit dem Laden).
func (m *Module) setRole(uid string, role int) (int, bool) {
	m.cl.mu.Lock()
	defer m.cl.mu.Unlock()
	if m.cl.roles == nil {
		m.cl.roles = map[string]int{}
	}
	prev, ok := m.cl.roles[uid]
	m.cl.roles[uid] = role
	return prev, ok
}

// stateMaxAge: so alt darf der Zustand einer anderen Node hoechstens sein, um ihn anzuzeigen bzw. damit weiterzumachen.
// Die meldende Node schickt ihn bei jeder Aenderung, sonst hoechstens alle saveEvery bzw. je Runde (langes Intervall).
// Aelter (Bereich status aus, Node weg, Abgleich haengt): nicht mehr verwenden.
func stateMaxAge(h *Host) time.Duration {
	return 3 * max(saveEvery, time.Duration(h.IntervalSec)*time.Second)
}

// idleView setzt die Ansicht eines Hosts, den eine andere Node ueberwacht (aus deren abgeglichenem Zustand; zu alt =
// noch kein Zustand, Unbekannt).
func (m *Module) idleView(rt *hostRT, owner string) {
	s := m.clusterSnapshot()
	ref := &ClusterRef{Node: owner, Name: s.name(owner), Reachable: s.online(owner)}
	v := &HostView{Host: rt.host, View: eval.ViewUnknown, State: eval.Unknown, Accesses: []AccessView{}, Services: []SvcView{}}
	if e := m.remoteState(rt.host.UID, owner); e != nil && e.View != nil && time.Since(e.At) <= stateMaxAge(rt.host) {
		cp := *e.View
		v = &cp
		v.Host = rt.host
		ref.Reporting, ref.At = e.Reporting, e.At
	} else {
		ref.Note = noteNoData
	}
	if !ref.Reachable {
		v.View, v.State, ref.Note = eval.ViewUnknown, eval.Unknown, noteOwnerUnreachable // nicht melden
	}
	v.Cluster = ref
	rt.setView(v)
}

// refreshIdle aktualisiert die Ansicht eines fremd ueberwachten Hosts sofort (neuer Zustand angekommen).
func (m *Module) refreshIdle(host string) {
	m.rtMu.Lock()
	rt := m.rts[host]
	m.rtMu.Unlock()
	if rt == nil {
		return
	}
	if role, owner := m.roleOf(rt.host); role == roleIdle {
		m.idleView(rt, owner)
	}
}

// clusterRefreshIdle: alle fremd ueberwachten Hosts (Erreichbarkeit der Nodes kann sich geaendert haben).
func (m *Module) clusterRefreshIdle() {
	m.rtMu.Lock()
	uids := make([]string, 0, len(m.rts))
	for uid := range m.rts {
		uids = append(uids, uid)
	}
	m.rtMu.Unlock()
	for _, uid := range uids {
		m.refreshIdle(uid)
	}
}

// adoptState: diese Node meldet den Host jetzt (wieder). Hat eine andere Node juenger gemeldet, macht diese Node mit
// deren Gedaechtnis der Meldungen weiter (nichts doppelt melden) und, wenn deren Stand juenger ist als der eigene, mit
// deren Laufzeitstand (Tracker: Dauer und Zustand laufen weiter; offene SNMP-Traps bleiben offen). Ein zu alter Stand
// (stateMaxAge) gilt nicht mehr:
// sonst meldete diese Node laengst Erledigtes erneut bzw. entwarnte dafuer. rt.mu gehalten.
func (m *Module) adoptState(ctx context.Context, rt *hostRT) {
	self := m.clusterSelf()
	var own *stateEntry
	var best *stateEntry
	rows, err := m.st.Reader().QueryContext(ctx, `SELECT node_id, data FROM m64_cstate WHERE host_uid = ?`, rt.host.UID)
	if err != nil {
		return
	}
	for rows.Next() {
		var node, data string
		var e stateEntry
		if rows.Scan(&node, &data) != nil || json.Unmarshal([]byte(data), &e) != nil || e.Node != node {
			continue
		}
		switch {
		case node == self:
			cp := e
			own = &cp
		case e.Reporting && (best == nil || e.At.After(best.At)):
			cp := e
			best = &cp
		}
	}
	rows.Close()
	if best == nil || own != nil && own.Reporting && !own.At.Before(best.At) {
		return
	}
	if age := time.Since(best.At); age > stateMaxAge(rt.host) {
		m.log.Info("monitor64: state of another node too old, starting fresh", "host", rt.host.Name, "node", best.Node, "age", age.Round(time.Second))
		return
	}
	if len(best.Mem) > 0 && string(best.Mem) != "null" {
		var mem eval.HostMemory
		if json.Unmarshal(best.Mem, &mem) == nil {
			m.memFromCluster(ctx, &mem)
			m.notifyMu.Lock()
			if m.notifier != nil {
				m.notifier.Hosts[rt.host.UID] = &mem
			}
			m.notifyMu.Unlock()
		}
	}
	if (own == nil || best.At.After(own.At)) && len(best.RT) > 0 {
		var tmp hostRT
		if json.Unmarshal(best.RT, &tmp) == nil {
			tmp.initMaps()
			rt.Trackers, rt.Kinds, rt.Failures, rt.Missing, rt.Provider = tmp.Trackers, tmp.Kinds, tmp.Failures, tmp.Missing, tmp.Provider
			rt.Rising, rt.Local, rt.Trend = tmp.Rising, tmp.Local, tmp.Trend
			if m.traps != nil && trapAccess(rt) != "" { // offene Traps der bisher zustaendigen Node weiterfuehren (traps_cluster.go)
				m.traps.adopt(rt.host.UID, tmp.Traps, best.At)
			}
		}
	}
	rt.dirty = true
	m.log.Info("monitor64: continuing with the state of another node", "host", rt.host.Name, "node", best.Node)
}

// clusterRole bestimmt die Rolle einer Runde und erledigt den Wechsel (rt.mu gehalten). Kurz nach dem Start
// (clusterStartWait) misst die Node im Cluster nur: erst den Stand der anderen abholen, sonst meldet sie nach einem
// Neustart doppelt, was die andere Node schon gemeldet hat.
func (m *Module) clusterRole(ctx context.Context, rt *hostRT) (int, string) {
	role, owner := m.roleOf(rt.host)
	active := m.clusterSnapshot().Active
	if role == roleReport && active && m.clusterStarting() {
		role = roleMeasure
	}
	prev, had := m.setRole(rt.host.UID, role)
	if !had || prev != role {
		rt.dirty = true // Rolle neu: Zustand gleich speichern und an den Cluster melden
	}
	if role == roleIdle && had && prev == roleReport {
		if m.traps != nil && rt.Traps != nil { // Traps seit der letzten Runde gehen mit
			if snap := m.traps.snapshot(rt.host.UID, false); snap != nil {
				rt.Traps = snap
			}
		}
		m.publishFinal(ctx, rt) // abgeben: letzten Stand (Gedaechtnis der Meldungen, offene Traps) der neuen Node mitgeben
	}
	if role == roleIdle && (!had || prev != roleIdle) && m.traps != nil && m.traps.handedOver(rt.host.UID) {
		// offene Traps fuehrt die zustaendige Node (auch ein nach dem Start wiederhergestellter Stand gilt nicht mehr)
		rt.Traps, rt.dirty = m.traps.snapshot(rt.host.UID, false), true
	}
	if role == roleReport && (!had || prev != roleReport) && active {
		m.adoptState(ctx, rt)
	}
	return role, owner
}

// clusterStarting: seit dem Start des Moduls ist clusterStartWait noch nicht vergangen.
func (m *Module) clusterStarting() bool {
	m.cl.mu.Lock()
	started := m.cl.started
	m.cl.mu.Unlock()
	return !started.IsZero() && m.cl.clock().Sub(started) < clusterStartWait
}

// publishFinal speichert und veroeffentlicht den letzten eigenen Stand beim Abgeben (rt.mu gehalten).
func (m *Module) publishFinal(ctx context.Context, rt *hostRT) {
	m.notifyMu.Lock()
	var mem []byte
	if m.notifier != nil {
		mem, _ = json.Marshal(m.notifier.Hosts[rt.host.UID])
	}
	m.notifyMu.Unlock()
	rt.dirty = true
	m.saveRuntimeAs(ctx, rt, mem, true)
}

// Kanaele im Gedaechtnis der Meldungen: lokal ihre Nummer (je Node verschieden), im Cluster ihre Kennung wie bei
// "gemeldet an" ("uid:<kennung>", "default" bleibt). Unbekannte Kanaele entfallen.

func (m *Module) memToCluster(ctx context.Context, raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return raw
	}
	var mem eval.HostMemory
	if json.Unmarshal(raw, &mem) != nil {
		return nil
	}
	byID, _ := m.channelUIDs(ctx)
	mapMemChans(&mem, func(id string) (string, bool) {
		u, ok := byID[id]
		return "uid:" + u, ok
	})
	b, err := json.Marshal(mem)
	if err != nil {
		return nil
	}
	return b
}

func (m *Module) memFromCluster(ctx context.Context, mem *eval.HostMemory) {
	_, byUID := m.channelUIDs(ctx)
	mapMemChans(mem, func(id string) (string, bool) {
		u, ok := strings.CutPrefix(id, "uid:")
		if !ok {
			return "", false
		}
		n, ok := byUID[u]
		return n, ok
	})
}

func mapMemChans(mem *eval.HostMemory, f func(string) (string, bool)) {
	conv := func(in []string) []string {
		var out []string
		for _, id := range in {
			if id == defaultChannels {
				out = append(out, id)
			} else if to, ok := f(id); ok {
				out = append(out, to)
			}
		}
		return out
	}
	mem.HostChans = conv(mem.HostChans)
	for _, s := range mem.Svcs {
		if s != nil {
			s.Chans = conv(s.Chans)
		}
	}
}
