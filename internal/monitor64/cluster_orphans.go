package monitor64

import (
	"context"
	"net/http"
	"slices"
	"sort"
	"strings"
)

// Verwaiste Hosts: Hosts, die keine Node mehr ueberwachen kann, weil ihre Node nicht mehr zum Cluster gehoert - nach
// dem Austritt aus dem Cluster bzw. mit ausgeschaltetem Bereich die Hosts der anderen Nodes, im Cluster die Hosts,
// deren zustaendige Node und alle Kandidatinnen (bevorzugte, Ersatz-Nodes) keine Mitglieder mehr sind. Sie stehen als
// "Unbekannt" in der Uebersicht. Die Node tut von sich aus nichts (die andere Node ueberwacht sie womoeglich weiter):
// die Uebersicht zeigt eine Hinweis-Karte mit "dieser Node zuweisen" und "entfernen" (einzeln und alle).
//
// Eine Node, die nur nicht erreichbar ist (offline, ausgesetzt), macht ihre Hosts nicht zu verwaisten: sie kommt wieder
// bzw. eine Ersatz-Node uebernimmt.

const (
	orphanNodeGone    = "node_gone"    // ohne Cluster (allein, Bereich aus): der Host gehoert einer anderen Node
	orphanNoCandidate = "no_candidate" // im Cluster: zustaendige Node entfernt und keine Kandidatin ist Mitglied
)

// orphanOut ist ein verwaister Host (API und Hinweis-Karte der Uebersicht).
type orphanOut struct {
	UID      string `json:"uid"`
	Name     string `json:"name"`
	Address  string `json:"address,omitempty"`
	Reason   string `json:"reason"` // node_gone, no_candidate
	Node     string `json:"node"`   // bisher zustaendige Node
	NodeName string `json:"node_name"`
}

// orphanReason: Grund, aus dem keine Node den Host mehr ueberwacht ("" = nicht verwaist), und die bisher zustaendige
// Node.
func orphanReason(h *Host, s *clusterSnap) (reason, node string) {
	if !s.Active {
		if p := preferredOf(h, s.Self); p != s.Self {
			return orphanNodeGone, p
		}
		return "", ""
	}
	owner := ownerOf(h, s.Self)
	member := func(id string) bool { return id == s.Self || isPeer(s, id) }
	if member(owner) || slices.ContainsFunc(candidatesOf(h, s.Self), member) {
		return "", "" // zustaendige Node bzw. eine Kandidatin ist Mitglied (auch offline): Uebernahme-Regeln
	}
	return orphanNoCandidate, owner
}

// orphansOf: die verwaisten unter den Hosts, nach Name.
func orphansOf(hosts []*Host, s *clusterSnap) []orphanOut {
	out := []orphanOut{}
	for _, h := range hosts {
		if reason, node := orphanReason(h, s); reason != "" {
			out = append(out, orphanOut{UID: h.UID, Name: h.Name, Address: h.Address, Reason: reason, Node: node, NodeName: s.name(node)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// orphanViews: verwaiste Hosts aus dem Stand im Speicher (Uebersicht, ohne Datenbank).
func (m *Module) orphanViews(s *clusterSnap) []orphanOut {
	m.rtMu.Lock()
	hosts := make([]*Host, 0, len(m.rts))
	for _, rt := range m.rts {
		hosts = append(hosts, rt.host)
	}
	m.rtMu.Unlock()
	return orphansOf(hosts, s)
}

// apiClusterOrphans: GET verwaiste Hosts mit Grund (node_gone, no_candidate) und bisheriger Node.
func (m *Module) apiClusterOrphans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s := m.clusterRefresh(ctx)
	hosts, err := m.store.Hosts(ctx)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"active": s.Active, "self": s.Self, "orphans": orphansOf(hosts, s)})
}

type orphanIn struct {
	UIDs []string `json:"uids"`
	All  bool     `json:"all"`
}

// apiClusterOrphansAct: POST verwaiste Hosts dieser Node zuweisen (assign) bzw. entfernen (remove) - Body
// {"uids": [...]} oder {"all": true}. Wirkt nur auf Hosts, die gerade verwaist sind (frisch geprueft); andere
// Kennungen werden uebergangen. Antwort: Zahl der behandelten Hosts und die verbliebenen verwaisten.
func (m *Module) apiClusterOrphansAct(assign bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var in orphanIn
		if err := decode(r, &in); err != nil {
			m.fail(w, r, err)
			return
		}
		if !in.All && len(in.UIDs) == 0 {
			m.fail(w, r, errBad("json", "error", "uids or all required"))
			return
		}
		s := m.clusterRefresh(ctx)
		hosts, err := m.store.Hosts(ctx)
		if err != nil {
			m.fail(w, r, err)
			return
		}
		by := m.actor(r)
		done := 0
		for _, h := range hosts {
			reason, node := orphanReason(h, s)
			if reason == "" || !in.All && !slices.Contains(in.UIDs, h.UID) {
				continue
			}
			if assign {
				err = m.orphanAssign(ctx, h, node, s, by)
			} else {
				err = m.orphanRemove(ctx, h, by)
			}
			if err != nil {
				m.fail(w, r, err)
				return
			}
			done++
			if assign {
				m.audit(r, "host.cluster.assign", h.Name, "uid="+h.UID+" from="+node+" reason="+reason)
			} else {
				m.audit(r, "host.delete", h.Name, "uid="+h.UID+" orphan="+reason+" node="+node)
			}
		}
		left, err := m.store.Hosts(ctx)
		if err != nil {
			m.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"done": done, "orphans": orphansOf(left, s)})
	}
}

// orphanAssign: diese Node ueberwacht den Host ab jetzt (bevorzugt und zustaendig); Ersatz-Nodes, die keine Mitglieder
// mehr sind, entfallen. Steht als Uebernahme im Verlauf des Hosts (Akteur: wer es ausgeloest hat).
func (m *Module) orphanAssign(ctx context.Context, h *Host, prev string, s *clusterSnap, by Actor) error {
	h.PreferredNode = s.Self
	h.BackupNodes = slices.DeleteFunc(slices.Clone(h.BackupNodes), func(b string) bool { return b == s.Self || !isPeer(s, b) })
	if err := m.store.SaveHost(ctx, h, by); err != nil {
		return err
	}
	if _, err := m.st.Writer().ExecContext(ctx, `UPDATE m64_hosts SET owner_node = ? WHERE uid = ?`, s.Self, h.UID); err != nil {
		return err
	}
	m.event(ctx, "", h.UID, "", "takeover", i18nText("monitor64.detail.cluster_takeover", "from", s.name(prev), "to", s.name(s.Self)), by, m.cl.clock())
	m.log.Info("monitor64: orphaned host assigned to this node", "host", h.Name, "from", prev)
	m.clusterChange(ctx, ClusterItemConfig, "owner:"+h.UID, false)
	m.ReloadHost(ctx, h.UID)
	return nil
}

// orphanRemove entfernt den Host wie "Host entfernen" (Zugaenge, Dienste und Einstellungen mit; offene Probleme
// schliessen; Verlauf und Problem-Historie bleiben).
func (m *Module) orphanRemove(ctx context.Context, h *Host, by Actor) error {
	if err := m.store.DeleteHost(ctx, h.UID, by); err != nil {
		return err
	}
	m.ReloadHost(ctx, h.UID)
	if err := m.CloseHostProblems(ctx, h.UID, by); err != nil {
		m.log.Warn("monitor64: close problems of removed host", "host", h.Name, "err", err)
	}
	m.notifyMu.Lock()
	if m.notifier != nil {
		m.notifier.Forget(h.UID)
	}
	m.notifyMu.Unlock()
	return nil
}
