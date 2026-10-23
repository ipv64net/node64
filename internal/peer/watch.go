package peer

import (
	"context"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/notify"
)

// Meldung, wenn ein Mitglied laenger nicht erreichbar oder ausgesetzt ist, und Entwarnung, wenn es wieder da ist.
// Gemeldet wird von genau einer Node: der mit der kleinsten Kennung unter den erreichbaren (diese eingeschlossen).
// Die Entwarnung schickt die Node, die gemeldet hat. Im Split-Brain meldet jede Seite fuer sich.

// memberGrace: so lange darf ein Mitglied weg sein, bevor gemeldet wird (Neustarts, Updates, kurze Netzaussetzer).
const memberGrace = 5 * time.Minute

// MemberDown: Mitglied laenger als memberGrace nicht erreichbar oder ausgesetzt (auch fuer das Dashboard).
func (x Member) MemberDown(now time.Time) bool {
	if x.Online() {
		return false
	}
	since := x.LastSeen
	if since.IsZero() {
		since = x.AddedAt
	}
	return x.Suspended() || now.Sub(since) >= memberGrace
}

// watchMembers prueft nach jedem Ping die Mitglieder und meldet Ausfall bzw. Rueckkehr.
func (m *Manager) watchMembers(ctx context.Context) {
	if m.d.Notify == nil {
		return
	}
	list, err := m.Members(ctx)
	if err != nil {
		return
	}
	self, now := m.d.NodeID(), time.Now()
	reporter := true
	for _, x := range list {
		if x.Online() && x.NodeID < self {
			reporter = false
		}
	}
	type alert struct {
		kind notify.Kind
		x    Member
	}
	var out []alert
	m.mu.Lock()
	if m.watch == nil {
		m.watch = map[string]bool{}
	}
	known := map[string]bool{}
	for _, x := range list {
		known[x.NodeID] = true
		down, sent := x.MemberDown(now), m.watch[x.NodeID]
		switch {
		case down && !sent && reporter:
			m.watch[x.NodeID] = true
			out = append(out, alert{notify.KindClusterDown, x})
		case !down && sent:
			delete(m.watch, x.NodeID)
			out = append(out, alert{notify.KindClusterUp, x})
		}
	}
	for id := range m.watch {
		if !known[id] { // aus dem Cluster genommen: keine Entwarnung mehr
			delete(m.watch, id)
		}
	}
	m.mu.Unlock()
	for _, a := range out {
		reason := ""
		var data map[string]string
		if a.kind == notify.KindClusterDown {
			if a.x.Suspended() {
				data = map[string]string{"text": "notify.text.cluster_suspended", "reason": a.x.Reason} // Text in der Sprache des Kanals
			} else {
				reason = a.x.LastError
			}
		}
		m.d.Log.Info("notification", "kind", a.kind, "node", a.x.Name, "reason", reason, "suspended", data != nil)
		m.d.Notify(notify.Alert{EventID: "cluster-" + string(a.kind) + "-" + a.x.NodeID + "-" + strconv.FormatInt(now.UnixNano(), 36), Kind: a.kind, Time: now.UTC(),
			Check: notify.CheckInfo{Name: a.x.Name, NotifyDown: true, NotifyUp: true, Local: true}, Reason: reason, Data: data})
	}
}
