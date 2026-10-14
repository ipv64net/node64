package peer

import "context"

// Benachrichtigungen (Schritt 4): Messen mehrere Nodes der Gruppe einen Check, meldet die erste erreichbare
// Node in der Liste der messenden Nodes (Besitzer-Node, bei Ausfall die naechste). Der hub meldet weiter selbst,
// wenn diese Node mit ihm verbunden ist, er bestaetigt und alle messenden Nodes kennt.

// NotifyRole: group = die Gruppe benachrichtigt (nicht der hub), me = diese Node ist an der Reihe,
// ready = der Stand der Gruppe ist nach dem Start abgeholt.
func (m *Manager) NotifyRole(ctx context.Context, nodes []string) (group, me, ready bool) {
	list, err := m.Members(ctx)
	if err != nil || len(list) == 0 {
		return false, false, false
	}
	byID := map[string]Member{}
	for _, x := range list {
		byID[x.NodeID] = x
	}
	inGroup := false
	for _, id := range nodes {
		if _, ok := byID[id]; ok {
			inGroup = true
		}
	}
	if !inGroup {
		return false, false, false // keine andere Node der Gruppe misst mit
	}
	if m.linkedSelf() && m.d.HubNotifies != nil && m.d.HubNotifies() && m.hubKnows(ctx, nodes) {
		return false, false, false // der hub bewertet und meldet
	}
	ready = m.ready.Load() // nach dem Start erst den Stand der Gruppe holen (sonst kaeme eine Meldung doppelt)
	self := m.d.NodeID()
	for _, id := range nodes {
		if id == self {
			return true, true, ready
		}
		if x, ok := byID[id]; ok && x.Online() {
			return true, false, ready
		}
	}
	return true, false, ready
}
