package healthchecks

import (
	"context"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/scheduler"
)

// Benachrichtigungen in der lokalen Gruppe (peer-Paket, Schritt 4): Messen mehrere Nodes der Gruppe einen
// Check und benachrichtigt nicht der hub, meldet genau eine Node – die erste erreichbare in der Liste der
// messenden Nodes (die Besitzer-Node, faellt sie aus, die naechste). Gemeldet wird der Gesamtzustand aus allen
// Messstellen wie beim hub. Den zuletzt gemeldeten Zustand (group_state) schreibt nur die meldende Node; die
// anderen uebernehmen ihn beim Abgleich, damit die naechste beim Uebernehmen weiss, was schon gemeldet ist, und
// nichts doppelt kommt (bestimmten auch die anderen ihn selbst, entginge der meldenden Node ein Wechsel).

// GroupRole sagt fuer die messenden Nodes eines Checks, ob die Gruppe benachrichtigt (nicht der hub), ob
// diese Node an der Reihe ist und ob sie den Stand der Gruppe schon kennt (nach dem Start erst abgleichen).
type GroupRole func(ctx context.Context, nodes []string) (group, me, ready bool)

// GroupState ist der zuletzt bestimmte Gesamtzustand der Gruppe fuer einen Check (Austausch zwischen den Nodes).
type GroupState struct {
	Token string    `json:"token"`
	State string    `json:"state"`
	Since time.Time `json:"since"`
	Open  bool      `json:"open,omitempty"` // Stoerung offen (seit down/flapping, bis up)
}

// SetGroupRole haengt die lokale Gruppe an (nil = keine Gruppe).
func (m *Module) SetGroupRole(f GroupRole) { m.groupRole = f }

// SetGroupDecides haengt die Regel an, wann die Gruppe den Gesamtzustand bewertet statt des hub.
func (m *Module) SetGroupDecides(f func(ctx context.Context, nodes []string) bool) {
	m.groupDecides = f
}

// SetGroupNotifier haengt die Anzeige an, wer in der lokalen Gruppe benachrichtigt (Detailseite).
func (m *Module) SetGroupNotifier(f func(ctx context.Context, nodes []string) (key, name string)) {
	m.groupNotifier = f
}

// SetGroupPeers haengt die Nodes der lokalen Gruppe an: sie stehen zur Auswahl der messenden Nodes und
// haben lesbare Namen, auch ohne hub.
func (m *Module) SetGroupPeers(f func(ctx context.Context) []Peer) { m.groupPeers = f }

// role: Rolle dieser Node fuer die Benachrichtigungen eines Checks (nur fuer Checks, die sie mitmisst).
func (m *Module) role(ctx context.Context, c *Check) (group, me, ready bool) {
	if m.groupRole == nil || len(c.Nodes) < 2 || !c.MeasuredHere() {
		return false, false, false
	}
	return m.groupRole(ctx, c.Nodes)
}

// PeerGroups liefert den Gesamtzustand der Gruppe fuer alle Checks, die diese Node mitmisst.
func (m *Module) PeerGroups(ctx context.Context) []GroupState {
	rows, err := m.st.r.QueryContext(ctx, `SELECT token, group_state, group_since, group_open FROM hc_checks WHERE group_state != ''`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []GroupState
	for rows.Next() {
		var g GroupState
		var since string
		if rows.Scan(&g.Token, &g.State, &since, &g.Open) == nil {
			g.Since = pt(since)
			out = append(out, g)
		}
	}
	return out
}

// ApplyPeerGroups uebernimmt den Gesamtzustand einer anderen Node, wenn er juenger ist (z. B. nach einem
// Ausfall dieser Node: was die andere inzwischen gemeldet hat, wird hier nicht noch einmal gemeldet).
func (m *Module) ApplyPeerGroups(ctx context.Context, list []GroupState) {
	for _, g := range list {
		if g.State == "" || g.Since.IsZero() {
			continue
		}
		_, _ = m.st.w.ExecContext(ctx, `UPDATE hc_checks SET group_state = ?, group_since = ?, group_open = ? WHERE token = ? AND (group_since = '' OR group_since < ?)`,
			g.State, ft(g.Since), g.Open, g.Token, ft(g.Since))
	}
}

// measuredLately: die letzte Messung einer Messstelle ist aktuell genug, um mitzuzaehlen (nach einem Neustart
// meldet eine Node sonst kurz ihren Zustand von vor dem Ausfall).
func measuredLately(c *Check, last time.Time) bool {
	limit := 3 * c.Interval
	if limit < peerFresh {
		limit = peerFresh
	}
	return !last.IsZero() && time.Since(last) <= limit
}

// notifiedBy: wer fuer einen Check benachrichtigt (Anzeige auf der Detailseite): Schluessel unter hc.notifier
// und Name der Node.
func (m *Module) notifiedBy(ctx context.Context, c *Check) (key, name string) {
	if c.Execution == "online" {
		return "hub", ""
	}
	if m.groupNotifier != nil && len(c.Nodes) > 0 {
		if key, name := m.groupNotifier(ctx, c.Nodes); key != "" { // Nodes der lokalen Gruppe messen mit
			return key, name
		}
	}
	if m.linked != nil && m.linked() {
		return "hub", ""
	}
	if c.MeasuredHere() && !c.Foreign() {
		return "self", ""
	}
	if names := m.nodeNames(ctx, c.Nodes); len(names) > 0 {
		return "owner", names[0]
	}
	return "none", ""
}

// groupState: zuletzt bestimmter Gesamtzustand der Gruppe fuer einen Check.
func (m *Module) groupState(ctx context.Context, token string) (scheduler.State, time.Time) {
	var st, since string
	_ = m.st.r.QueryRowContext(ctx, `SELECT group_state, group_since FROM hc_checks WHERE token = ?`, token).Scan(&st, &since)
	return scheduler.State(st), pt(since)
}

// groupVerdict bestimmt den Gesamtzustand aus der eigenen Messung und den Messstellen der Gruppe und meldet
// einen Wechsel, wenn diese Node an der Reihe ist.
func (m *Module) groupVerdict(ctx context.Context, c *Check) {
	group, me, ready := m.role(ctx, c)
	if !group || !ready {
		return // keine Gruppe bzw. Stand der Gruppe nach dem Start noch nicht abgeholt
	}
	type src struct {
		scheduler.SourceState
		last            time.Time
		reason, message string
	}
	rt := m.liveRuntime(c)
	srcs := []src{{SourceState: scheduler.SourceState{Source: "self", State: rt.State, LastStatus: rt.LastStatus, Fresh: true},
		last: rt.LastCheck, reason: string(rt.LastReason), message: rt.LastMessage}}
	rows, err := m.st.r.QueryContext(ctx, `SELECT source, state, last_status, last_check_at, reason, message, updated_at FROM hc_sources WHERE token = ?`, c.Token)
	if err != nil {
		return
	}
	self := "node:" + selfNodeID()
	for rows.Next() {
		var x src
		var state, status, last, upd string
		if rows.Scan(&x.Source, &state, &status, &last, &x.reason, &x.message, &upd) != nil || x.Source == self ||
			!strings.HasPrefix(x.Source, "node:") || !sourceBelongs(c, x.Source) {
			continue
		}
		x.State, x.LastStatus, x.last = scheduler.State(state), checks.Status(status), pt(last)
		x.Fresh = !pt(upd).IsZero() && time.Since(pt(upd)) <= peerFresh && measuredLately(c, x.last)
		srcs = append(srcs, x)
	}
	rows.Close()
	states := make([]scheduler.SourceState, len(srcs))
	for i := range srcs {
		states[i] = srcs[i].SourceState
	}
	overall := scheduler.Overall(c.Policy, states)
	if c.Paused {
		overall = scheduler.StatePaused
	}
	if !me {
		return // eine andere Node der Gruppe meldet (ihren Stand uebernimmt diese Node beim Abgleich)
	}
	if m.st.InMaintenance(ctx, c.Token, time.Now()) {
		// Wartung: gemeldeten Stand nicht fortschreiben, so meldet der naechste Abgleich nach dem Fenster,
		// was sich geaendert hat (Ausfall dauert an bzw. wieder erreichbar)
		return
	}
	old, oldSince := m.groupState(ctx, c.Token)
	if overall == old || overall == scheduler.StatePending {
		return // unveraendert bzw. noch keine Messung
	}
	var wasOpen bool
	_ = m.st.r.QueryRowContext(ctx, `SELECT group_open FROM hc_checks WHERE token = ?`, c.Token).Scan(&wasOpen)
	kind, open, send := groupKind(old, overall, wasOpen)
	now := time.Now().UTC()
	_, _ = m.st.w.ExecContext(ctx, `UPDATE hc_checks SET group_state = ?, group_since = ?, group_open = ? WHERE token = ?`, string(overall), ft(now), open, c.Token)
	if overall == scheduler.StateUp {
		m.mu.Lock()
		delete(m.reminders, c.Token)
		m.mu.Unlock()
	}
	m.log.Info("group state changed", "check", c.Name, "from", old, "to", overall)
	if m.dispatcher == nil {
		return
	}
	if !send {
		return // erster Zustand, aus Pause usw.: kein Anlass
	}
	// bestimmende Messstelle: bei Stoerung eine gestoerte, sonst die zuletzt gemessene
	bad := kind == notify.KindDown || kind == notify.KindFlappingStart || kind == notify.KindDegraded
	var lead *src
	for i := range srcs {
		x := &srcs[i]
		isDown := x.State == scheduler.StateDown || (x.State == scheduler.StateFlapping && x.LastStatus == checks.Down)
		if !x.Fresh || (bad && !isDown) {
			continue
		}
		if lead == nil || x.last.After(lead.last) {
			lead = x
		}
	}
	a := notify.Alert{EventID: scheduler.NewID(), Kind: kind, Time: now, Check: alertInfo(c)}
	a.Check.Local = true // die Gruppe meldet, nicht der hub
	a.Check.NotifyDegraded = c.NotifyDegraded
	if lead != nil {
		a.Reason, a.Message = lead.reason, lead.message
	}
	if !bad && !oldSince.IsZero() {
		a.Duration = now.Sub(oldSince)
	}
	m.dispatcher.Dispatch(a)
}

// groupKind leitet aus dem Wechsel des Gesamtzustands die Meldung ab, wie der hub (eventKind): "down" und
// "flapping" oeffnen eine Stoerung, "teilweise gestoert" und Pause halten sie offen, erst "up" beendet sie und
// wird dann als "wieder erreichbar" gemeldet (auch nach down -> teilweise gestoert -> up).
func groupKind(old, overall scheduler.State, wasOpen bool) (kind notify.Kind, open, ok bool) {
	open = wasOpen
	switch overall {
	case scheduler.StateDown, scheduler.StateFlapping:
		open = true
	case scheduler.StateDegraded, scheduler.StatePaused:
	default:
		open = false
	}
	switch {
	case overall == scheduler.StateDown:
		return notify.KindDown, open, true
	case overall == scheduler.StateFlapping:
		return notify.KindFlappingStart, open, true
	case overall == scheduler.StateDegraded:
		return notify.KindDegraded, open, true
	case overall == scheduler.StateUp && old == scheduler.StateFlapping:
		return notify.KindFlappingEnd, open, true
	case overall == scheduler.StateUp && (old == scheduler.StateDown || wasOpen):
		return notify.KindUp, open, true
	case overall == scheduler.StateUp && old == scheduler.StateDegraded:
		return notify.KindDegradedEnd, open, true
	}
	return "", open, false
}
