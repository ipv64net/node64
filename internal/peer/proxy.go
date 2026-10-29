package peer

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/wire"
)

// Stellvertreter-Nodes: Die weiterreichende Node meldet die nicht verknuepften Mitglieder der Gruppe beim hub an
// und reicht ihre Zustaende und Messpunkte weiter. So erscheinen deren Checks mit Messwerten im Portal. Der hub
// zeigt sie nur an; benachrichtigt wird weiter in der Gruppe (hubDecides).

// Hub ist die Anbindung an den Healthchecks-Sync fuer Stellvertreter-Nodes.
type Hub interface {
	ProxyReady() bool
	RegisterProxies(ctx context.Context, items []wire.ProxyNode) (map[string]int64, error)
	ProxyData(ctx context.Context, node string, states []wire.State, batch []wire.Measurement) (int64, error)
}

const (
	proxyPages = 10  // Seiten je Mitglied und Runde (der Rest folgt in der naechsten)
	proxyBatch = 500 // Messpunkte je Nachricht an den hub
)

// pushProxies laeuft nach jedem Abgleich auf der weiterreichenden Node.
func (m *Manager) pushProxies(ctx context.Context, list []Member) {
	h := m.d.Hub
	if h == nil || m.data() == nil || !m.forwarder(ctx) || !h.ProxyReady() {
		return
	}
	acc := m.d.AccountID()
	items := []wire.ProxyNode{}
	byID := map[string]Member{}
	for _, x := range list {
		// streng: nur Mitglieder desselben Accounts; eine Node ohne Account im Cluster wird nicht beim hub angemeldet
		if x.Linked || acc <= 0 || x.AccountID != acc {
			continue
		}
		items = append(items, wire.ProxyNode{ID: x.NodeID, Name: x.Name, Version: x.Version, Online: x.Online()})
		byID[x.NodeID] = x
	}
	acks, err := h.RegisterProxies(ctx, items)
	if err != nil {
		m.d.Log.Debug("proxy nodes not registered", "err", err)
		return
	}
	for id, ack := range acks {
		x, ok := byID[id]
		if !ok || !x.Online() {
			continue
		}
		if err := m.proxyData(ctx, h, x, ack); err != nil {
			m.d.Log.Debug("proxy data", "node", x.Name, "err", err)
		}
	}
	m.forwardHeld(ctx, acks)
}

// proxyData reicht Zustaende und neue Messpunkte eines Mitglieds an den hub weiter. Der Stand liegt hier
// (pcursor); ohne ihn (erste Runde dieser Node als weiterreichende) gilt der Stand des hubs.
func (m *Manager) proxyData(ctx context.Context, h Hub, x Member, hubAck int64) error {
	var cursor int64
	_ = m.db.QueryRowContext(ctx, `SELECT pcursor FROM peer_members WHERE node_id = ?`, x.NodeID).Scan(&cursor)
	if cursor == 0 {
		cursor = hubAck
	}
	if cursor == 0 {
		cursor = startFresh
	}
	sent := 0
	for page := 0; page < proxyPages; page++ {
		q := "/peer/v1/measurements?since=" + strconv.FormatInt(cursor, 10)
		if page == 0 {
			q += "&states=1"
		}
		var out measOut
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := m.call(cctx, x, http.MethodGet, q, nil, &out)
		cancel()
		if err != nil {
			return err
		}
		if cursor > 0 && out.Head < cursor { // Datenbank des Mitglieds neu: ab den letzten 24 h
			cursor = startFresh
			continue
		}
		states, items := out.States, out.Items
		for first := true; first || len(items) > 0; first = false {
			n := min(len(items), proxyBatch)
			if len(states) == 0 && n == 0 {
				break
			}
			if _, err := h.ProxyData(ctx, x.NodeID, states, items[:n]); err != nil {
				return err
			}
			states, items = nil, items[n:]
		}
		sent += len(out.Items)
		if out.Last > 0 && out.Last != cursor {
			cursor = out.Last
			_, _ = m.db.ExecContext(ctx, `UPDATE peer_members SET pcursor = ? WHERE node_id = ?`, cursor, x.NodeID)
		}
		if !out.More {
			break
		}
	}
	if sent > 0 {
		m.d.Log.Debug("measurements of group member to hub", "node", x.Name, "points", sent)
	}
	return nil
}

// forwardHeld reicht Checks mit einem Mitglied unter den messenden Nodes an den hub weiter – einmal je Mitglied, sobald
// der hub es als Stellvertreter-Node fuehrt (und erneut, wenn es nach einer Pause wieder Stellvertreter wird). Neue Checks und Aenderungen (z. B. das Mitglied als
// weitere messende Node) blieben bis dahin in der Gruppe, weil der hub das Mitglied nicht kannte.
func (m *Manager) forwardHeld(ctx context.Context, acks map[string]int64) {
	hc := m.checks()
	if hc == nil || m.d.Forward == nil {
		return
	}
	known := m.hubNodes(ctx)
	m.mu.Lock()
	if m.proxied == nil {
		m.proxied = map[string]bool{}
	}
	for id := range m.proxied { // nicht mehr Stellvertreter (Mitglied weg, vom hub widerrufen): beim Wiederkommen erneut
		if _, ok := acks[id]; !ok || !known[id] {
			delete(m.proxied, id)
		}
	}
	fresh := map[string]bool{}
	for id := range acks {
		if known[id] && !m.proxied[id] {
			fresh[id], m.proxied[id] = true, true
		}
	}
	m.mu.Unlock()
	if len(fresh) == 0 {
		return
	}
	n := 0
	for _, t := range hc.PeerTokens(ctx) {
		w, _, _, err := hc.PeerCheck(ctx, t, m.d.NodeID())
		if err != nil || w == nil || w.Execution == "online" || !m.hubKnows(ctx, w.Nodes) {
			continue
		}
		for _, id := range w.Nodes {
			if fresh[id] {
				m.d.Forward(ctx, "check", t, "upsert")
				n++
				break
			}
		}
	}
	if n > 0 {
		m.d.Log.Info("checks of group members forwarded to hub", "checks", n)
	}
}

// hubNodes: die Nodes, die der hub fuer den Account fuehrt (verknuepfte und Stellvertreter-Nodes).
func (m *Manager) hubNodes(ctx context.Context) map[string]bool {
	var list []struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(m.d.Core.SettingOr(ctx, healthchecks.SettingPeers, "[]")), &list)
	out := make(map[string]bool, len(list))
	for _, p := range list {
		out[p.ID] = true
	}
	return out
}
