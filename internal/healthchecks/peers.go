package healthchecks

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"sync"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/store"
)

// Mehrere Nodes je Account: ein Check kann von mehreren Nodes gemessen werden (Liste Nodes).
// Besitzer bleibt die Node, die ihn angelegt hat (bearbeiten, Benachrichtigung ohne hub).
// Docker-Checks gehoeren zu genau einer Node; Push-Checks koennen ueberall ausgeloest werden.

// Peer ist eine Node des Accounts (vom hub, /v1/nodes/me).
type Peer struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`
	Online   bool   `json:"online"`
	Self     bool   `json:"-"`
	Cluster  string `json:"-"` // Bereiche, ueber die die Node Docker- bzw. Proxmox-Checks mitmessen kann ("proxmox docker")
}

// SettingPeers haelt die Nodes des Accounts (JSON, vom Sync-Client geschrieben).
const SettingPeers = "sync.account_nodes"

var nodeIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,40}$`)

// self merkt sich die eigene Node-Kennung (node.id); leer, solange keine erzeugt wurde.
var self struct {
	sync.Mutex
	core *store.Store
	id   string
}

func setSelfStore(core *store.Store) {
	self.Lock()
	self.core = core
	self.Unlock()
}

// selfNodeID liefert die eigene Kennung (aus den Einstellungen, einmal gelesen).
func selfNodeID() string {
	self.Lock()
	defer self.Unlock()
	if self.id == "" && self.core != nil {
		self.id = self.core.SettingOr(context.Background(), "node.id", "")
	}
	return self.id
}

// singleNode: Docker-Checks gehoeren zur Node mit dem Container, Proxmox-Checks zur Node, die das System abfragt
// (Push-Checks sind frei zuordenbar). Im Cluster mit den Bereichen Proxmox VE bzw. Docker (Host ueber das Netz)
// messen die Nodes mit, die den Bereich abgleichen (clusterNodesOf).
func singleNode(t checks.Type) bool { return t == checks.TypeDocker || t == checks.TypeProxmox }

// measures sagt, ob diese Node den Check misst (ohne Ausfuehrungsort).
// Where beschreibt fuer die Anzeige, wo ein Check gemessen wird (nicht, wem er gehoert):
// Online (nur ipv64), Hybrid (Nodes und ipv64), Lokal (diese Node misst mit), Andere Node.
type Where struct{ Key, Icon, Hint string }

func (c *Check) Where() Where {
	switch {
	case c.Execution == "online" || c.Owner == "online":
		return Where{"hc.where.online", "bi-cloud", "hc.where.online_hint"}
	case c.Execution == "both" && c.measures():
		return Where{"hc.where.hybrid", "bi-cloud-plus", "hc.where.hybrid_here"}
	case c.Execution == "both":
		return Where{"hc.where.hybrid", "bi-cloud-plus", "hc.where.hybrid_other"}
	case c.measures():
		return Where{"hc.where.local", "bi-house", "hc.where.local_here"}
	}
	return Where{"hc.where.other", "bi-hdd-network", "hc.where.other_hint"}
}

// MeasuresHere: diese Node misst den Check (auch wenn eine andere Node Besitzerin ist).
func (c *Check) MeasuresHere() bool { return c.Execution != "online" && c.measures() }

func (c *Check) measures() bool {
	if len(c.Nodes) > 0 {
		if id := selfNodeID(); id != "" {
			for _, n := range c.Nodes {
				if n == id {
					return true
				}
			}
			return false
		}
	}
	return c.Owner == "" || c.Owner == "self"
}

// peers liefert die Nodes des Accounts; die eigene ist markiert und steht vorn.
func (m *Module) peers(ctx context.Context) []Peer {
	var list []Peer
	_ = json.Unmarshal([]byte(m.core.SettingOr(ctx, SettingPeers, "[]")), &list)
	me := selfNodeID()
	out := make([]Peer, 0, len(list)+1)
	found := false
	for _, p := range list {
		if p.ID == me {
			p.Self, found = true, true
			out = append([]Peer{p}, out...)
			continue
		}
		out = append(out, p)
	}
	if !found && me != "" {
		out = append([]Peer{{ID: me, Name: m.core.SettingOr(ctx, "sync.node_name", "Node"), Online: true, Self: true}}, out...)
	}
	if m.groupPeers != nil { // Nodes der lokalen Gruppe (auch ohne hub)
		at := map[string]int{}
		for i, p := range out {
			at[p.ID] = i
		}
		for _, g := range m.groupPeers(ctx) {
			if i, ok := at[g.ID]; ok {
				out[i].Online = out[i].Online || g.Online
				continue
			}
			out = append(out, g)
		}
	}
	return out
}

// nodeNames liefert lesbare Namen der messenden Nodes.
func (m *Module) nodeNames(ctx context.Context, ids []string) []string {
	names := map[string]string{}
	for _, p := range m.peers(ctx) {
		names[p.ID] = p.Name
	}
	var out []string
	for _, id := range ids {
		if n := names[id]; n != "" {
			out = append(out, n)
		} else {
			out = append(out, "Node "+id[:min(8, len(id))])
		}
	}
	return out
}

// cleanNodes prueft und entdoppelt eine Node-Liste.
func cleanNodes(in []string) ([]string, bool) {
	seen := map[string]bool{}
	var out []string
	for _, id := range in {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		if !nodeIDRe.MatchString(id) {
			return nil, false
		}
		seen[id] = true
		out = append(out, id)
	}
	return out, true
}

// PeerRow ist eine Node des Accounts mit der Zahl der Checks, die sie misst.
type PeerRow struct {
	Peer
	Checks int
}

// Peers liefert die Nodes dieser Verknuepfung (ueber die ipv64-hubs bekannt; keine direkte Verbindung).
// LinkScope zaehlt fuer Trennen/Zuruecksetzen: own = Checks, die nur diese Node misst (laufen online
// weiter oder werden geloescht); other = alle anderen im Account (andere Nodes, Online-Checks), die bleiben.
func (m *Module) LinkScope(ctx context.Context) (own, other int) {
	list, err := m.st.Checks(ctx)
	if err != nil {
		return 0, 0
	}
	for _, c := range list {
		if c.MeasuresHere() && len(c.Nodes) <= 1 { // misst nur diese Node (Besitz egal)
			own++
		} else {
			other++
		}
	}
	return own, other
}

func (m *Module) Peers(ctx context.Context) []PeerRow {
	list := m.peers(ctx)
	count := map[string]int{}
	if checks, err := m.st.Checks(ctx); err == nil {
		me := selfNodeID()
		for _, c := range checks {
			if c.Execution == "online" {
				continue
			}
			if len(c.Nodes) == 0 {
				if c.Owner == "" || c.Owner == "self" {
					count[me]++
				}
				continue
			}
			for _, id := range c.Nodes {
				count[id]++
			}
		}
	}
	out := make([]PeerRow, 0, len(list))
	for _, p := range list {
		out = append(out, PeerRow{Peer: p, Checks: count[p.ID]})
	}
	return out
}
