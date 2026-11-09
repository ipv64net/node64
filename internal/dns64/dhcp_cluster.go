package dns64

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/dns64/dhcp"
)

// DHCP im Cluster (Plan D5/D6). Drei Bereiche, wie alle ohne Einstellung aus:
//   - DHCP-Netze (s:<Netz>): Bereich, Optionen, PXE - nicht die Schnittstelle und nicht an/aus. Ein neues Netz aus dem
//     Cluster kommt ausgeschaltet an (nie zwei DHCP-Server ungewollt), mit der Schnittstelle, die dort im Netz liegt.
//     Das Netz eines vorhandenen Netzes laesst sich nicht aendern (es ist die Kennung).
//   - Feste Adressen (r:<Netz>|<MAC>).
//   - Zum Bereich DHCP-Netze gehoert auch der DHCP-Zustand jeder Node (n:<Node>: Rolle, Schalter, Server-ID je Netz,
//     Adressen mit DNS64 auf Port 53) - fuer die Reserve-Node und die weiteren DNS-Server der Geraete.
//   - Vergaben (l:<Netz>|<MAC>): fuer die Reserve-Node und die DNS-Namen auf allen Nodes.
//
// Schalter und Rolle (Haupt-/Reserve-Node) gelten je Node. Die Reserve antwortet in einem Netz nur, wenn es dort eine
// Haupt-Node gibt (laut ihrem Zustand: Rolle Haupt-Node, Schalter an, Netz eingeschaltet) und keine davon lebt: im
// Cluster nicht erreichbar (2 Minuten) und ihre Server-ID hat seit 3 Minuten nicht als DHCP-Server geantwortet (die
// Reserve sucht jede Minute). Ohne Haupt-Node fuer das Netz bleibt sie still. Das secs-Feld der Clients zaehlt nicht
// mit: viele Geraete senden dort immer 0. Zwei Haupt-Nodes im selben Netz meldet DNS64 als Fehler.

const (
	ItemDHCPScopes = "dhcp_scopes"       // Netze (s:<Netz>) und Zustand je Node (n:<Node>)
	ItemDHCPRes    = "dhcp_reservations" // feste Adressen (r:<Netz>|<MAC>)
	ItemDHCPLeases = "dhcp_leases"       // Vergaben (l:<Netz>|<MAC>)

	setNodeID    = "node.id"              // Kennung dieser Node (Kern)
	standbyCache = 10 * time.Second       // Reserve: Zustand so lange merken (nicht je Paket in die Datenbank)
	peerSeen     = 3 * time.Minute        // Haupt-Node hat zuletzt als DHCP-Server geantwortet
	applySoon    = 500 * time.Millisecond // Neustart nach Uebernahmen aus dem Cluster (gebuendelt)
)

// DHCPPeer ist eine andere Node, mit der ein DHCP-Bereich abgeglichen wird.
type DHCPPeer struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	Online bool   `json:"online"`
}

// SetDHCPPeers verbindet DNS64 mit den Mitgliedern des Clusters (dns64cluster); item "" = alle Mitglieder. Der
// DHCP-Server startet danach neu (er kann beim Programmstart vor dem Cluster angelaufen sein: DNS-Server der Nodes).
func (m *Module) SetDHCPPeers(f func(ctx context.Context, item string) []DHCPPeer) {
	m.dhcpPeersFn.Store(&f)
	m.dhcpApplySoon()
}

func (m *Module) dhcpPeers(ctx context.Context, item string) []DHCPPeer {
	f := m.dhcpPeersFn.Load()
	if f == nil {
		return nil
	}
	return (*f)(ctx, item)
}

// dhcpPeerNames: Node-Kennung -> Name (alle Mitglieder).
func (m *Module) dhcpPeerNames(ctx context.Context) map[string]string {
	out := map[string]string{}
	for _, p := range m.dhcpPeers(ctx, "") {
		out[p.NodeID] = p.Name
	}
	return out
}

// ---- Zustand je Node ----

type clDHCPNode struct {
	Role string          `json:"role"`
	Mode string          `json:"mode"`
	Nets []clDHCPNodeNet `json:"nets,omitempty"` // eingeschaltete Netze mit Server-ID
	DNS  []string        `json:"dns,omitempty"`  // IPv4-Adressen, unter denen DNS64 dort auf Port 53 antwortet
}

type clDHCPNodeNet struct {
	Subnet string `json:"subnet"`
	Server string `json:"server"`
}

// primaryFor: Node vergibt als Haupt-Node in diesem Netz; Server-ID dort.
func (n clDHCPNode) primaryFor(subnet string) (netip.Addr, bool) {
	if n.Role != dhcpPrimary || n.Mode != dhcpOn {
		return netip.Addr{}, false
	}
	for _, x := range n.Nets {
		if x.Subnet == subnet {
			a, _ := netip.ParseAddr(x.Server)
			return a, true
		}
	}
	return netip.Addr{}, false
}

// dhcpOwnNode: Zustand dieser Node fuer die anderen.
func (m *Module) dhcpOwnNode(ctx context.Context) clDHCPNode {
	n := clDHCPNode{Role: m.dhcpRole(ctx), Mode: m.dhcpMode(ctx)}
	if scopes, err := m.DHCPScopes(ctx); err == nil {
		for _, s := range scopes {
			p, err := netip.ParsePrefix(s.Subnet)
			if !s.Enabled || s.Iface == "" || err != nil {
				continue
			}
			if a := dhcpServerAddr(s.Iface, p, s.Relay); a.IsValid() {
				n.Nets = append(n.Nets, clDHCPNodeNet{s.Subnet, a.String()})
			}
		}
	}
	m.mu.Lock()
	on := m.life != nil
	m.mu.Unlock()
	if on {
		n.DNS = m.dhcpDNSAddrs(ctx)
	}
	return n
}

// dhcpServerAddr: Server-ID der Node in einem Netz (dieselbe Wahl wie der Server).
func dhcpServerAddr(iface string, p netip.Prefix, relay bool) netip.Addr {
	return dhcp.ServerAddr(dhcp.IfaceAddrs(iface), p, relay)
}

// dhcpDNSAddrs: IPv4-Adressen, unter denen DNS64 dieser Node auf Port 53 antwortet (nichts bei anderem Port).
func (m *Module) dhcpDNSAddrs(ctx context.Context) []string {
	if m.port(ctx) != 53 {
		return nil
	}
	if b, err := netip.ParseAddr(strings.TrimSpace(m.core.SettingOr(ctx, setBind, ""))); err == nil && !b.IsUnspecified() {
		if b.Is4() {
			return []string{b.String()}
		}
		return nil
	}
	var out []string
	for _, i := range dhcpInterfaces() {
		if virtualIface(i.Name) {
			continue
		}
		for _, a := range i.Addrs {
			out = append(out, a.Addr().String())
		}
	}
	slices.Sort(out)
	return out
}

// dhcpNodes: Zustand der anderen Nodes (aus dem Cluster).
func (m *Module) dhcpNodes(ctx context.Context) map[string]clDHCPNode {
	out := map[string]clDHCPNode{}
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT node_id, data FROM dns64_dhcp_nodes`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id, data string
		var n clDHCPNode
		if rows.Scan(&id, &data) == nil && json.Unmarshal([]byte(data), &n) == nil {
			out[id] = n
		}
	}
	return out
}

// dhcpCluster: einmal gelesener Stand der anderen Nodes (Erreichbarkeit, Namen, DHCP-Zustand) und die eigene Rolle.
type dhcpCluster struct {
	online map[string]bool       // Node -> im Cluster erreichbar (Mitglieder mit dem Bereich DHCP-Netze)
	names  map[string]string     // Node -> Name (alle Mitglieder)
	nodes  map[string]clDHCPNode // Node -> DHCP-Zustand
	role   string                // eigene Rolle
}

func (m *Module) dhcpClusterState(ctx context.Context) dhcpCluster {
	c := dhcpCluster{online: map[string]bool{}, names: m.dhcpPeerNames(ctx), nodes: m.dhcpNodes(ctx), role: m.dhcpRole(ctx)}
	for _, p := range m.dhcpPeers(ctx, ItemDHCPScopes) {
		c.online[p.NodeID] = p.Online
	}
	return c
}

func (c dhcpCluster) name(id string) string {
	if n := c.names[id]; n != "" {
		return n
	}
	return id
}

// peerDNS: weitere DNS-Server fuer ein Netz - die anderen erreichbaren Nodes, deren DNS64 dort auf Port 53 antwortet.
func (c dhcpCluster) peerDNS(subnet netip.Prefix) []netip.Addr {
	var out []netip.Addr
	for id, n := range c.nodes {
		if !c.online[id] {
			continue
		}
		for _, d := range n.DNS {
			if a, err := netip.ParseAddr(d); err == nil && subnet.Contains(a) && !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return out
}

// primaryAlive: eine Haupt-Node fuer das Netz lebt (erreichbar oder ihre Server-ID antwortete); gibt es keine, gilt
// das als lebendig (die Reserve bleibt still). primaries = Namen der Haupt-Nodes fuer das Netz.
func (c dhcpCluster) primaryAlive(subnet string, s *dhcp.Server) (alive bool, primaries []string) {
	for id, n := range c.nodes {
		server, ok := n.primaryFor(subnet)
		if !ok {
			continue
		}
		primaries = append(primaries, c.name(id))
		if c.online[id] || (s != nil && server.IsValid() && s.SawServer(server, peerSeen)) {
			alive = true
		}
	}
	slices.Sort(primaries)
	return alive || len(primaries) == 0, primaries
}

// expected: Server-ID einer Haupt-Node des Clusters - fuer eine Reserve erwartet, fuer eine Haupt-Node meldet sie der
// Hinweis "zwei Haupt-Nodes" (solange die andere erreichbar ist) statt "fremder Server". Alles andere (z. B. eine
// Reserve, die vergibt, waehrend diese Haupt-Node lebt) ist ein fremder Server.
func (c dhcpCluster) expected(server netip.Addr) bool {
	for id, n := range c.nodes {
		for _, x := range n.Nets {
			if a, ok := n.primaryFor(x.Subnet); ok && a == server {
				return c.role == dhcpReserve || (c.role == dhcpPrimary && c.online[id])
			}
		}
	}
	return false
}

// conflicts: Netze, in denen ausser dieser Node noch eine erreichbare Haupt-Node vergibt (Netz -> Namen der anderen).
// Zustaende von Nodes, die nicht (mehr) erreichbar sind, zaehlen nicht.
func (c dhcpCluster) conflicts(own clDHCPNode) map[string][]string {
	out := map[string][]string{}
	if own.Role != dhcpPrimary || own.Mode != dhcpOn {
		return out
	}
	for id, n := range c.nodes {
		if !c.online[id] {
			continue
		}
		for _, x := range own.Nets {
			if _, ok := n.primaryFor(x.Subnet); ok {
				out[x.Subnet] = append(out[x.Subnet], c.name(id))
			}
		}
	}
	return out
}

func (m *Module) dhcpExpected(server netip.Addr) bool {
	return m.dhcpClusterState(context.Background()).expected(server)
}

func (m *Module) dhcpPrimaryAlive(ctx context.Context, subnet string) (bool, []string) {
	return m.dhcpClusterState(ctx).primaryAlive(subnet, m.dhcpSrv.Load())
}

func (m *Module) dhcpConflicts(ctx context.Context) map[string][]string {
	return m.dhcpClusterState(ctx).conflicts(m.dhcpOwnNode(ctx))
}

func (m *Module) dhcpRole(ctx context.Context) string {
	return oneOf(m.core.SettingOr(ctx, setDHCPRole, ""), dhcpPrimary, dhcpPrimary, dhcpReserve)
}

// SetDHCPRole setzt die Rolle dieser Node (primary, reserve) und startet den DHCP-Server passend neu.
func (m *Module) SetDHCPRole(ctx context.Context, role string) error {
	if role != dhcpPrimary && role != dhcpReserve {
		return errCfg("err_dhcp_role")
	}
	if err := m.core.SetSetting(ctx, setDHCPRole, role); err != nil {
		return err
	}
	m.dhcpStandbyReset()
	m.dhcpApply(ctx)
	return nil
}

func (m *Module) dhcpStandbyReset() {
	m.dh.soonMu.Lock()
	m.dh.standby = nil
	m.dh.soonMu.Unlock()
}

// dhcpStandby: Reserve-Node bleibt in diesem Netz still (Server.Standby, ohne gehaltene Sperre des Servers).
func (m *Module) dhcpStandby(subnet netip.Prefix) bool {
	key := subnet.String()
	m.dh.soonMu.Lock()
	if e, ok := m.dh.standby[key]; ok && time.Since(e.at) < standbyCache {
		m.dh.soonMu.Unlock()
		return e.quiet
	}
	m.dh.soonMu.Unlock()
	alive, _ := m.dhcpPrimaryAlive(context.Background(), key)
	m.dh.soonMu.Lock()
	if m.dh.standby == nil {
		m.dh.standby = map[string]standbyState{}
	}
	m.dh.standby[key] = standbyState{alive, time.Now()}
	m.dh.soonMu.Unlock()
	return alive
}

type standbyState struct {
	quiet bool
	at    time.Time
}

// dhcpCheckConflicts meldet zwei Haupt-Nodes im selben Netz (einmal je Netz und Node).
func (m *Module) dhcpCheckConflicts(ctx context.Context) {
	conf := m.dhcpConflicts(ctx)
	m.dh.soonMu.Lock()
	if m.dh.conflictSent == nil {
		m.dh.conflictSent = map[string]bool{}
	}
	var send [][2]string
	seen := map[string]bool{}
	for subnet, nodes := range conf {
		for _, n := range nodes {
			k := subnet + "|" + n
			seen[k] = true
			if !m.dh.conflictSent[k] {
				m.dh.conflictSent[k] = true
				send = append(send, [2]string{subnet, n})
			}
		}
	}
	for k := range m.dh.conflictSent {
		if !seen[k] {
			delete(m.dh.conflictSent, k)
		}
	}
	m.dh.soonMu.Unlock()
	for _, x := range send {
		if sc, ok, _ := m.dhcpScopeBySubnet(ctx, x[0]); ok {
			m.log.Warn("dhcp: second primary node in network", "network", x[0], "node", x[1])
			m.dhcpNotify(sc.ID, "dns64_dhcp_primary", map[string]string{"node": x[1]})
		}
	}
}

// dhcpSynced meldet Aenderungen an Netzen und festen Adressen an den Cluster (mit einem Netz verschwinden auch
// seine Vergaben; der eigene Zustand aendert sich mit) und baut die Namen neu.
func (m *Module) dhcpSynced(ctx context.Context) {
	for _, it := range []string{ItemDHCPScopes, ItemDHCPRes, ItemDHCPLeases} {
		m.clChanged(ctx, it)
	}
	m.dhcpNamesSoon()
}

// dhcpLeasesSoon meldet Vergaben und eigenen Zustand (Bereich Netze) gebuendelt an den Cluster.
func (m *Module) dhcpLeasesSoon() {
	m.dh.soonMu.Lock()
	defer m.dh.soonMu.Unlock()
	if m.dh.leasesT != nil {
		return
	}
	m.dh.leasesT = time.AfterFunc(2*time.Second, func() {
		m.dh.soonMu.Lock()
		m.dh.leasesT = nil
		m.dh.soonMu.Unlock()
		m.clChanged(context.Background(), ItemDHCPLeases)
		m.clChanged(context.Background(), ItemDHCPScopes)
	})
}

// dhcpApplySoon startet den DHCP-Server gebuendelt kurz danach neu (Uebernahmen aus dem Cluster: beim ersten
// Abgleich hunderter fester Adressen nicht je Eintrag).
func (m *Module) dhcpApplySoon() {
	m.dh.soonMu.Lock()
	defer m.dh.soonMu.Unlock()
	if m.dh.applyT != nil {
		return
	}
	m.dh.applyT = time.AfterFunc(applySoon, func() {
		m.dh.soonMu.Lock()
		m.dh.applyT = nil
		m.dh.soonMu.Unlock()
		m.dhcpApply(context.Background())
	})
}

// ---- Stand je Bereich ----

type clDHCPScope struct {
	Name          string   `json:"name,omitempty"`
	Subnet        string   `json:"subnet"`
	Start         string   `json:"range_start"`
	End           string   `json:"range_end"`
	Router        string   `json:"router,omitempty"`
	DNS           []string `json:"dns,omitempty"`
	Domain        string   `json:"domain,omitempty"`
	LeaseHours    int      `json:"lease_hours"`
	NTP           []string `json:"ntp,omitempty"`
	Authoritative bool     `json:"authoritative"`
	BootServer    string   `json:"boot_server,omitempty"`
	BootBIOS      string   `json:"boot_bios,omitempty"`
	BootUEFI      string   `json:"boot_uefi,omitempty"`
	BootIPXE      string   `json:"boot_ipxe,omitempty"`
	Relay         bool     `json:"relay,omitempty"`
}

type clDHCPRes struct {
	Subnet  string `json:"subnet"`
	MAC     string `json:"mac"`
	IP      string `json:"ip"`
	Name    string `json:"name,omitempty"`
	Comment string `json:"comment,omitempty"`
}

type clDHCPLease struct {
	Subnet   string `json:"subnet"`
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	Expires  string `json:"expires"`
	State    string `json:"state"`
}

func clScopeOf(s DHCPScope) clDHCPScope {
	return clDHCPScope{Name: s.Name, Subnet: s.Subnet, Start: s.Start, End: s.End, Router: s.Router, DNS: s.DNS, Domain: s.Domain,
		LeaseHours: s.LeaseHours, NTP: s.NTP, Authoritative: s.Authoritative, BootServer: s.BootServer, BootBIOS: s.BootBIOS,
		BootUEFI: s.BootUEFI, BootIPXE: s.BootIPXE, Relay: s.Relay}
}

func clLeaseOf(subnet string, l dhcp.Lease) clDHCPLease {
	return clDHCPLease{subnet, l.MAC, l.IP.String(), l.Hostname, l.Expires.UTC().Format(time.RFC3339), l.State}
}

func (m *Module) clDHCPCurrent(ctx context.Context, item string) (map[string]string, error) {
	out := map[string]string{}
	scopes, err := m.DHCPScopes(ctx)
	if m.noTable(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	subnet := map[int64]string{}
	for _, s := range scopes {
		subnet[s.ID] = s.Subnet
		if item == ItemDHCPScopes {
			out["s:"+s.Subnet] = jsonString(clScopeOf(s))
		}
	}
	if item == ItemDHCPScopes {
		if id := m.dhcpNodeID(ctx); id != "" {
			out["n:"+id] = jsonString(m.dhcpOwnNode(ctx))
		}
		for id, n := range m.dhcpNodes(ctx) {
			out["n:"+id] = jsonString(n)
		}
	}
	switch item {
	case ItemDHCPRes:
		list, err := m.DHCPReservations(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range list {
			out["r:"+subnet[r.ScopeID]+"|"+r.MAC] = jsonString(clDHCPRes{subnet[r.ScopeID], r.MAC, r.IP, r.Name, r.Comment})
		}
	case ItemDHCPLeases:
		list, err := m.dhcpLeaseRows(ctx)
		if err != nil {
			return nil, err
		}
		for _, l := range list {
			out["l:"+subnet[l.Scope]+"|"+l.MAC] = jsonString(clLeaseOf(subnet[l.Scope], l))
		}
	}
	return out, nil
}

func (m *Module) dhcpNodeID(ctx context.Context) string { return m.core.SettingOr(ctx, setNodeID, "") }

func (m *Module) dhcpScopeBySubnet(ctx context.Context, subnet string) (DHCPScope, bool, error) {
	s, err := scanDHCPScope(m.core.Reader().QueryRowContext(ctx, `SELECT `+dhcpScopeCols+` FROM dns64_dhcp_scopes WHERE subnet = ?`, subnet))
	if errors.Is(err, sql.ErrNoRows) {
		return s, false, nil
	}
	return s, err == nil, err
}

// dhcpGuessIface: echte Schnittstelle dieser Node mit einer Adresse im Netz ("" = keine).
func dhcpGuessIface(subnet string) string {
	p, err := netip.ParsePrefix(subnet)
	if err != nil {
		return ""
	}
	for _, i := range dhcpInterfaces() {
		if virtualIface(i.Name) {
			continue
		}
		for _, a := range i.Addrs {
			if p.Contains(a.Addr()) {
				return i.Name
			}
		}
	}
	return ""
}

// clDHCPApply uebernimmt einen Eintrag einer anderen Node.
func (m *Module) clDHCPApply(ctx context.Context, item, id string, data json.RawMessage, deleted bool) error {
	w := m.core.Writer()
	switch item {
	case ItemDHCPScopes:
		if node, isNode := strings.CutPrefix(id, "n:"); isNode {
			return m.clApplyNode(ctx, id, node, data, deleted)
		}
		subnet := strings.TrimPrefix(id, "s:")
		cur, ok, err := m.dhcpScopeBySubnet(ctx, subnet)
		if err != nil {
			return err
		}
		if deleted {
			if ok {
				if _, err := w.ExecContext(ctx, `DELETE FROM dns64_dhcp_scopes WHERE id = ?`, cur.ID); err != nil {
					return err
				}
			}
			m.clSetSnap(item, id, "")
			break
		}
		var in clDHCPScope
		if err := json.Unmarshal(data, &in); err != nil {
			return err
		}
		s := DHCPScope{Name: in.Name, Iface: "cluster", Subnet: in.Subnet, Start: in.Start, End: in.End, Router: in.Router, DNS: in.DNS, Domain: in.Domain,
			LeaseHours: in.LeaseHours, NTP: in.NTP, Authoritative: in.Authoritative, BootServer: in.BootServer, BootBIOS: in.BootBIOS, BootUEFI: in.BootUEFI,
			BootIPXE: in.BootIPXE, Relay: in.Relay}
		if err := normalizeDHCPScope(&s); err != nil { // Iface "cluster": Platzhalter, die Schnittstelle bleibt je Node
			return err
		}
		if s.Subnet != subnet {
			return fmt.Errorf("dhcp cluster: subnet %s does not match %s", s.Subnet, subnet)
		}
		if other, taken := m.dhcpOverlap(ctx, s.Subnet, cur.ID); taken {
			return fmt.Errorf("dhcp cluster: network %s overlaps local network %s", s.Subnet, other)
		}
		if ok {
			iface, enabled := cur.Iface, cur.Enabled
			if !s.Relay && iface != "" && m.dhcpIfaceTaken(ctx, DHCPScope{Iface: iface}, cur.ID) { // jetzt direkt: Schnittstelle schon belegt
				iface, enabled = "", false
			}
			_, err = w.ExecContext(ctx, `UPDATE dns64_dhcp_scopes SET name = ?, iface = ?, range_start = ?, range_end = ?, router = ?, dns = ?, domain = ?, lease_hours = ?, ntp = ?,
				authoritative = ?, boot_server = ?, boot_bios = ?, boot_uefi = ?, boot_ipxe = ?, relay = ?, enabled = ? WHERE id = ?`, s.Name, iface, s.Start, s.End, s.Router,
				strings.Join(s.DNS, ","), s.Domain, s.LeaseHours, strings.Join(s.NTP, ","), s.Authoritative, s.BootServer, s.BootBIOS, s.BootUEFI, s.BootIPXE, s.Relay, enabled, cur.ID)
		} else {
			iface := ""
			if !s.Relay {
				if iface = dhcpGuessIface(s.Subnet); iface != "" && m.dhcpIfaceTaken(ctx, DHCPScope{Iface: iface}, 0) {
					iface = ""
				}
			}
			_, err = w.ExecContext(ctx, `INSERT INTO dns64_dhcp_scopes (name, iface, subnet, range_start, range_end, router, dns, domain, lease_hours, ntp, authoritative, boot_server, boot_bios, boot_uefi, boot_ipxe, relay, enabled, created_at)
				VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)`, s.Name, iface, s.Subnet, s.Start, s.End, s.Router, strings.Join(s.DNS, ","), s.Domain, s.LeaseHours,
				strings.Join(s.NTP, ","), s.Authoritative, s.BootServer, s.BootBIOS, s.BootUEFI, s.BootIPXE, s.Relay, time.Now().UTC().Format(time.RFC3339))
		}
		if err != nil {
			return err
		}
		m.clSetSnap(item, id, jsonString(clScopeOf(s)))
	case ItemDHCPRes:
		subnet, mac, _ := strings.Cut(strings.TrimPrefix(id, "r:"), "|")
		sc, ok, err := m.dhcpScopeBySubnet(ctx, subnet)
		if err != nil {
			return err
		}
		if deleted {
			if ok {
				if _, err := w.ExecContext(ctx, `DELETE FROM dns64_dhcp_reservations WHERE scope_id = ? AND mac = ?`, sc.ID, mac); err != nil {
					return err
				}
			}
			m.clSetSnap(item, id, "")
			break
		}
		if !ok {
			return fmt.Errorf("dhcp cluster: network %s not here yet", subnet)
		}
		var in clDHCPRes
		if err := json.Unmarshal(data, &in); err != nil {
			return err
		}
		r := DHCPReservation{ScopeID: sc.ID, MAC: in.MAC, IP: in.IP, Name: in.Name, Comment: in.Comment}
		if err := m.normalizeDHCPReservation(ctx, &r, false); err != nil {
			return err
		}
		if _, err := w.ExecContext(ctx, `DELETE FROM dns64_dhcp_reservations WHERE scope_id = ? AND ip = ? AND mac <> ?`, sc.ID, r.IP, r.MAC); err != nil {
			return err
		}
		if _, err := w.ExecContext(ctx, `INSERT INTO dns64_dhcp_reservations (scope_id, mac, ip, name, comment) VALUES (?,?,?,?,?)
			ON CONFLICT(scope_id, mac) DO UPDATE SET ip = excluded.ip, name = excluded.name, comment = excluded.comment`, sc.ID, r.MAC, r.IP, r.Name, r.Comment); err != nil {
			return err
		}
		m.clSetSnap(item, id, jsonString(clDHCPRes{subnet, r.MAC, r.IP, r.Name, r.Comment}))
	case ItemDHCPLeases:
		subnet, mac, _ := strings.Cut(strings.TrimPrefix(id, "l:"), "|")
		sc, ok, err := m.dhcpScopeBySubnet(ctx, subnet)
		if err != nil {
			return err
		}
		if deleted {
			if ok {
				if err := (dhcpStore{m}).DeleteLease(sc.ID, mac); err != nil {
					return err
				}
				if s := m.dhcpSrv.Load(); s != nil {
					s.Forget(sc.ID, mac)
				}
			}
			m.clSetSnap(item, id, "")
			m.dhcpNamesSoon()
			return nil
		}
		if !ok {
			return fmt.Errorf("dhcp cluster: network %s not here yet", subnet)
		}
		var in clDHCPLease
		if err := json.Unmarshal(data, &in); err != nil {
			return err
		}
		ip, err := netip.ParseAddr(in.IP)
		if err != nil || in.MAC != mac {
			return fmt.Errorf("dhcp cluster: bad lease %s", id)
		}
		exp, _ := time.Parse(time.RFC3339, in.Expires)
		l := dhcp.Lease{Scope: sc.ID, MAC: mac, IP: ip, Hostname: in.Hostname, Expires: exp, State: in.State}
		if l.State != dhcp.StateBound && l.State != dhcp.StateFree {
			return fmt.Errorf("dhcp cluster: bad lease state %q", in.State)
		}
		applied, err := m.clApplyLease(ctx, l)
		if err != nil {
			return err
		}
		if s := m.dhcpSrv.Load(); s != nil && applied {
			s.Import(l)
		}
		// Stand der anderen Node merken: weicht der eigene ab (aelter dort), meldet der naechste Abgleich ihn zurueck
		m.clSetSnap(item, id, jsonString(clLeaseOf(subnet, l)))
		m.dhcpNamesSoon()
		return nil
	default:
		return errUnknownItem
	}
	m.dhcpApplySoon()
	m.dhcpNamesSoon()
	return nil
}

// clApplyNode speichert den DHCP-Zustand einer anderen Node.
func (m *Module) clApplyNode(ctx context.Context, id, node string, data json.RawMessage, deleted bool) error {
	if node == m.dhcpNodeID(ctx) {
		return nil // der eigene Zustand entsteht hier
	}
	w := m.core.Writer()
	if deleted {
		if _, err := w.ExecContext(ctx, `DELETE FROM dns64_dhcp_nodes WHERE node_id = ?`, node); err != nil {
			return err
		}
		m.clSetSnap(ItemDHCPScopes, id, "")
	} else {
		var n clDHCPNode
		if err := json.Unmarshal(data, &n); err != nil {
			return err
		}
		if _, err := w.ExecContext(ctx, `INSERT INTO dns64_dhcp_nodes (node_id, data) VALUES (?, ?) ON CONFLICT(node_id) DO UPDATE SET data = excluded.data`,
			node, jsonString(n)); err != nil {
			return err
		}
		m.clSetSnap(ItemDHCPScopes, id, jsonString(n))
	}
	m.dhcpStandbyReset()
	m.dhcpApplySoon() // DNS-Server der Geraete koennen sich geaendert haben
	go m.dhcpCheckConflicts(context.WithoutCancel(ctx))
	return nil
}

// clApplyLease uebernimmt eine Vergabe einer anderen Node, wenn sie nicht aelter ist als der Stand hier: eine
// laengere eigene Vergabe derselben MAC bleibt, und eine laufende Vergabe einer anderen MAC auf derselben IP wird
// nur von einer noch laengeren gebundenen verdraengt (freie Vergaben verdraengen nie). applied = gespeichert.
func (m *Module) clApplyLease(ctx context.Context, l dhcp.Lease) (applied bool, err error) {
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var curExp string
	switch err := tx.QueryRowContext(ctx, `SELECT expires FROM dns64_dhcp_leases WHERE scope_id = ? AND mac = ?`, l.Scope, l.MAC).Scan(&curExp); {
	case err == nil:
		if t, _ := time.Parse(time.RFC3339, curExp); t.After(l.Expires) {
			return false, nil
		}
	case !errors.Is(err, sql.ErrNoRows):
		return false, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT mac, expires, state FROM dns64_dhcp_leases WHERE scope_id = ? AND ip = ? AND mac <> ?`, l.Scope, l.IP.String(), l.MAC)
	if err != nil {
		return false, err
	}
	var others []string
	now := time.Now()
	for rows.Next() {
		var mac, exp, state string
		if err := rows.Scan(&mac, &exp, &state); err != nil {
			rows.Close()
			return false, err
		}
		t, _ := time.Parse(time.RFC3339, exp)
		if state == dhcp.StateBound && now.Before(t) && (l.State != dhcp.StateBound || !l.Expires.After(t)) {
			rows.Close()
			return false, nil // laufende Vergabe hier ist neuer
		}
		others = append(others, mac)
	}
	rows.Close()
	if l.State == dhcp.StateBound {
		for _, mac := range others {
			if _, err := tx.ExecContext(ctx, `DELETE FROM dns64_dhcp_leases WHERE scope_id = ? AND mac = ?`, l.Scope, mac); err != nil {
				return false, err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO dns64_dhcp_leases (scope_id, mac, ip, hostname, expires, state) VALUES (?,?,?,?,?,?)
		ON CONFLICT(scope_id, mac) DO UPDATE SET ip = excluded.ip, hostname = excluded.hostname, expires = excluded.expires, state = excluded.state`,
		l.Scope, l.MAC, l.IP.String(), l.Hostname, l.Expires.UTC().Format(time.RFC3339), l.State); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
