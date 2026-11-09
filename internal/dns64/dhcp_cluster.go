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
//   - Feste Adressen (r:<Netz>|<MAC>).
//   - Vergaben (l:<Netz>|<MAC>): fuer die Reserve-Node und fuer DNS-Namen auf allen Nodes.
//
// Der Schalter an/aus/Probelauf und die Rolle (Haupt-/Reserve-Node) gelten je Node. Die Reserve antwortet nur, wenn
// die Haupt-Node wirklich weg ist: kein Mitglied mit dem Bereich "Vergaben" erreichbar (Cluster, 2 Minuten) und
// keines hat in den letzten 3 Minuten als DHCP-Server geantwortet (eigene Suche jede Minute). Ohne Mitglied mit
// diesem Bereich bleibt sie still. Das secs-Feld der Clients zaehlt nicht mit: viele Geraete senden dort immer 0.
// Im Cluster bekommen die Geraete (DNS leer) nach dieser Node auch die anderen Nodes im Netz als DNS-Server.

const (
	ItemDHCPScopes = "dhcp_scopes"       // Netze (s:<Netz>)
	ItemDHCPRes    = "dhcp_reservations" // feste Adressen (r:<Netz>|<MAC>)
	ItemDHCPLeases = "dhcp_leases"       // Vergaben (l:<Netz>|<MAC>)

	standbyCache = 10 * time.Second // Reserve: Zustand so lange merken (nicht je Paket in die Datenbank)
	peerSeen     = 3 * time.Minute  // Haupt-Node hat zuletzt als DHCP-Server geantwortet
)

// DHCPPeer ist eine andere Node, mit der ein DHCP-Bereich abgeglichen wird.
type DHCPPeer struct {
	Name   string     `json:"name"`
	Addr   netip.Addr `json:"addr"` // aus der Adresse der Node im Cluster (ungueltig = Name statt IP)
	Online bool       `json:"online"`
}

// SetDHCPPeers verbindet DNS64 mit den Mitgliedern des Clusters (dns64cluster); item "" = alle Mitglieder.
func (m *Module) SetDHCPPeers(f func(ctx context.Context, item string) []DHCPPeer) { m.dhcpPeersFn = f }

func (m *Module) dhcpPeers(ctx context.Context, item string) []DHCPPeer {
	if m.dhcpPeersFn == nil {
		return nil
	}
	return m.dhcpPeersFn(ctx, item)
}

// dhcpPeerDNS: weitere DNS-Server fuer ein Netz - die anderen Nodes mit dem Bereich "DHCP-Netze" in diesem Netz.
func (m *Module) dhcpPeerDNS(ctx context.Context, subnet netip.Prefix) []netip.Addr {
	var out []netip.Addr
	for _, p := range m.dhcpPeers(ctx, ItemDHCPScopes) {
		if p.Addr.Is4() && subnet.Contains(p.Addr) && !slices.Contains(out, p.Addr) {
			out = append(out, p.Addr)
		}
	}
	return out
}

// dhcpIsPeer: Adresse einer Node des Clusters mit einem DHCP-Bereich (kein fremder DHCP-Server).
func (m *Module) dhcpIsPeer(ip netip.Addr) bool {
	ctx := context.Background()
	for _, item := range []string{ItemDHCPLeases, ItemDHCPScopes, ItemDHCPRes} {
		for _, p := range m.dhcpPeers(ctx, item) {
			if p.Addr == ip {
				return true
			}
		}
	}
	return false
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
	m.dh.soonMu.Lock()
	m.dh.standbyAt = time.Time{}
	m.dh.soonMu.Unlock()
	m.dhcpApply(ctx)
	return nil
}

// dhcpStandby: Reserve-Node bleibt still (Server.Standby, ohne gehaltene Sperre des Servers).
func (m *Module) dhcpStandby() bool {
	m.dh.soonMu.Lock()
	if time.Since(m.dh.standbyAt) < standbyCache {
		v := m.dh.standby
		m.dh.soonMu.Unlock()
		return v
	}
	m.dh.soonMu.Unlock()
	v := m.dhcpPrimaryAlive(context.Background())
	m.dh.soonMu.Lock()
	m.dh.standby, m.dh.standbyAt = v, time.Now()
	m.dh.soonMu.Unlock()
	return v
}

// dhcpPrimaryAlive: eine andere Node mit dem Bereich "Vergaben" ist erreichbar bzw. antwortet als DHCP-Server;
// ohne solche Node gilt sie als lebendig (Reserve ohne Partner bleibt still).
func (m *Module) dhcpPrimaryAlive(ctx context.Context) bool {
	peers := m.dhcpPeers(ctx, ItemDHCPLeases)
	if len(peers) == 0 {
		return true
	}
	s := m.dhcpSrv.Load()
	for _, p := range peers {
		if p.Online || (s != nil && p.Addr.IsValid() && s.SawServer(p.Addr, peerSeen)) {
			return true
		}
	}
	return false
}

// dhcpSynced meldet Aenderungen an Netzen und festen Adressen an den Cluster (mit einem Netz verschwinden auch
// seine Vergaben) und baut die Namen neu.
func (m *Module) dhcpSynced(ctx context.Context) {
	for _, it := range []string{ItemDHCPScopes, ItemDHCPRes, ItemDHCPLeases} {
		m.clChanged(ctx, it)
	}
	m.dhcpNamesSoon()
}

// dhcpLeasesSoon meldet die Vergaben gebuendelt an den Cluster.
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
	nz := func(l []string) []string {
		if len(l) == 0 {
			return nil
		}
		return l
	}
	return clDHCPScope{s.Name, s.Subnet, s.Start, s.End, s.Router, nz(s.DNS), s.Domain, s.LeaseHours, nz(s.NTP), s.Authoritative,
		s.BootServer, s.BootBIOS, s.BootUEFI, s.BootIPXE, s.Relay}
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

func (m *Module) dhcpScopeBySubnet(ctx context.Context, subnet string) (DHCPScope, bool, error) {
	s, err := scanDHCPScope(m.core.Reader().QueryRowContext(ctx, `SELECT `+dhcpScopeCols+` FROM dns64_dhcp_scopes WHERE subnet = ?`, subnet))
	if errors.Is(err, sql.ErrNoRows) {
		return s, false, nil
	}
	return s, err == nil, err
}

// dhcpGuessIface: Schnittstelle dieser Node mit einer Adresse im Netz ("" = keine).
func dhcpGuessIface(subnet string) string {
	p, err := netip.ParsePrefix(subnet)
	if err != nil {
		return ""
	}
	for _, i := range dhcpInterfaces() {
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
		if err := normalizeDHCPScope(&s); err != nil {
			return err
		}
		if s.Subnet != subnet {
			return fmt.Errorf("dhcp cluster: subnet %s does not match %s", s.Subnet, subnet)
		}
		if ok {
			_, err = w.ExecContext(ctx, `UPDATE dns64_dhcp_scopes SET name = ?, range_start = ?, range_end = ?, router = ?, dns = ?, domain = ?, lease_hours = ?, ntp = ?, authoritative = ?,
				boot_server = ?, boot_bios = ?, boot_uefi = ?, boot_ipxe = ?, relay = ? WHERE id = ?`, s.Name, s.Start, s.End, s.Router, strings.Join(s.DNS, ","), s.Domain, s.LeaseHours,
				strings.Join(s.NTP, ","), s.Authoritative, s.BootServer, s.BootBIOS, s.BootUEFI, s.BootIPXE, s.Relay, cur.ID)
		} else {
			iface := ""
			if !s.Relay {
				iface = dhcpGuessIface(s.Subnet)
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
		if err := m.normalizeDHCPReservation(ctx, &r); err != nil {
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
					s.Import(dhcp.Lease{Scope: sc.ID, MAC: mac})
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
		if err := (dhcpStore{m}).SaveLease(l); err != nil {
			return err
		}
		if s := m.dhcpSrv.Load(); s != nil {
			s.Import(l)
		}
		m.clSetSnap(item, id, jsonString(clLeaseOf(subnet, l)))
		m.dhcpNamesSoon()
		return nil
	default:
		return errUnknownItem
	}
	m.dhcpApply(ctx)
	m.dhcpNamesSoon()
	return nil
}
