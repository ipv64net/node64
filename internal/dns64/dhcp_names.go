package dns64

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/dhcp"
)

// DHCP und DNS Hand in Hand (Plan D3): Jede aktive Vergabe und jede feste Adresse mit Namen bekommt
// <name>.<Domain des Netzes> als A-Eintrag samt PTR. Der Name kommt aus der festen Adresse, sonst vom Geraet
// (Option 12), als DNS-Name bereinigt (deviceSlug). Vorrang: eigene Eintraege, dann DHCP, dann Platzhalter-Eintraege
// und Geraetenamen der Zonen. Ist ein Name schon von einer anderen MAC belegt, bekommt das zweite Geraet keinen.
// Die Tabelle entsteht aus node64.db (Netze, feste Adressen, Vergaben) - also auch auf Nodes ohne eigenen
// DHCP-Server, die die Vergaben ueber den Cluster bekommen. Dazu gehen MAC und IP der Vergaben an die Geraetegruppen.

const dhcpTTL = 60

type dhcpName struct {
	ip  netip.Addr
	exp time.Time // Null = feste Adresse (gilt immer)
}

func (n dhcpName) live(now time.Time) bool {
	return n.ip.IsValid() && (n.exp.IsZero() || now.Before(n.exp))
}

type dhcpNameTable struct {
	byName map[string]dhcpName   // Name -> Adresse
	byPTR  map[string]string     // in-addr.arpa-Name (ohne Punkt) -> Name
	byIP   map[netip.Addr]string // Adresse -> DNS-Name (Seite)
	labels map[netip.Addr]string // Adresse -> Name, auch ohne Domain (Client-Namen im Abfrage-Log)
}

// dhcpLeaseRows liest alle Vergaben aus node64.db.
func (m *Module) dhcpLeaseRows(ctx context.Context) ([]dhcp.Lease, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT scope_id, mac, ip, hostname, expires, state FROM dns64_dhcp_leases`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []dhcp.Lease
	for rows.Next() {
		var l dhcp.Lease
		var ip, exp string
		if err := rows.Scan(&l.Scope, &l.MAC, &ip, &l.Hostname, &exp, &l.State); err != nil {
			return nil, err
		}
		l.IP, _ = netip.ParseAddr(ip)
		l.Expires, _ = time.Parse(time.RFC3339, exp)
		out = append(out, l)
	}
	return out, rows.Err()
}

// dhcpNamesBuild baut die Namen neu (nach jeder Vergabe, Aenderung an Netzen/festen Adressen und beim Start).
func (m *Module) dhcpNamesBuild(ctx context.Context) error {
	scopes, err := m.DHCPScopes(ctx)
	if err != nil {
		return err
	}
	res, err := m.DHCPReservations(ctx)
	if err != nil {
		return err
	}
	leases, err := m.dhcpLeaseRows(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	t := &dhcpNameTable{byName: map[string]dhcpName{}, byPTR: map[string]string{}, byIP: map[netip.Addr]string{}, labels: map[netip.Addr]string{}}
	domain := map[int64]string{}
	for _, s := range scopes {
		domain[s.ID] = s.Domain
	}
	key := func(scope int64, mac string) string { return strconv.FormatInt(scope, 10) + "/" + mac }
	owner := map[string]string{} // Name -> MAC
	claim := func(scope int64, label, mac string, ip netip.Addr, exp time.Time) {
		if _, seen := t.labels[ip]; !seen && label != "" {
			t.labels[ip] = label
		}
		slug := deviceSlug(label)
		if slug == "" || domain[scope] == "" || !ip.IsValid() {
			return
		}
		name := slug + "." + domain[scope]
		if _, taken := owner[name]; taken {
			return // erste Vergabe gewinnt (feste Adressen zuerst, dann nach MAC)
		}
		owner[name] = mac
		t.byName[name] = dhcpName{ip, exp}
		t.byIP[ip] = name
		if arpa, err := dns.ReverseAddr(ip.String()); err == nil {
			if a := strings.TrimSuffix(arpa, "."); t.byPTR[a] == "" {
				t.byPTR[a] = name
			}
		}
	}
	fixed := map[string]DHCPReservation{}
	for _, r := range res {
		fixed[key(r.ScopeID, r.MAC)] = r
		ip, _ := netip.ParseAddr(r.IP)
		claim(r.ScopeID, r.Name, r.MAC, ip, time.Time{})
	}
	slices.SortFunc(leases, func(a, b dhcp.Lease) int { return strings.Compare(a.MAC, b.MAC) })
	macs := map[netip.Addr]string{}
	for _, l := range leases {
		if !l.Active(now) || l.State != dhcp.StateBound {
			continue
		}
		macs[l.IP] = l.MAC
		label := l.Hostname
		if r, ok := fixed[key(l.Scope, l.MAC)]; ok && r.Name != "" {
			label = r.Name
		}
		claim(l.Scope, label, l.MAC, l.IP, l.Expires)
	}
	m.dhcpNames.Store(t)
	m.grp.SetLeases(macs)
	return nil
}

// dhcpNamesSoon baut die Namen gebuendelt kurz danach neu.
func (m *Module) dhcpNamesSoon() {
	m.dh.soonMu.Lock()
	defer m.dh.soonMu.Unlock()
	if m.dh.namesT != nil {
		return
	}
	m.dh.namesT = time.AfterFunc(300*time.Millisecond, func() {
		m.dh.soonMu.Lock()
		m.dh.namesT = nil
		m.dh.soonMu.Unlock()
		if err := m.dhcpNamesBuild(context.Background()); err != nil && !m.noTable(err) {
			m.log.Warn("dhcp names", "err", err)
		}
	})
}

// dhcpA beantwortet einen DHCP-Namen (nur A; andere Typen: Name bekannt, keine Daten).
func (m *Module) dhcpA(name string, qtype uint16) ([]dns.RR, bool) {
	t := m.dhcpNames.Load()
	if t == nil {
		return nil, false
	}
	n, ok := t.byName[name]
	if !ok || !n.live(time.Now()) {
		return nil, false
	}
	if qtype == dns.TypeA {
		return []dns.RR{&dns.A{Hdr: hdr(name, dns.TypeA, dhcpTTL), A: n.ip.AsSlice()}}, true
	}
	return nil, true
}

// dhcpPTR beantwortet die Rueckwaertssuche einer vergebenen Adresse.
func (m *Module) dhcpPTR(name string) ([]dns.RR, bool) {
	t := m.dhcpNames.Load()
	if t == nil {
		return nil, false
	}
	target, ok := t.byPTR[name]
	if !ok || !t.byName[target].live(time.Now()) {
		return nil, false
	}
	return []dns.RR{&dns.PTR{Hdr: hdr(name, dns.TypePTR, dhcpTTL), Ptr: dns.Fqdn(target)}}, true
}

// dhcpLabel: Name eines Geraets aus der festen Adresse bzw. vom Geraet ("" = keiner), auch ohne Domain.
func (m *Module) dhcpLabel(ip netip.Addr) string {
	if t := m.dhcpNames.Load(); t != nil {
		return t.labels[ip]
	}
	return ""
}

// dhcpDNSName: DNS-Name einer Adresse (Seite), "" = keiner.
func (m *Module) dhcpDNSName(ip netip.Addr) string {
	if t := m.dhcpNames.Load(); t != nil {
		return t.byIP[ip]
	}
	return ""
}
