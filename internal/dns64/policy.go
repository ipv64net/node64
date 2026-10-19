package dns64

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/ipv64net/node64/internal/dns64/dnsserver"
	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/groups"
)

// Regeln je Geraetegruppe (Phase G2): Blocklisten der Gruppe (wie global oder eigene Auswahl), Kategorien,
// Freigaben und Sperren. Geladen werden die global eingeschalteten Listen plus die, die eine Gruppe zusaetzlich
// nutzt; welche davon fuer wen gelten, steht als Bitmaske im Filter (Global fuer Geraete ohne Gruppe).

// groupListURLs sind die Blocklisten einer Gruppe (URLs).
func groupListURLs(g groups.Group, global []string) []string {
	out := slices.Clone(global)
	if g.ListsMode == groups.ListsCustom {
		out = slices.Clone(g.Lists)
	}
	for _, c := range g.Cats {
		if u, ok := filter.GroupCategoryLists[c]; ok && !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	if g.Bypass && !slices.Contains(out, filter.BypassList) { // fremde DoH-Server, VPNs, Proxys
		out = append(out, filter.BypassList)
	}
	return out
}

func listURLs(lists []filter.List) []string {
	out := make([]string, 0, len(lists))
	for _, l := range lists {
		out = append(out, l.URL)
	}
	return out
}

// neededLists: zuerst die global eingeschalteten, dann die zusaetzlichen Listen der Gruppen.
func neededLists(c config, list []groups.Group) []filter.List {
	out := c.activeLists()
	have := map[string]bool{}
	for _, l := range out {
		have[l.URL] = true
	}
	names := map[string]string{}
	for _, l := range c.Lists {
		names[l.URL] = l.Name
	}
	global := listURLs(out)
	for _, g := range list {
		for _, u := range groupListURLs(g, global) {
			if have[u] {
				continue
			}
			have[u] = true
			name := names[u]
			if name == "" {
				name = u
			}
			out = append(out, filter.List{Name: name, URL: u})
		}
	}
	return out
}

// buildPolicies setzt die Maske fuer Geraete ohne Gruppe und die Regeln je Gruppe.
func (m *Module) buildPolicies(lists *filter.Manager, c config, list []groups.Group) {
	global := listURLs(c.activeLists())
	lists.SetGlobal(lists.Mask(global))
	pol := make(map[int64]*dnsserver.Policy, len(list))
	for _, g := range list {
		var allow, block []string
		for _, d := range g.Domains {
			if d.Action == groups.ActionAllow {
				allow = append(allow, d.Domain)
			} else {
				block = append(block, d.Domain)
			}
		}
		p := &dnsserver.Policy{Group: g.Name, Mask: lists.Mask(groupListURLs(g, global)), Allow: filter.NewDomainSet(allow), Block: filter.NewDomainSet(block),
			SafeSearch: g.SafeSearch, YouTube: g.YouTube, Bypass: g.Bypass, Loc: m.location()}
		switch until := holdUntil(g.HoldUntil); g.Hold {
		case groups.HoldBlock:
			p.BlockUntil = until
		case groups.HoldFree:
			p.FreeUntil = until
		}
		for _, s := range g.Schedules {
			if !s.Enabled {
				continue
			}
			start, _ := parseClock(s.Start)
			end, _ := parseClock(s.End)
			rule := dnsserver.TimeRule{Label: s.Label, Start: start, End: end, Off: s.Action == groups.ScheduleOff}
			for _, d := range s.Days {
				if d >= 1 && d <= 7 {
					rule.Days |= 1 << uint(d-1)
				}
			}
			for _, key := range s.Cats {
				if set := filter.GroupCategory(key); set != nil {
					rule.Cats = append(rule.Cats, dnsserver.Category{Key: key, Set: set})
				}
			}
			p.Rules = append(p.Rules, rule)
		}
		for _, key := range g.Cats {
			if set := filter.GroupCategory(key); set != nil {
				p.Cats = append(p.Cats, dnsserver.Category{Key: key, Set: set})
			}
		}
		pol[g.ID] = p
	}
	m.pol.Store(&pol)
}

// holdUntil: Ende eines Sofort-Knopfs ("" = bis zum Aufheben).
func holdUntil(s string) time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return dnsserver.Forever
}

// location ist die Zeitzone der Node (Einstellung des Kerns), sonst die des Containers.
func (m *Module) location() *time.Location {
	if tz := m.core.SettingOr(context.Background(), "node.timezone", ""); tz != "" {
		if loc, err := time.LoadLocation(tz); err == nil {
			return loc
		}
	}
	return time.Local
}

// policy liefert die Regeln der Gruppe eines Clients (nil = keine Gruppe, es gilt die globale Auswahl).
func (m *Module) policy(ip netip.Addr) *dnsserver.Policy {
	match := m.grp.For(ip)
	if match.ID == 0 {
		return nil
	}
	if pol := m.pol.Load(); pol != nil {
		if p := (*pol)[match.ID]; p != nil {
			return p
		}
	}
	return nil
}

// groupsChanged laedt die Gruppen neu. Braucht eine Gruppe eine Blockliste, die noch nicht geladen ist, startet
// der DNS-Dienst neu (laedt sie); sonst gelten die neuen Regeln sofort.
func (m *Module) groupsChanged(ctx context.Context) error {
	if err := m.loadGroups(ctx); err != nil {
		return err
	}
	e := m.running()
	list, err := m.Groups(ctx)
	if err != nil {
		return err
	}
	if e == nil {
		m.syncHintRoute(list, false)
		return nil
	}
	c := m.loadConfig(ctx)
	for _, l := range neededLists(c, list) {
		if e.lists.Mask([]string{l.URL}) == 0 {
			return m.restart(ctx)
		}
	}
	m.buildPolicies(e.lists, c, list)
	m.syncHintRoute(list, true)
	return nil
}

// hintAddrs sind die Adressen der Node fuer die Hinweisseite bei "Internet aus": die feste Adresse aus den
// Einstellungen, sonst die Absenderadresse der Standardroute (UDP-"Verbindung" ohne Pakete), je IPv4 und IPv6.
func hintAddrs(bind string) (v4, v6 net.IP) {
	if ip := net.ParseIP(bind); ip != nil && !ip.IsUnspecified() {
		if ip.To4() != nil {
			return ip.To4(), nil
		}
		return nil, ip
	}
	src := func(network, addr string) net.IP {
		c, err := net.Dial(network, addr)
		if err != nil {
			return nil
		}
		defer c.Close()
		if ua, ok := c.LocalAddr().(*net.UDPAddr); ok && !ua.IP.IsLoopback() && !ua.IP.IsLinkLocalUnicast() {
			return ua.IP
		}
		return nil
	}
	v4 = src("udp4", "192.0.2.1:53") // Dokumentationsnetz: es geht kein Paket raus
	if v4 != nil {
		v4 = v4.To4()
	}
	return v4, src("udp6", "[2001:db8::1]:53")
}
