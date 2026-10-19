package dns64

import (
	"context"
	"net/netip"
	"slices"

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
		p := &dnsserver.Policy{Group: g.Name, Mask: lists.Mask(groupListURLs(g, global)), Allow: filter.NewDomainSet(allow), Block: filter.NewDomainSet(block)}
		for _, key := range g.Cats {
			if set := filter.GroupCategory(key); set != nil {
				p.Cats = append(p.Cats, dnsserver.Category{Key: key, Set: set})
			}
		}
		pol[g.ID] = p
	}
	m.pol.Store(&pol)
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
	if e == nil {
		return nil
	}
	list, err := m.Groups(ctx)
	if err != nil {
		return err
	}
	c := m.loadConfig(ctx)
	for _, l := range neededLists(c, list) {
		if e.lists.Mask([]string{l.URL}) == 0 {
			return m.restart(ctx)
		}
	}
	m.buildPolicies(e.lists, c, list)
	return nil
}
