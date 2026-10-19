package dns64

import (
	"context"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/dns64/dnsserver"
	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/groups"
)

// Geraetegruppen in node64.db (Modul-Scope); der Resolver (m.grp) haelt den Stand fuer die Anfragen.

// Groups liefert alle Gruppen mit Mitgliedern, nach Position.
func (m *Module) Groups(ctx context.Context) ([]groups.Group, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT id, name, position, lists_mode, lists, cats, safesearch, youtube, bypass FROM dns64_groups ORDER BY position, id`)
	if err != nil {
		return nil, err
	}
	out := []groups.Group{}
	idx := map[int64]int{}
	for rows.Next() {
		var g groups.Group
		var lists, cats string
		if err := rows.Scan(&g.ID, &g.Name, &g.Position, &g.ListsMode, &lists, &cats, &g.SafeSearch, &g.YouTube, &g.Bypass); err != nil {
			rows.Close()
			return nil, err
		}
		g.Members, g.Domains, g.Lists, g.Cats = []groups.Member{}, []groups.Domain{}, splitLines(lists), splitList(cats)
		if g.Lists == nil {
			g.Lists = []string{} // JSON: [] statt null
		}
		idx[g.ID] = len(out)
		out = append(out, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	mrows, err := m.core.Reader().QueryContext(ctx, `SELECT id, group_id, kind, value, label FROM dns64_group_members ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var x groups.Member
		if err := mrows.Scan(&x.ID, &x.GroupID, &x.Kind, &x.Value, &x.Label); err != nil {
			return nil, err
		}
		if i, ok := idx[x.GroupID]; ok {
			out[i].Members = append(out[i].Members, x)
		}
	}
	if err := mrows.Err(); err != nil {
		return nil, err
	}
	drows, err := m.core.Reader().QueryContext(ctx, `SELECT id, group_id, domain, action FROM dns64_group_domains ORDER BY action, domain`)
	if err != nil {
		return nil, err
	}
	defer drows.Close()
	for drows.Next() {
		var x groups.Domain
		if err := drows.Scan(&x.ID, &x.GroupID, &x.Domain, &x.Action); err != nil {
			return nil, err
		}
		if i, ok := idx[x.GroupID]; ok {
			out[i].Domains = append(out[i].Domains, x)
		}
	}
	return out, drows.Err()
}

func splitList(s string) []string {
	out := []string{}
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// SetGroupRules setzt die Regeln einer Gruppe. Lists sind URLs bekannter Listen (Vorlagen und eigene);
// unbekannte fallen weg.
func (m *Module) SetGroupRules(ctx context.Context, id int64, in groups.Rules) error {
	mode, lists, cats := in.ListsMode, in.Lists, in.Cats
	switch in.YouTube {
	case dnsserver.YouTubeModerate, dnsserver.YouTubeOff:
	default:
		in.YouTube = dnsserver.YouTubeStrict
	}
	if mode != groups.ListsCustom {
		mode = groups.ListsGlobal
	}
	known := map[string]bool{}
	for _, l := range m.loadConfig(ctx).Lists {
		known[l.URL] = true
	}
	var keep []string
	seen := map[string]bool{}
	for _, u := range lists {
		if u = strings.TrimSpace(u); known[u] && !seen[u] {
			seen[u] = true
			keep = append(keep, u)
		}
	}
	var catKeep []string
	for _, c := range filter.GroupCategories {
		if slices.Contains(cats, c) {
			catKeep = append(catKeep, c)
		}
	}
	res, err := m.core.Writer().ExecContext(ctx, `UPDATE dns64_groups SET lists_mode = ?, lists = ?, cats = ?, safesearch = ?, youtube = ?, bypass = ? WHERE id = ?`,
		mode, strings.Join(keep, "\n"), strings.Join(catKeep, ","), in.SafeSearch, in.YouTube, in.Bypass, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return m.groupsChanged(ctx)
}

// AddGroupDomain legt eine Freigabe oder Sperre der Gruppe an (ersetzt eine vorhandene fuer dieselbe Domain).
func (m *Module) AddGroupDomain(ctx context.Context, x groups.Domain) (groups.Domain, error) {
	d, ok := filter.NormalizeDomain(x.Domain)
	if !ok || (x.Action != groups.ActionAllow && x.Action != groups.ActionBlock) {
		return x, errCfg("err_group_domain")
	}
	x.Domain = d
	var n int
	if err := m.core.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM dns64_groups WHERE id = ?`, x.GroupID).Scan(&n); err != nil {
		return x, err
	}
	if n == 0 {
		return x, errNotFound
	}
	if _, err := m.core.Writer().ExecContext(ctx, `DELETE FROM dns64_group_domains WHERE group_id = ? AND domain = ?`, x.GroupID, x.Domain); err != nil {
		return x, err
	}
	res, err := m.core.Writer().ExecContext(ctx, `INSERT INTO dns64_group_domains (group_id, domain, action, created_at) VALUES (?, ?, ?, ?)`,
		x.GroupID, x.Domain, x.Action, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return x, err
	}
	x.ID, _ = res.LastInsertId()
	return x, m.groupsChanged(ctx)
}

// RemoveGroupDomain loescht eine Freigabe oder Sperre der Gruppe.
func (m *Module) RemoveGroupDomain(ctx context.Context, id int64) (groups.Domain, error) {
	var x groups.Domain
	if err := m.core.Reader().QueryRowContext(ctx, `SELECT id, group_id, domain, action FROM dns64_group_domains WHERE id = ?`, id).
		Scan(&x.ID, &x.GroupID, &x.Domain, &x.Action); err != nil {
		return x, errNotFound
	}
	if _, err := m.core.Writer().ExecContext(ctx, `DELETE FROM dns64_group_domains WHERE id = ?`, id); err != nil {
		return x, err
	}
	return x, m.groupsChanged(ctx)
}

// loadGroups gibt den Stand an den Resolver.
func (m *Module) loadGroups(ctx context.Context) error {
	list, err := m.Groups(ctx)
	if err != nil {
		return err
	}
	m.grp.Set(list)
	return nil
}

func groupName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > 40 {
		return "", errCfg("err_group_name")
	}
	return s, nil
}

// AddGroup legt eine Gruppe an (hinten in der Reihenfolge).
func (m *Module) AddGroup(ctx context.Context, name string) (groups.Group, error) {
	name, err := groupName(name)
	if err != nil {
		return groups.Group{}, err
	}
	var pos int
	_ = m.core.Reader().QueryRowContext(ctx, `SELECT COALESCE(MAX(position), 0) + 1 FROM dns64_groups`).Scan(&pos)
	res, err := m.core.Writer().ExecContext(ctx, `INSERT INTO dns64_groups (name, position, created_at) VALUES (?, ?, ?)`, name, pos, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return groups.Group{}, errCfg("err_group_dup")
		}
		return groups.Group{}, err
	}
	id, _ := res.LastInsertId()
	return groups.Group{ID: id, Name: name, Position: pos, Members: []groups.Member{}, ListsMode: groups.ListsGlobal, Lists: []string{}, Cats: []string{}, Domains: []groups.Domain{}}, m.groupsChanged(ctx)
}

// RenameGroup benennt eine Gruppe um.
func (m *Module) RenameGroup(ctx context.Context, id int64, name string) error {
	name, err := groupName(name)
	if err != nil {
		return err
	}
	res, err := m.core.Writer().ExecContext(ctx, `UPDATE dns64_groups SET name = ? WHERE id = ?`, name, id)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return errCfg("err_group_dup")
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return m.groupsChanged(ctx)
}

// DeleteGroup loescht eine Gruppe samt Mitgliedern.
func (m *Module) DeleteGroup(ctx context.Context, id int64) error {
	res, err := m.core.Writer().ExecContext(ctx, `DELETE FROM dns64_groups WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	if _, err := m.core.Writer().ExecContext(ctx, `DELETE FROM dns64_group_members WHERE group_id = ?`, id); err != nil {
		return err
	}
	if _, err := m.core.Writer().ExecContext(ctx, `DELETE FROM dns64_group_domains WHERE group_id = ?`, id); err != nil {
		return err
	}
	return m.groupsChanged(ctx)
}

// MoveGroup verschiebt eine Gruppe in der Reihenfolge (up = nach vorn, also hoeherer Vorrang).
func (m *Module) MoveGroup(ctx context.Context, id int64, up bool) error {
	list, err := m.Groups(ctx)
	if err != nil {
		return err
	}
	i := -1
	for k, g := range list {
		if g.ID == id {
			i = k
		}
	}
	if i < 0 {
		return errNotFound
	}
	j := i + 1
	if up {
		j = i - 1
	}
	if j < 0 || j >= len(list) {
		return nil
	}
	list[i], list[j] = list[j], list[i]
	for k, g := range list {
		if _, err := m.core.Writer().ExecContext(ctx, `UPDATE dns64_groups SET position = ? WHERE id = ?`, k+1, g.ID); err != nil {
			return err
		}
	}
	return m.loadGroups(ctx)
}

// AddMember ordnet ein Geraet (MAC, IP) bzw. Netz einer Gruppe zu. Gehoert es schon zu einer anderen Gruppe,
// wechselt es dorthin (ein Geraet, eine Gruppe).
func (m *Module) AddMember(ctx context.Context, x groups.Member) (groups.Member, error) {
	if !groups.Normalize(&x) {
		return x, errCfg("err_member")
	}
	if utf8.RuneCountInString(x.Label) > 60 {
		return x, errCfg("err_member")
	}
	var n int
	if err := m.core.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM dns64_groups WHERE id = ?`, x.GroupID).Scan(&n); err != nil {
		return x, err
	}
	if n == 0 {
		return x, errNotFound
	}
	if _, err := m.core.Writer().ExecContext(ctx, `DELETE FROM dns64_group_members WHERE kind = ? AND value = ?`, x.Kind, x.Value); err != nil {
		return x, err
	}
	res, err := m.core.Writer().ExecContext(ctx, `INSERT INTO dns64_group_members (group_id, kind, value, label, created_at) VALUES (?, ?, ?, ?, ?)`,
		x.GroupID, x.Kind, x.Value, x.Label, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return x, err
	}
	x.ID, _ = res.LastInsertId()
	return x, m.loadGroups(ctx)
}

// RemoveMember nimmt ein Mitglied aus seiner Gruppe.
func (m *Module) RemoveMember(ctx context.Context, id int64) (groups.Member, error) {
	var x groups.Member
	err := m.core.Reader().QueryRowContext(ctx, `SELECT id, group_id, kind, value, label FROM dns64_group_members WHERE id = ?`, id).
		Scan(&x.ID, &x.GroupID, &x.Kind, &x.Value, &x.Label)
	if err != nil {
		return x, errNotFound
	}
	if _, err := m.core.Writer().ExecContext(ctx, `DELETE FROM dns64_group_members WHERE id = ?`, id); err != nil {
		return x, err
	}
	return x, m.loadGroups(ctx)
}

// UnassignDevice nimmt ein Geraet (MAC und/oder IP) aus seiner Gruppe.
func (m *Module) UnassignDevice(ctx context.Context, mac, ip string) error {
	for _, x := range []groups.Member{{Kind: groups.KindMAC, Value: mac}, {Kind: groups.KindIP, Value: ip}} {
		if x.Value == "" || !groups.Normalize(&x) {
			continue
		}
		if _, err := m.core.Writer().ExecContext(ctx, `DELETE FROM dns64_group_members WHERE kind = ? AND value = ?`, x.Kind, x.Value); err != nil {
			return err
		}
	}
	return m.loadGroups(ctx)
}
