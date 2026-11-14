package usercluster

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/ipv64net/node64/internal/store"
)

// Gruppen im Cluster (Bereich groups, Kennung user_groups.uid). Die juengere Aenderung gewinnt als Ganzes. Die
// Mitgliedschaften stehen am Benutzer (accounts: group_uids, ext_group_uids); eine geloeschte Gruppe wird dort einfach
// uebergangen.
//
// Gleicher Name, andere Kennung (zwei Nodes legen „Admins“ getrennt an): es gilt die kleinere Kennung. Die Node mit der
// groesseren uebernimmt sie an Ort und Stelle (Inhalt der kleineren) und biegt die Gruppen ihrer Benutzer um, ohne
// diese Benutzer neu zu melden. Statt eines Loeschvermerks liefert sie fuer die alte Kennung eine Umleitung (Into);
// wer die alte Kennung noch hat, biegt ebenso um. So loescht keine dritte Node eine Gruppe samt Mitgliedschaften.
// Die Umleitungen stehen in users.group_aliases (alte -> neue Kennung) und gelten auch fuer Benutzer, die mit einer
// alten Kennung eintreffen.

const (
	setGroupAliases = "users.group_aliases"
	maxAliases      = 500
)

// clusterGroup ist eine Gruppe im Cluster. Into: die Kennung ist in dieser Gruppe aufgegangen (sonst leer).
type clusterGroup struct {
	Name        string   `json:"name,omitempty"`
	Role        string   `json:"role,omitempty"`
	Description string   `json:"description,omitempty"`
	LDAPGroups  []string `json:"ldap_groups,omitempty"`
	OIDCGroups  []string `json:"oidc_groups,omitempty"`
	CreatedAt   string   `json:"created_at,omitempty"`
	Into        string   `json:"into,omitempty"`
}

// aliases: umgeleitete Gruppen-Kennungen (alte -> neue).
func (c *Cluster) aliases(ctx context.Context) map[string]string {
	m := map[string]string{}
	_ = json.Unmarshal([]byte(c.st.SettingOr(ctx, setGroupAliases, "{}")), &m)
	return m
}

// resolve folgt den Umleitungen (hoechstens 10 Schritte).
func resolve(m map[string]string, uid string) string {
	for i := 0; i < 10; i++ {
		to, ok := m[uid]
		if !ok || to == uid {
			break
		}
		uid = to
	}
	return uid
}

func (c *Cluster) addAlias(ctx context.Context, from, to string) error {
	m := c.aliases(ctx)
	m[from] = to
	for k, v := range m { // Ketten kurz halten
		if v == from {
			m[k] = to
		}
	}
	for k := range m { // Obergrenze: beliebige alte Umleitungen fallen weg
		if len(m) <= maxAliases {
			break
		}
		if k != from {
			delete(m, k)
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return c.st.SetSetting(ctx, setGroupAliases, string(b))
}

// groupRefs: Gruppen-Kennungen eines Benutzers gueltig, umgeleitet, sortiert und ohne Doppelte.
func groupRefs(l []string, alias map[string]string) []string {
	out := make([]string, 0, len(l))
	for _, x := range l {
		if uidRe.MatchString(x) {
			out = append(out, resolve(alias, x))
		}
	}
	return normList(out)
}

// remap ersetzt from durch to in einer Liste von Gruppen-Kennungen.
func remap(l []string, from, to string) []string {
	out := make([]string, 0, len(l))
	for _, x := range l {
		if x == from {
			x = to
		}
		out = append(out, x)
	}
	return normList(out)
}

// getGroup liefert eine Gruppe bzw. die Umleitung einer aufgegangenen Kennung.
func (c *Cluster) getGroup(ctx context.Context, uid string) (json.RawMessage, bool, error) {
	g, err := c.st.GroupByUID(ctx, uid)
	if err != nil {
		return nil, false, err
	}
	if g == nil {
		if to := resolve(c.aliases(ctx), uid); to != uid {
			b, err := json.Marshal(clusterGroup{Into: to})
			return b, err == nil, err
		}
		return nil, false, nil
	}
	b, err := json.Marshal(clusterGroup{Name: g.Name, Role: g.Role, Description: g.Description, LDAPGroups: g.LDAPGroups, OIDCGroups: g.OIDCGroups,
		CreatedAt: store.FormatTime(g.CreatedAt)})
	return b, err == nil, err
}

// keepLastGroup: die Gruppenaenderung naehme der Node den letzten aktiven lokalen Administrator (sie bleibt).
func (c *Cluster) keepLastGroup(ctx context.Context, name string) error {
	c.log.Warn("cluster: group change would leave this node without an active local administrator, kept", "group", name)
	c.audit(ctx, "user.cluster.keep_last", name, "group")
	return ErrLastAdmin
}

// applyGroup uebernimmt eine Gruppe einer anderen Node.
func (c *Cluster) applyGroup(ctx context.Context, uid string, data json.RawMessage, deleted bool) error {
	cur, err := c.st.GroupByUID(ctx, uid)
	if err != nil {
		return err
	}
	if deleted {
		if cur == nil {
			return nil
		}
		if lose, err := c.losesLastAdmin(ctx, nil, func(r map[string]string) { delete(r, uid) }); err != nil {
			return err
		} else if lose {
			return c.keepLastGroup(ctx, cur.Name)
		}
		if _, err := c.st.DeleteGroup(ctx, uid); err != nil {
			return err
		}
		c.audit(ctx, "group.cluster.delete", cur.Name, "")
		return nil
	}
	var in clusterGroup
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	if in.Into != "" { // aufgegangen: hier ebenso umbiegen
		if !uidRe.MatchString(in.Into) || in.Into == uid {
			return errFormat
		}
		return c.redirectGroup(ctx, uid, in.Into)
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 {
		return errFormat
	}
	if !store.ValidRole(in.Role) {
		in.Role = store.RoleRead // unbekannte (neuere) Rolle: die kleinste
	}
	groups, err := c.st.Groups(ctx)
	if err != nil {
		return err
	}
	var other *store.Group
	for _, g := range groups {
		if g.UID != uid && strings.EqualFold(g.Name, in.Name) {
			other = g
		}
	}
	if other != nil && other.UID < uid { // hier gilt die gleichnamige mit der kleineren Kennung: uid geht in ihr auf
		return c.redirectGroup(ctx, uid, other.UID)
	}
	from := "" // die gleichnamige Gruppe hier (groessere Kennung) geht in uid auf
	if other != nil {
		from = other.UID
	}
	if lose, err := c.losesLastAdmin(ctx, func(u *store.User) *store.User {
		if from != "" {
			u.GroupUIDs, u.ExtGroupUIDs = remap(u.GroupUIDs, from, uid), remap(u.ExtGroupUIDs, from, uid)
		}
		return u
	}, func(r map[string]string) {
		delete(r, from)
		r[uid] = in.Role
	}); err != nil {
		return err
	} else if lose {
		return c.keepLastGroup(ctx, in.Name)
	}
	created := in.CreatedAt
	if store.ParseTime(created).IsZero() {
		created = store.Now()
	}
	tx, err := c.st.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if from != "" {
		q := `UPDATE user_groups SET uid = ? WHERE uid = ?`
		args := []any{uid, from}
		if cur != nil {
			q, args = `DELETE FROM user_groups WHERE uid = ?`, []any{from}
		}
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return err
		}
		if err := rewriteRefs(ctx, tx, from, uid); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_groups (uid, name, role, description, ldap_groups, oidc_groups, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(uid) DO UPDATE SET name = excluded.name, role = excluded.role, description = excluded.description,
		ldap_groups = excluded.ldap_groups, oidc_groups = excluded.oidc_groups, updated_at = excluded.updated_at`,
		uid, in.Name, in.Role, strings.TrimSpace(in.Description), strings.Join(in.LDAPGroups, "\n"), strings.Join(in.OIDCGroups, "\n"), created, store.Now()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	c.st.LoginChanged(ctx, ItemGroups, uid, false)
	switch {
	case from != "":
		if err := c.addAlias(ctx, from, uid); err != nil {
			return err
		}
		c.audit(ctx, "group.cluster.merge", in.Name, "uid="+short(from)+"->"+short(uid))
	case cur == nil:
		c.audit(ctx, "group.cluster.create", in.Name, "role="+in.Role)
	default:
		c.audit(ctx, "group.cluster.update", in.Name, "role="+in.Role)
	}
	return nil
}

// redirectGroup: die Gruppe from (falls hier vorhanden) geht in to auf - an Ort und Stelle umbenannt, wenn es to hier
// noch nicht gibt (den Inhalt von to bringt dessen eigener Eintrag), sonst entfernt; die Benutzer zeigen danach auf to.
// Keine Meldung an den Cluster: jede Node biegt selbst um (getGroup liefert die Umleitung).
func (c *Cluster) redirectGroup(ctx context.Context, from, to string) error {
	cur, err := c.st.GroupByUID(ctx, from)
	if err != nil {
		return err
	}
	target, err := c.st.GroupByUID(ctx, to)
	if err != nil {
		return err
	}
	name := to
	if cur != nil {
		name = cur.Name
	}
	if lose, err := c.losesLastAdmin(ctx, func(u *store.User) *store.User {
		u.GroupUIDs, u.ExtGroupUIDs = remap(u.GroupUIDs, from, to), remap(u.ExtGroupUIDs, from, to)
		return u
	}, func(r map[string]string) {
		if cur != nil && target == nil {
			r[to] = cur.Role
		}
		delete(r, from)
	}); err != nil {
		return err
	} else if lose {
		return c.keepLastGroup(ctx, name)
	}
	tx, err := c.st.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if cur != nil {
		q := `UPDATE user_groups SET uid = ? WHERE uid = ?`
		args := []any{to, from}
		if target != nil {
			q, args = `DELETE FROM user_groups WHERE uid = ?`, []any{from}
		}
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return err
		}
	}
	if err := rewriteRefs(ctx, tx, from, to); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := c.addAlias(ctx, from, to); err != nil {
		return err
	}
	if cur != nil {
		c.audit(ctx, "group.cluster.merge", name, "uid="+short(from)+"->"+short(to))
	}
	return nil
}

// rewriteRefs biegt die Gruppen der Benutzer von from auf to um (ohne Meldung an den Cluster).
func rewriteRefs(ctx context.Context, tx *sql.Tx, from, to string) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, group_uids, ext_group_uids FROM users WHERE instr(group_uids, ?) > 0 OR instr(ext_group_uids, ?) > 0`, from, from)
	if err != nil {
		return err
	}
	type ref struct {
		id         int64
		groups, ex string
	}
	var list []ref
	for rows.Next() {
		var r ref
		if err := rows.Scan(&r.id, &r.groups, &r.ex); err != nil {
			rows.Close()
			return err
		}
		list = append(list, r)
	}
	rows.Close()
	for _, r := range list {
		g := strings.Join(remap(splitList(r.groups), from, to), ",")
		e := strings.Join(remap(splitList(r.ex), from, to), ",")
		if _, err := tx.ExecContext(ctx, `UPDATE users SET group_uids = ?, ext_group_uids = ? WHERE id = ?`, g, e, r.id); err != nil {
			return err
		}
	}
	return nil
}
