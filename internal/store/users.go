package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"
)

// Benutzerverwaltung (docs/PLAN-NODE64-BENUTZER.md): zwei Rollen, Sperre, Herkunft (lokal, LDAP, SSO), Gruppen mit
// Rolle und Zuordnungen nach aussen. Nur lokal fuer Node64 (kein Bezug zu ipv64.net). Aenderungen gehen ueber
// LoginChanged an den Cluster (Bereiche accounts und groups).

const (
	RoleAdmin = "admin" // alles
	RoleRead  = "read"  // nur lesen

	SourceLocal = "local"
	SourceLDAP  = "ldap"
	SourceOIDC  = "oidc"
)

// ValidRole: admin oder read.
func ValidRole(r string) bool { return r == RoleAdmin || r == RoleRead }

// IsAdmin: wirksame Rolle ist Administrator.
func IsAdmin(role string) bool { return role == RoleAdmin }

// splitList: Komma-Liste ohne leere Teile.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// joinList: Liste sortiert und ohne Doppelte als Komma-Liste.
func joinList(l []string) string {
	seen := map[string]bool{}
	var out []string
	for _, p := range l {
		if p = strings.TrimSpace(p); p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// NewUser sind die Angaben fuer CreateUserWith (UID leer = zufaellig; Role/Source leer = admin/local).
type NewUser struct {
	UID          string
	Username     string
	PasswordHash string // leer bei LDAP/SSO
	Lang         string
	Timezone     string
	Role         string
	Source       string
	Email        string
	GroupUIDs    []string
	ExtGroupUIDs []string
	MustChange   bool
}

// CreateUserWith legt einen Benutzer mit Rolle, Herkunft und Gruppen an (Benutzerverwaltung, Anlage beim ersten
// Anmelden ueber LDAP/SSO mit fester UID).
func (s *Store) CreateUserWith(ctx context.Context, n NewUser) (*User, error) {
	if n.UID == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		n.UID = hex.EncodeToString(b)
	}
	if !ValidRole(n.Role) {
		n.Role = RoleAdmin
	}
	if n.Source == "" {
		n.Source = SourceLocal
	}
	res, err := s.w.ExecContext(ctx, `INSERT INTO users (uid, username, password_hash, lang, timezone, created_at, role, source, email, group_uids, ext_group_uids, must_change)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		n.UID, n.Username, n.PasswordHash, n.Lang, n.Timezone, Now(), n.Role, n.Source, n.Email, joinList(n.GroupUIDs), joinList(n.ExtGroupUIDs), n.MustChange)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	s.userChanged(ctx, id)
	return s.UserByID(ctx, id)
}

// UserByUID liefert einen Benutzer ueber seine Cluster-Kennung (nil = gibt es nicht).
func (s *Store) UserByUID(ctx context.Context, uid string) (*User, error) {
	u, err := s.withTOTP(scanUser(s.r.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE uid = ?`, uid)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

// UserAdmin sind die Felder, die ein Administrator an einem Benutzer aendert.
type UserAdmin struct {
	Role      string
	Disabled  bool
	Email     string
	GroupUIDs []string
}

// UpdateUserAdmin aendert Rolle, Sperre, E-Mail und Gruppen. Die Schutzregel „letzter lokaler Administrator“ prueft
// der Aufrufer (ActiveLocalAdmins).
func (s *Store) UpdateUserAdmin(ctx context.Context, id int64, a UserAdmin) error {
	if !ValidRole(a.Role) {
		return errors.New("invalid role")
	}
	_, err := s.w.ExecContext(ctx, `UPDATE users SET role = ?, disabled = ?, email = ?, group_uids = ? WHERE id = ?`,
		a.Role, a.Disabled, strings.TrimSpace(a.Email), joinList(a.GroupUIDs), id)
	if err == nil {
		s.userChanged(ctx, id)
	}
	return err
}

// SetUserExtGroups merkt die beim Anmelden ueber LDAP/SSO ermittelten Gruppen (nur bei Aenderung, dann Cluster).
func (s *Store) SetUserExtGroups(ctx context.Context, id int64, groups []string) error {
	v := joinList(groups)
	res, err := s.w.ExecContext(ctx, `UPDATE users SET ext_group_uids = ? WHERE id = ? AND ext_group_uids <> ?`, v, id, v)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.userChanged(ctx, id)
	}
	return nil
}

// SetUserMustChange setzt bzw. loescht „Passwort beim naechsten Anmelden setzen“.
func (s *Store) SetUserMustChange(ctx context.Context, id int64, on bool) error {
	_, err := s.w.ExecContext(ctx, `UPDATE users SET must_change = ? WHERE id = ?`, on, id)
	if err == nil {
		s.userChanged(ctx, id)
	}
	return err
}

// EffectiveRole: hoechste Rolle aus eigener Rolle und allen Gruppen (von Hand und von LDAP/SSO).
func (s *Store) EffectiveRole(ctx context.Context, u *User) string {
	if u == nil {
		return ""
	}
	if IsAdmin(u.Role) {
		return RoleAdmin
	}
	uids := append(append([]string{}, u.GroupUIDs...), u.ExtGroupUIDs...)
	if len(uids) > 0 {
		groups, _ := s.Groups(ctx)
		for _, g := range groups {
			for _, id := range uids {
				if g.UID == id && IsAdmin(g.Role) {
					return RoleAdmin
				}
			}
		}
	}
	return RoleRead
}

// ActiveLocalAdmins zaehlt die nicht gesperrten lokalen Benutzer mit wirksamer Rolle Administrator (ohne exclude).
// Schutzregel: davon muss immer mindestens einer bleiben (LDAP/SSO koennen ausfallen).
func (s *Store) ActiveLocalAdmins(ctx context.Context, exclude int64) (int, error) {
	users, err := s.Users(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range users {
		if u.ID != exclude && !u.Disabled && u.Source == SourceLocal && s.EffectiveRole(ctx, u) == RoleAdmin {
			n++
		}
	}
	return n, nil
}

// ---------------------------------------------------------------- Gruppen

// Group ist eine Benutzergruppe mit Rolle; LDAPGroups/OIDCGroups ordnen Gruppen von aussen zu.
type Group struct {
	UID         string
	Name        string
	Role        string
	Description string
	LDAPGroups  []string // DNs bzw. Namen der Verzeichnisgruppen (Vergleich ohne Gross/klein)
	OIDCGroups  []string // Gruppennamen aus dem SSO-Claim
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

const groupCols = `uid, name, role, description, ldap_groups, oidc_groups, created_at, updated_at`

func scanGroup(row interface{ Scan(...any) error }) (*Group, error) {
	var g Group
	var ldap, oidc, created, updated string
	if err := row.Scan(&g.UID, &g.Name, &g.Role, &g.Description, &ldap, &oidc, &created, &updated); err != nil {
		return nil, err
	}
	g.LDAPGroups, g.OIDCGroups = splitLines(ldap), splitLines(oidc)
	g.CreatedAt, g.UpdatedAt = ParseTime(created), ParseTime(updated)
	return &g, nil
}

// splitLines: Zeilen ohne leere (DNs enthalten Kommas, daher Zeilen statt Komma-Liste).
func splitLines(s string) []string {
	var out []string
	for _, p := range strings.Split(s, "\n") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func joinLines(l []string) string {
	var out []string
	for _, p := range l {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "\n")
}

// Groups liefert alle Gruppen nach Name.
func (s *Store) Groups(ctx context.Context) ([]*Group, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+groupCols+` FROM user_groups ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GroupByUID liefert eine Gruppe (nil = gibt es nicht).
func (s *Store) GroupByUID(ctx context.Context, uid string) (*Group, error) {
	g, err := scanGroup(s.r.QueryRowContext(ctx, `SELECT `+groupCols+` FROM user_groups WHERE uid = ?`, uid))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return g, err
}

// ErrGroupName: Name leer oder schon vergeben.
var ErrGroupName = errors.New("group name empty or taken")

// SaveGroup legt eine Gruppe an (UID leer) oder aendert sie; meldet sie an den Cluster.
func (s *Store) SaveGroup(ctx context.Context, g *Group) error {
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" {
		return ErrGroupName
	}
	if !ValidRole(g.Role) {
		g.Role = RoleRead
	}
	now := Now()
	if g.UID == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		g.UID = hex.EncodeToString(b)
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO user_groups (uid, name, role, description, ldap_groups, oidc_groups, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(uid) DO UPDATE SET name = excluded.name, role = excluded.role, description = excluded.description,
		ldap_groups = excluded.ldap_groups, oidc_groups = excluded.oidc_groups, updated_at = excluded.updated_at`,
		g.UID, g.Name, g.Role, strings.TrimSpace(g.Description), joinLines(g.LDAPGroups), joinLines(g.OIDCGroups), now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrGroupName
		}
		return err
	}
	s.LoginChanged(ctx, "groups", g.UID, false)
	return nil
}

// DeleteGroup loescht eine Gruppe; Benutzer, die sie noch nennen, uebergehen sie (false = gab es nicht).
func (s *Store) DeleteGroup(ctx context.Context, uid string) (bool, error) {
	res, err := s.w.ExecContext(ctx, `DELETE FROM user_groups WHERE uid = ?`, uid)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	s.LoginChanged(ctx, "groups", uid, true)
	return true, nil
}
