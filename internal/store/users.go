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

// NormList: Liste getrimmt, sortiert und ohne Leere und Doppelte (nie nil). Eine Fassung fuer Store und Cluster.
func NormList(l []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, p := range l {
		if p = strings.TrimSpace(p); p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// joinList: NormList als Komma-Liste.
func joinList(l []string) string { return strings.Join(NormList(l), ",") }

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
// Anmelden ueber LDAP/SSO mit fester UID; mitgegebene Gruppen von dort gelten als eben geprueft).
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
	checked := ""
	if len(n.ExtGroupUIDs) > 0 {
		checked = Now()
	}
	now := Now()
	res, err := s.w.ExecContext(ctx, `INSERT INTO users (uid, username, password_hash, lang, timezone, created_at, role, source, email, group_uids, ext_group_uids, must_change, ext_checked_at,
		admin_at, password_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		n.UID, n.Username, n.PasswordHash, n.Lang, n.Timezone, now, n.Role, n.Source, n.Email, joinList(n.GroupUIDs), joinList(n.ExtGroupUIDs), n.MustChange, checked,
		now, now)
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

// UpdateUserAdmin aendert Rolle, Sperre, E-Mail und Gruppen (auch admin_at fuer den Cluster). Die Schutzregel „letzter
// lokaler Administrator“ prueft der Aufrufer (GuardLastAdmin).
func (s *Store) UpdateUserAdmin(ctx context.Context, id int64, a UserAdmin) error {
	if !ValidRole(a.Role) {
		return errors.New("invalid role")
	}
	_, err := s.w.ExecContext(ctx, `UPDATE users SET role = ?, disabled = ?, email = ?, group_uids = ?, admin_at = ? WHERE id = ?`,
		a.Role, a.Disabled, strings.TrimSpace(a.Email), joinList(a.GroupUIDs), Now(), id)
	if err == nil {
		s.userChanged(ctx, id)
	}
	return err
}

// Gruppen aus LDAP/SSO zaehlen nur, solange ihre letzte Pruefung (ext_checked_at) frisch ist (EffectiveRole); an den
// Cluster geht eine Pruefung ohne Aenderung hoechstens einmal je extNotifyEvery.
const (
	ExtMaxAgeLDAP  = 24 * time.Hour
	ExtMaxAgeOIDC  = 7 * 24 * time.Hour
	extNotifyEvery = time.Hour
)

// SetUserExtGroups merkt die beim Anmelden bzw. Abgleich ueber LDAP/SSO ermittelten Gruppen und den Zeitpunkt der
// Pruefung (bei jedem Aufruf, auch mit leerer Liste). An den Cluster nur bei geaenderten Gruppen oder wenn die
// gespeicherte Pruefung aelter als extNotifyEvery ist (Drossel).
func (s *Store) SetUserExtGroups(ctx context.Context, id int64, groups []string) error {
	v, now := joinList(groups), time.Now()
	var old, at string
	if err := s.w.QueryRowContext(ctx, `SELECT ext_group_uids, ext_checked_at FROM users WHERE id = ?`, id).Scan(&old, &at); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if _, err := s.w.ExecContext(ctx, `UPDATE users SET ext_group_uids = ?, ext_checked_at = ? WHERE id = ?`, v, FormatTime(now), id); err != nil {
		return err
	}
	if old != v || now.Sub(ParseTime(at)) >= extNotifyEvery {
		s.userChanged(ctx, id)
	}
	return nil
}

// SetUserMustChange setzt bzw. loescht „Passwort beim naechsten Anmelden setzen“ (auch password_at fuer den Cluster).
func (s *Store) SetUserMustChange(ctx context.Context, id int64, on bool) error {
	_, err := s.w.ExecContext(ctx, `UPDATE users SET must_change = ?, password_at = ? WHERE id = ?`, on, Now(), id)
	if err == nil {
		s.userChanged(ctx, id)
	}
	return err
}

// extGroups: die Gruppen aus LDAP/SSO, wenn ihre letzte Pruefung frisch ist (LDAP ExtMaxAgeLDAP, SSO ExtMaxAgeOIDC);
// sonst keine. Lokale Benutzer bekommen sie nur ueber ein verknuepftes SSO-Konto: wie SSO.
func (u *User) extGroups() []string {
	age := time.Since(u.ExtCheckedAt)
	switch {
	case u.Source == SourceLDAP && age >= ExtMaxAgeLDAP, u.Source != SourceLDAP && age >= ExtMaxAgeOIDC:
		return nil
	}
	return u.ExtGroupUIDs
}

// RoleIn: wirksame Rolle bei den Gruppenrollen roles (Kennung -> Rolle; GroupRoles), also die hoechste aus eigener
// Rolle, den Gruppen von Hand und den frischen Gruppen aus LDAP/SSO. Gleiche Regel wie EffectiveRole, ohne Datenbank.
func RoleIn(u *User, roles map[string]string) string {
	if u == nil {
		return ""
	}
	if IsAdmin(u.Role) {
		return RoleAdmin
	}
	for _, l := range [][]string{u.GroupUIDs, u.extGroups()} {
		for _, id := range l {
			if IsAdmin(roles[id]) {
				return RoleAdmin
			}
		}
	}
	return RoleRead
}

// GroupRoles: Rolle je Gruppe (Kennung -> Rolle).
func (s *Store) GroupRoles(ctx context.Context) (map[string]string, error) {
	groups, err := s.Groups(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(groups))
	for _, g := range groups {
		out[g.UID] = g.Role
	}
	return out, nil
}

// EffectiveRole: hoechste Rolle aus eigener Rolle und allen Gruppen (von Hand und - solange frisch - von LDAP/SSO).
func (s *Store) EffectiveRole(ctx context.Context, u *User) string {
	if u == nil {
		return ""
	}
	if IsAdmin(u.Role) || len(u.GroupUIDs)+len(u.ExtGroupUIDs) == 0 {
		return RoleIn(u, nil)
	}
	roles, _ := s.GroupRoles(ctx)
	return RoleIn(u, roles)
}

// ActiveLocalAdmin: zaehlt fuer die Schutzregel „letzter aktiver lokaler Administrator“ - nicht gesperrt, Herkunft
// lokal, wirksame Rolle Administrator (eigene Rolle oder Gruppe). LDAP/SSO-Administratoren zaehlen nicht (das
// Verzeichnis kann ausfallen).
func ActiveLocalAdmin(u *User, roles map[string]string) bool {
	return u != nil && !u.Disabled && u.Source == SourceLocal && RoleIn(u, roles) == RoleAdmin
}

// ErrLastAdmin: die Aenderung naehme der Node den letzten aktiven lokalen Administrator.
var ErrLastAdmin = errors.New("the last active local administrator cannot be disabled, demoted or deleted")

// AdminChange beschreibt eine gedachte Aenderung fuer GuardLastAdmin: User aendert eine Kopie jedes Benutzers (nil
// zurueck = geloescht), Roles die Gruppenrollen (Kennung -> Rolle, Eintrag geloescht = Gruppe weg). nil = unveraendert.
type AdminChange struct {
	User  func(u *User) *User
	Roles func(roles map[string]string)
}

// GuardLastAdmin ist die eine Fassung der Schutzregel „letzter aktiver lokaler Administrator“ (Oberflaeche, API und
// Cluster): write laeuft nur, wenn die beschriebene Aenderung der Node nicht ihren letzten aktiven lokalen
// Administrator nimmt (vorher mindestens einer, danach keiner); sonst ErrLastAdmin und nichts wird geschrieben. Gibt es
// schon keinen mehr, greift die Regel nicht. Pruefen und Schreiben laufen unter einer Sperre, damit zwei gleichzeitige
// Aenderungen nicht beide den Stand vor der anderen sehen. write darf GuardLastAdmin nicht erneut aufrufen.
func (s *Store) GuardLastAdmin(ctx context.Context, ch AdminChange, write func() error) error {
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	users, err := s.Users(ctx)
	if err != nil {
		return err
	}
	roles, err := s.GroupRoles(ctx)
	if err != nil {
		return err
	}
	count := func(list []*User, r map[string]string) int {
		n := 0
		for _, u := range list {
			if ActiveLocalAdmin(u, r) {
				n++
			}
		}
		return n
	}
	if count(users, roles) > 0 {
		after := users
		if ch.User != nil {
			after = nil
			for _, u := range users {
				cp := *u
				if x := ch.User(&cp); x != nil {
					after = append(after, x)
				}
			}
		}
		if ch.Roles != nil {
			ch.Roles(roles)
		}
		if count(after, roles) == 0 {
			return ErrLastAdmin
		}
	}
	return write()
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
