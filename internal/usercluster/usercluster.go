// Package usercluster gleicht Benutzer und Anmeldung ueber den Cluster ab (internal/peer, Modul users; Bereiche
// accounts, groups, sso und directory, ohne Einstellung aus). Benutzerkonten gehen mit Passwort-Hash, App-2FA (Geheimnis
// und gehashte Wiederherstellungscodes), Sprache, Zeitzone, den verknuepften SSO-Konten und den Feldern der
// Benutzerverwaltung (Rolle, Sperre, Herkunft, E-Mail, Gruppen, „Passwort beim naechsten Anmelden setzen“); Gruppen
// mit Rolle und Zuordnungen nach aussen; die SSO-Einrichtung (OIDC) mit Client-Secret und „Benutzer ueber Gruppen
// anlegen“; directory mit der AD/LDAP-Anbindung (Bind-Passwort) und der 2FA-Pflicht. Ueber die Leitung geht alles im
// Klartext (HTTPS, an die Kopplung gebunden), gespeichert wird wie lokal (Hash; 2FA-Geheimnis, Client-Secret und
// Bind-Passwort mit dem eigenen secret.key verschluesselt).
//
// Je Node bleiben: Passkeys (an den Hostnamen gebunden), Sitzungen, letzte Anmeldung, Sperren nach Fehlversuchen,
// API- und MCP-Keys, die feste Rueckleit-Adresse fuer SSO (base_url, enthaelt den eigenen Hostnamen) und Forward-Auth
// komplett (die Proxy-Adressen gehoeren zum Netz der Node).
//
// Kennung eines Benutzers im Cluster ist users.uid. Gleichnamige Benutzer mit verschiedener Kennung:
//   - exakt gleich (Name, Hash, 2FA, Codes, Sprache, Zeitzone, SSO-Konten, Rolle, Sperre, Herkunft, E-Mail, Gruppen):
//     die kleinere Kennung gilt, die Node mit der groesseren uebernimmt sie (lokale Nummer, Passkeys und Sitzungen
//     bleiben);
//   - sonst Abweichung: nichts wird ueberschrieben, jede Node behaelt ihren Benutzer, die Seite Cluster stellt die
//     Versionen zur Wahl. Die Wahl geht mit dem gewaehlten Benutzer hinaus (abgeloeste Kennungen, Zeitpunkt); eine
//     Node, deren Benutzer darin abgeloest ist, uebernimmt den gewaehlten an seiner Stelle. Bei zwei Wahlen gilt die
//     juengere.
//
// Dieselbe Kennung auf beiden Seiten (also schon ueber den Cluster abgeglichen): die juengere Aenderung gewinnt.
// Eine aeltere Node ohne Benutzerverwaltung sendet keine Rolle: dann bleiben Rolle, Sperre, Herkunft, E-Mail und Gruppen
// hier unveraendert (neu angelegt: Administrator, lokal), damit ein gemischter Cluster nichts herauf- oder herabstuft.
//
// Schutz: Eine Loeschung aus dem Cluster entfernt nie den letzten Benutzer einer Node; eine Uebernahme, die der Node
// den letzten aktiven lokalen Administrator naehme (sperren, herabstufen, loeschen, auch ueber eine Gruppe), wird
// nicht uebernommen. Die Wahl ersetzt den Benutzer an Ort und Stelle, die eigene Sitzung bleibt. Aendert eine
// Uebernahme Passwort, 2FA, Rolle, Sperre oder Gruppen, enden die Sitzungen dieses Benutzers auf der Node.
package usercluster

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/authcfg"
	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

// Kennungen fuer den Cluster.
const (
	ModuleID      = "users"
	ItemAccounts  = "accounts"
	ItemSSO       = "sso"
	ItemGroups    = "groups"    // Benutzergruppen (groups.go)
	ItemDirectory = "directory" // AD/LDAP und 2FA-Pflicht, ein Eintrag authcfg.DirectoryID (directory.go)

	ssoID = "oidc" // die eine SSO-Einrichtung je Node
)

// Schluessel der SSO-Einrichtung wie in web/auth_oidc.go (auth.oidc.base_url bleibt je Node).
const (
	SetOIDCIssuer = "auth.oidc.issuer"
	SetOIDCClient = "auth.oidc.client_id"
	SetOIDCSecret = "auth.oidc.client_secret" // verschluesselt
	SetOIDCLabel  = "auth.oidc.label"
	SetOIDCScopes = "auth.oidc.scopes"
	defaultScopes = "openid profile email" // wie oidcDefaultScop in web/auth_oidc.go

	setConflicts = "users.cluster_conflicts" // abweichende gleichnamige Benutzer anderer Nodes (Daten verschluesselt)
)

var (
	// ErrConflict: gleichnamiger Benutzer mit anderem Inhalt (Wahl auf der Seite Cluster).
	ErrConflict = errors.New("user with the same name differs on this node, choose one on the cluster page")
	// ErrReplaced: der Benutzer der anderen Node ist durch eine Wahl im Cluster abgeloest.
	ErrReplaced = errors.New("user was replaced by the choice in the cluster")
	// ErrLastUser: der letzte Benutzer der Node wird nicht geloescht.
	ErrLastUser = errors.New("last user of this node is not deleted")
	// ErrLastAdmin: die Uebernahme naehme der Node den letzten aktiven lokalen Administrator.
	ErrLastAdmin = errors.New("last active local administrator of this node is kept")
	// ErrChoice: die gewaehlte Version gibt es (hier) nicht (mehr).
	ErrChoice = errors.New("unknown user version")

	errItem   = errors.New("cluster: unknown area")
	uidRe     = regexp.MustCompile(`^[0-9a-f]{16,64}$`)
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)     // wie web/handlers_core.go
	extNameRe = regexp.MustCompile(`^[\p{L}\p{N}._@+-]{1,128}$`) // Benutzer aus LDAP/SSO (z. B. user@firma.local)
	errFormat = errors.New("cluster: invalid user")
)

// Cluster ist der Provider fuer Benutzer und Anmeldung.
type Cluster struct {
	st    *store.Store
	box   *secrets.Box
	log   *slog.Logger
	names func(ctx context.Context) map[string]string // Node-Kennung -> Name (Audit), nil = Kennung
	mu    sync.Mutex                                  // Uebernahmen und Wahl nacheinander
}

// New baut den Provider (Register haengt ihn an den Cluster).
func New(st *store.Store, box *secrets.Box, log *slog.Logger) *Cluster {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Cluster{st: st, box: box, log: log}
}

// Register meldet den Bereich beim Cluster an (vor peer.Run) und haengt die Benutzer und die SSO-Einrichtung an.
func Register(pm *peer.Manager, c *Cluster) {
	pm.RegisterProvider(c)
	c.names = func(ctx context.Context) map[string]string {
		out := map[string]string{}
		list, _ := pm.Members(ctx)
		for _, x := range list {
			out[x.NodeID] = x.Name
		}
		return out
	}
	c.st.SetLoginCluster(func(ctx context.Context, item, id string, deleted bool) {
		pm.ClusterChange(ctx, ModuleID, item, id, deleted)
	})
}

// ClusterModule: Modul „Benutzer & Anmeldung“ mit seinen Bereichen.
func (c *Cluster) ClusterModule() peer.ModuleInfo {
	return peer.ModuleInfo{ID: ModuleID, TitleKey: "cluster.mod.users", Items: []peer.ItemInfo{
		{ID: ItemAccounts, TitleKey: "cluster.item.user_accounts", HintKey: "cluster.users_hint"},
		{ID: ItemSSO, TitleKey: "cluster.item.user_sso"},
		{ID: ItemGroups, TitleKey: "cluster.item.groups"},
		{ID: ItemDirectory, TitleKey: "cluster.item.directory"},
	}}
}

// identity ist ein verknuepftes SSO-Konto eines Benutzers.
type identity struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
	Label    string `json:"label,omitempty"`
}

// clusterUser ist ein Benutzer im Cluster.
type clusterUser struct {
	Username   string     `json:"username"`
	Password   string     `json:"password_hash"`
	TOTP       string     `json:"totp_secret,omitempty"`
	Recovery   string     `json:"totp_recovery,omitempty"`
	Lang       string     `json:"lang,omitempty"`
	Timezone   string     `json:"timezone,omitempty"`
	CreatedAt  string     `json:"created_at,omitempty"`
	Identities []identity `json:"identities"`
	Replaces   []string   `json:"replaces,omitempty"`  // durch eine Wahl abgeloeste Kennungen
	ChosenAt   string     `json:"chosen_at,omitempty"` // Zeitpunkt der Wahl
	// Benutzerverwaltung; eine aeltere Node sendet diese Felder nicht (Role leer, siehe legacy)
	Role         string   `json:"role,omitempty"`
	Disabled     bool     `json:"disabled,omitempty"`
	Source       string   `json:"source,omitempty"`
	Email        string   `json:"email,omitempty"`
	GroupUIDs    []string `json:"group_uids,omitempty"`
	ExtGroupUIDs []string `json:"ext_group_uids,omitempty"`
	MustChange   bool     `json:"must_change,omitempty"`
	// zuletzt geprueft (Gruppen aus LDAP/SSO) bzw. verbrauchter TOTP-Zeitschritt; aeltere Nodes senden sie nicht. Es
	// gilt der neuere Zeitpunkt samt seinen ext_group_uids bzw. der hoechste Schritt (write), beide zaehlen nicht zum
	// Inhalt (same).
	ExtCheckedAt string `json:"ext_checked_at,omitempty"`
	TOTPStep     int64  `json:"totp_last_step,omitempty"`
}

// legacy: Stand einer aelteren Node ohne Benutzerverwaltung (sendet keine Rolle).
func (u clusterUser) legacy() bool { return u.Role == "" }

// norm: fehlende Felder einer aelteren Node als Standard (Administrator, lokal, nicht gesperrt, keine Gruppen) - so
// sind dort alle Benutzer.
func (u clusterUser) norm() clusterUser {
	if u.Role == "" {
		u.Role = store.RoleAdmin
	}
	if u.Source == "" {
		u.Source = store.SourceLocal
	}
	return u
}

// adminOf: die Felder der Benutzerverwaltung vom Benutzer hier (eine aeltere Node kennt sie nicht und aendert sie nie).
func (u clusterUser) adminOf(l clusterUser) clusterUser {
	u.Role, u.Disabled, u.Source, u.Email, u.MustChange = l.Role, l.Disabled, l.Source, l.Email, l.MustChange
	u.GroupUIDs, u.ExtGroupUIDs = l.GroupUIDs, l.ExtGroupUIDs
	return u
}

// adminSame: Rolle, Sperre und Gruppen gleich (sonst enden die Sitzungen).
func (u clusterUser) adminSame(o clusterUser) bool {
	return u.Role == o.Role && u.Disabled == o.Disabled && slices.Equal(store.NormList(u.GroupUIDs), store.NormList(o.GroupUIDs)) &&
		slices.Equal(store.NormList(u.ExtGroupUIDs), store.NormList(o.ExtGroupUIDs))
}

// same: exakt gleicher Benutzer (ohne Kennung, Anlegezeit und Wahl). Beide Seiten mit norm.
func (u clusterUser) same(o clusterUser) bool {
	if !strings.EqualFold(u.Username, o.Username) || u.Password != o.Password || u.TOTP != o.TOTP || u.Recovery != o.Recovery ||
		u.Lang != o.Lang || u.Timezone != o.Timezone || len(u.Identities) != len(o.Identities) ||
		!u.adminSame(o) || u.Source != o.Source || u.Email != o.Email || u.MustChange != o.MustChange {
		return false
	}
	key := func(l []identity) []string {
		out := make([]string, 0, len(l))
		for _, i := range l {
			out = append(out, i.Provider+"\x00"+i.Subject)
		}
		sort.Strings(out)
		return out
	}
	return slices.Equal(key(u.Identities), key(o.Identities))
}

type localUser struct {
	id      int64
	uid     string
	u       clusterUser // TOTP im Klartext
	totpErr error       // TOTP-Geheimnis hier nicht entschluesselbar (dann bleibt der gespeicherte Wert in u.TOTP)
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

// load liefert einen Benutzer (where mit einem Parameter) samt SSO-Konten; nil = gibt es nicht.
func (c *Cluster) load(ctx context.Context, where string, arg any) (*localUser, error) {
	var l localUser
	var repl, groups, ext string
	err := c.st.Reader().QueryRowContext(ctx, `SELECT id, uid, username, password_hash, totp_secret, totp_recovery, lang, timezone, created_at,
		cluster_replaces, cluster_chosen_at, role, disabled, source, email, group_uids, ext_group_uids, must_change, ext_checked_at, totp_last_step
		FROM users WHERE `+where, arg).Scan(
		&l.id, &l.uid, &l.u.Username, &l.u.Password, &l.u.TOTP, &l.u.Recovery, &l.u.Lang, &l.u.Timezone, &l.u.CreatedAt, &repl, &l.u.ChosenAt,
		&l.u.Role, &l.u.Disabled, &l.u.Source, &l.u.Email, &groups, &ext, &l.u.MustChange, &l.u.ExtCheckedAt, &l.u.TOTPStep)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	l.u.Replaces = splitList(repl)
	l.u.GroupUIDs, l.u.ExtGroupUIDs = store.NormList(splitList(groups)), store.NormList(splitList(ext))
	if !store.ValidRole(l.u.Role) {
		l.u.Role = store.RoleRead
	}
	l.u = l.u.norm()
	if p, err := c.st.DecodeTOTP(l.u.TOTP); err != nil {
		l.totpErr = err
	} else {
		l.u.TOTP = p
	}
	rows, err := c.st.Reader().QueryContext(ctx, `SELECT provider, subject, label FROM user_identities WHERE user_id = ? ORDER BY provider, subject`, l.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	l.u.Identities = []identity{}
	for rows.Next() {
		var i identity
		if err := rows.Scan(&i.Provider, &i.Subject, &i.Label); err != nil {
			return nil, err
		}
		l.u.Identities = append(l.u.Identities, i)
	}
	return &l, rows.Err()
}

func (c *Cluster) byUID(ctx context.Context, uid string) (*localUser, error) {
	if uid == "" {
		return nil, nil
	}
	return c.load(ctx, `uid = ?`, uid)
}

// byName: Benutzer mit diesem Namen (gross/klein egal wie die Spalte).
func (c *Cluster) byName(ctx context.Context, name string) (*localUser, error) {
	return c.load(ctx, `username = ?`, name)
}

// ClusterIDs: alle Benutzer bzw. Gruppen, die SSO-Einrichtung bzw. directory, wenn eingerichtet (erster Abgleich).
func (c *Cluster) ClusterIDs(ctx context.Context, item string) ([]string, error) {
	switch item {
	case ItemAccounts:
		rows, err := c.st.Reader().QueryContext(ctx, `SELECT uid FROM users WHERE uid <> '' ORDER BY id`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var uid string
			if err := rows.Scan(&uid); err != nil {
				return nil, err
			}
			out = append(out, uid)
		}
		return out, rows.Err()
	case ItemSSO:
		if c.st.SettingOr(ctx, SetOIDCIssuer, "") == "" {
			return nil, nil
		}
		return []string{ssoID}, nil
	case ItemGroups:
		groups, err := c.st.Groups(ctx)
		if err != nil {
			return nil, err
		}
		out := []string{}
		for _, g := range groups {
			out = append(out, g.UID)
		}
		return out, nil
	case ItemDirectory:
		if !c.hasDirectory(ctx) {
			return nil, nil
		}
		return []string{authcfg.DirectoryID}, nil
	}
	return nil, errItem
}

// clusterSSO ist die SSO-Einrichtung im Cluster (Secret im Klartext).
type clusterSSO struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
	Secret   string `json:"client_secret,omitempty"`
	Label    string `json:"label,omitempty"`
	Scopes   string `json:"scopes,omitempty"`
	// Benutzer ueber den Gruppen-Claim anlegen und Name des Claims (nil = aeltere Node: hier unveraendert)
	JIT        *bool   `json:"jit,omitempty"`
	GroupClaim *string `json:"group_claim,omitempty"`
	// Secret hier nicht lesbar: die anderen behalten ihren Stand (sonst ginge ein leeres Secret hinaus)
	Incomplete bool `json:"incomplete,omitempty"`
}

// ClusterGet liefert einen Benutzer bzw. die SSO-Einrichtung samt Geheimnissen (found=false: gibt es nicht).
func (c *Cluster) ClusterGet(ctx context.Context, item, id string) (json.RawMessage, bool, error) {
	switch item {
	case ItemAccounts:
		l, err := c.byUID(ctx, id)
		if err != nil || l == nil {
			return nil, false, err
		}
		if l.totpErr != nil { // nicht mit einem unlesbaren Geheimnis hinaus (spaeter erneut)
			return nil, false, l.totpErr
		}
		b, err := json.Marshal(l.u)
		return b, err == nil, err
	case ItemSSO:
		in := clusterSSO{Issuer: c.st.SettingOr(ctx, SetOIDCIssuer, ""), ClientID: c.st.SettingOr(ctx, SetOIDCClient, ""),
			Label: c.st.SettingOr(ctx, SetOIDCLabel, ""), Scopes: c.st.SettingOr(ctx, SetOIDCScopes, "")}
		if id != ssoID || in.Issuer == "" {
			return nil, false, nil
		}
		if enc := c.st.SettingOr(ctx, SetOIDCSecret, ""); enc != "" {
			if c.box == nil {
				in.Incomplete = true
			} else if v, err := c.box.Decrypt(enc); err != nil {
				in.Incomplete = true
			} else {
				in.Secret = v
			}
		}
		jit, claim := c.st.SettingOr(ctx, authcfg.SetOIDCJIT, "0") == "1", c.st.SettingOr(ctx, authcfg.SetOIDCGroupClaim, "")
		in.JIT, in.GroupClaim = &jit, &claim
		b, err := json.Marshal(in)
		return b, err == nil, err
	case ItemGroups:
		return c.getGroup(ctx, id)
	case ItemDirectory:
		return c.getDirectory(ctx, id)
	}
	return nil, false, errItem
}

// ClusterApply uebernimmt einen Benutzer bzw. die SSO-Einrichtung einer anderen Node (ctx traegt die Herkunft).
func (c *Cluster) ClusterApply(ctx context.Context, item, id string, data json.RawMessage, deleted bool) error {
	switch item {
	case ItemAccounts:
		if !uidRe.MatchString(id) {
			return errItem
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.applyUser(ctx, id, data, deleted)
	case ItemSSO:
		if id != ssoID {
			return errItem
		}
		return c.applySSO(ctx, data, deleted)
	case ItemGroups:
		if !uidRe.MatchString(id) {
			return errItem
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.applyGroup(ctx, id, data, deleted)
	case ItemDirectory:
		if id != authcfg.DirectoryID {
			return errItem
		}
		return c.applyDirectory(ctx, data, deleted)
	}
	return errItem
}

// origin: Urheberin einer Uebernahme (Kennung, Name fuers Audit).
func (c *Cluster) origin(ctx context.Context) (string, string) {
	node, _, _ := peer.ClusterOrigin(ctx)
	name := node
	if c.names != nil {
		if n := c.names(ctx)[node]; n != "" {
			name = n
		}
	}
	return node, name
}

// audit vermerkt eine aus dem Cluster uebernommene Aenderung (Herkunft cluster).
func (c *Cluster) audit(ctx context.Context, action, target, details string) {
	_, name := c.origin(ctx)
	if err := c.st.Audit(context.WithoutCancel(ctx), store.AuditEntry{Actor: "node:" + name, Action: action, Target: target, Details: details, Origin: "cluster"}); err != nil {
		c.log.Error("audit write failed", "err", err)
	}
}

func (c *Cluster) userCount(ctx context.Context) int {
	var n int
	_ = c.st.Reader().QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n
}

func (c *Cluster) applyUser(ctx context.Context, uid string, data json.RawMessage, deleted bool) error {
	cur, err := c.byUID(ctx, uid)
	if err != nil {
		return err
	}
	if deleted {
		if cur == nil {
			return c.dropConflicts(ctx, func(x conflict) bool { return x.UID == uid })
		}
		if c.userCount(ctx) <= 1 { // nie den letzten Benutzer (Administrator) der Node
			c.log.Warn("cluster: last user of this node is kept", "user", cur.u.Username)
			c.audit(ctx, "user.cluster.keep_last", cur.u.Username, "")
			return ErrLastUser
		}
		if err := c.deleteUser(ctx, cur); err != nil {
			return err
		}
		c.audit(ctx, "user.cluster.delete", cur.u.Username, "")
		return nil
	}
	var in clusterUser
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	if err := c.check(ctx, &in); err != nil {
		return err
	}
	in.Replaces = slices.DeleteFunc(in.Replaces, func(x string) bool { return !uidRe.MatchString(x) || x == uid })
	same, err := c.byName(ctx, in.Username)
	if err != nil {
		return err
	}
	if same != nil && cur != nil && same.id == cur.id {
		same = nil
	}
	if cur != nil && same == nil { // schon abgeglichen: die juengere Aenderung gewinnt
		return c.write(ctx, cur, uid, in, "", "user.cluster.update")
	}
	if same == nil {
		return c.write(ctx, nil, uid, in, "", "user.cluster.create")
	}
	switch {
	case slices.Contains(in.Replaces, same.uid) && (!slices.Contains(same.u.Replaces, uid) || laterChoice(in, uid, same)):
		// durch die Wahl im Cluster abgeloest: der gewaehlte Benutzer tritt an seine Stelle
		if cur != nil { // die gewaehlte Kennung gibt es hier schon unter anderem Namen: dieser weicht
			if c.userCount(ctx) <= 1 {
				return ErrLastUser
			}
			if err := c.deleteUser(ctx, cur); err != nil {
				return err
			}
		}
		if err := c.write(ctx, same, uid, in, "", "user.cluster.choice"); err != nil {
			return err
		}
		return c.dropConflicts(ctx, func(x conflict) bool { return strings.EqualFold(x.Username, in.Username) })
	case slices.Contains(same.u.Replaces, uid):
		return ErrReplaced
	case cur == nil && same.u.same(in.norm()):
		// exaktes Doppel unter anderer Kennung: die kleinere gilt
		if same.uid < uid {
			return nil // hier gilt die eigene Kennung, die andere Node uebernimmt sie
		}
		if _, err := c.st.Writer().ExecContext(ctx, `UPDATE users SET uid = ? WHERE id = ?`, uid, same.id); err != nil {
			return err
		}
		c.st.LoginChanged(ctx, ItemAccounts, uid, false)
		c.audit(ctx, "user.cluster.merge", in.Username, "uid="+short(same.uid)+"->"+short(uid))
		return nil
	}
	return c.addConflict(ctx, uid, in)
}

// check prueft einen Benutzer einer anderen Node und bereinigt die Felder der Benutzerverwaltung. Unbekannte (neuere)
// Rolle: die kleinste (nur lesen). Lokale Benutzer brauchen den Namen wie beim Anlegen hier und ein Passwort (ausser
// „Passwort beim naechsten Anmelden setzen“); Benutzer aus LDAP/SSO haben kein lokales Passwort.
func (c *Cluster) check(ctx context.Context, in *clusterUser) error {
	if !in.legacy() {
		if !store.ValidRole(in.Role) {
			in.Role = store.RoleRead
		}
		if in.Source == "" {
			in.Source = store.SourceLocal
		}
		if in.Source != store.SourceLocal && in.Source != store.SourceLDAP && in.Source != store.SourceOIDC {
			return errFormat
		}
		in.Email = strings.TrimSpace(in.Email)
		if len(in.Email) > 320 {
			return errFormat
		}
		alias := c.aliases(ctx)
		in.GroupUIDs, in.ExtGroupUIDs = groupRefs(in.GroupUIDs, alias), groupRefs(in.ExtGroupUIDs, alias)
	}
	local := in.legacy() || in.Source == store.SourceLocal
	if local && !nameRe.MatchString(in.Username) || !local && !extNameRe.MatchString(in.Username) {
		return errFormat
	}
	if in.Password == "" && local && (in.legacy() || !in.MustChange) {
		return errFormat
	}
	return nil
}

// guard fuehrt write unter der Schutzregel „letzter aktiver lokaler Administrator“ aus (store.GuardLastAdmin, dieselbe
// Fassung wie Oberflaeche und API, unter derselben Sperre). Naehme die Aenderung der Node den letzten, bleibt alles, wie
// es ist (Audit user.cluster.keep_last mit der Aenderung what, ErrLastAdmin; der Cluster versucht es spaeter erneut).
func (c *Cluster) guard(ctx context.Context, name, what string, ch store.AdminChange, write func() error) error {
	err := c.st.GuardLastAdmin(ctx, ch, write)
	if !errors.Is(err, store.ErrLastAdmin) {
		return err
	}
	c.log.Warn("cluster: last active local administrator of this node is kept", "target", name, "change", what)
	if _, _, ok := peer.ClusterOrigin(ctx); ok {
		c.audit(ctx, "user.cluster.keep_last", name, what)
	}
	return ErrLastAdmin
}

// userChange: der Benutzer l wird zu to (nil = geloescht), fuer guard.
func userChange(l *localUser, to *clusterUser) store.AdminChange {
	return store.AdminChange{User: func(u *store.User) *store.User {
		if u.ID != l.id {
			return u
		}
		if to == nil {
			return nil
		}
		u.Role, u.Disabled, u.Source, u.GroupUIDs, u.ExtGroupUIDs = to.Role, to.Disabled, to.Source, to.GroupUIDs, to.ExtGroupUIDs
		u.ExtCheckedAt = store.ParseTime(to.ExtCheckedAt)
		return u
	}}
}

// deleteUser loescht l, ausser er ist der letzte aktive lokale Administrator der Node (guard).
func (c *Cluster) deleteUser(ctx context.Context, l *localUser) error {
	return c.guard(ctx, l.u.Username, "delete", userChange(l, nil), func() error {
		_, err := c.st.DeleteUser(ctx, l.id)
		return err
	})
}

// keptError: die Uebernahme ist gespeichert, aber mit hier neueren Gruppen aus LDAP/SSO bzw. einem hoeheren
// TOTP-Schritt; dieser zusammengefuehrte Stand ist neu gemeldet (peer: kein Fehler, kein Eintrag des fremden Stands),
// damit die anderen Nodes ihn bekommen. Die Gegenstelle nimmt ihn ohne erneute Meldung (bei ihr ist nichts neuer).
type keptError struct{}

func (keptError) Error() string    { return "newer own directory groups or totp step kept and announced" }
func (keptError) Superseded() bool { return true }

// laterChoice: die Wahl von in (Kennung uid) ist juenger als die von l (Gleichstand: kleinere Kennung).
func laterChoice(in clusterUser, uid string, l *localUser) bool {
	a, b := store.ParseTime(in.ChosenAt), store.ParseTime(l.u.ChosenAt)
	return a.After(b) || a.Equal(b) && uid < l.uid
}

func short(uid string) string {
	if len(uid) > 12 {
		return uid[:12]
	}
	return uid
}

// write legt einen Benutzer an (l nil) oder ersetzt l (auch mit neuer Kennung) samt SSO-Konten. Kommt in von einer
// aelteren Node (keine Rolle), bleiben Rolle, Sperre, Herkunft, E-Mail und Gruppen von l (neu: Standard). Naehme die
// Aenderung der Node den letzten aktiven lokalen Administrator, bleibt l (ErrLastAdmin). Aendern sich Passwort, 2FA,
// Rolle, Sperre oder Gruppen, enden seine Sitzungen hier (ausser keep; gesperrt: alle). Meldet die Aenderung an den
// Cluster und ins Audit (action "" = kein Audit). Ist das 2FA-Geheimnis von l hier nicht lesbar und bliebe es, wird
// nichts geschrieben (l.totpErr). Gruppen aus LDAP/SSO mit neuerem Pruefzeitpunkt und einen hoeheren TOTP-Schritt
// behaelt l; dann geht der zusammengefuehrte Stand neu hinaus (keptError).
func (c *Cluster) write(ctx context.Context, l *localUser, uid string, in clusterUser, keep, action string) error {
	if l != nil && l.totpErr != nil && in.TOTP == l.u.TOTP { // sonst stuende der Chiffretext als Geheimnis da
		return l.totpErr
	}
	if in.legacy() && l != nil {
		in = in.adminOf(l.u)
	}
	in = in.norm()
	kept := false
	if l != nil {
		if store.ParseTime(in.ExtCheckedAt).Before(store.ParseTime(l.u.ExtCheckedAt)) {
			kept = in.ExtCheckedAt != "" || !slices.Equal(store.NormList(in.ExtGroupUIDs), l.u.ExtGroupUIDs)
			in.ExtGroupUIDs, in.ExtCheckedAt = l.u.ExtGroupUIDs, l.u.ExtCheckedAt
		}
		if in.TOTPStep < l.u.TOTPStep {
			kept = kept || in.TOTPStep > 0 // 0: aeltere Node oder nie verwendet
			in.TOTPStep = l.u.TOTPStep
		}
	}
	var details string
	do := func() (err error) {
		details, err = c.writeTx(ctx, l, uid, in, keep)
		return err
	}
	var err error
	if l != nil && adminChange(l.u, in) != "" {
		err = c.guard(ctx, l.u.Username, adminChange(l.u, in), userChange(l, &in), do)
	} else {
		err = do()
	}
	if err != nil {
		return err
	}
	c.st.LoginChanged(ctx, ItemAccounts, uid, false)
	if len(in.Replaces) > 0 { // durch die Wahl erledigte Abweichungen
		if err := c.dropConflicts(ctx, func(x conflict) bool { return slices.Contains(in.Replaces, x.UID) }); err != nil {
			return err
		}
	}
	if action == "user.cluster.update" && l != nil && details == "" && l.u.same(in) {
		action = "" // nur TOTP-Schritt bzw. Pruefzeitpunkt der Gruppen: kein Eintrag
	}
	if action != "" {
		c.audit(ctx, action, in.Username, details)
	}
	if _, _, ok := peer.ClusterOrigin(ctx); ok && kept {
		c.st.LoginChanged(context.Background(), ItemAccounts, uid, false) // ohne Herkunft: als eigene, neuere Aenderung
		return keptError{}
	}
	return nil
}

// writeTx schreibt in fuer write in einer Transaktion (Benutzer, Sitzungsende, SSO-Konten); liefert die Aenderungen
// fuers Audit.
func (c *Cluster) writeTx(ctx context.Context, l *localUser, uid string, in clusterUser, keep string) (string, error) {
	created := in.CreatedAt
	if store.ParseTime(created).IsZero() {
		created = store.Now()
	}
	tx, err := c.st.Writer().BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var id int64
	groups, ext := strings.Join(store.NormList(in.GroupUIDs), ","), strings.Join(store.NormList(in.ExtGroupUIDs), ",")
	details := ""
	if l == nil {
		res, err := tx.ExecContext(ctx, `INSERT INTO users (uid, username, password_hash, totp_secret, totp_recovery, lang, timezone, created_at,
			cluster_replaces, cluster_chosen_at, role, disabled, source, email, group_uids, ext_group_uids, must_change, ext_checked_at, totp_last_step)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			uid, in.Username, in.Password, c.st.EncodeTOTP(in.TOTP), in.Recovery, in.Lang, in.Timezone, created, strings.Join(in.Replaces, ","), in.ChosenAt,
			in.Role, in.Disabled, in.Source, in.Email, groups, ext, in.MustChange, in.ExtCheckedAt, max(in.TOTPStep, 0))
		if err != nil {
			return "", err
		}
		id, _ = res.LastInsertId()
	} else {
		id = l.id
		if _, err := tx.ExecContext(ctx, `UPDATE users SET uid = ?, username = ?, password_hash = ?, totp_secret = ?, totp_recovery = ?, lang = ?,
			timezone = ?, cluster_replaces = ?, cluster_chosen_at = ?, role = ?, disabled = ?, source = ?, email = ?, group_uids = ?, ext_group_uids = ?,
			must_change = ?, ext_checked_at = ?, totp_last_step = MAX(totp_last_step, ?) WHERE id = ?`, uid, in.Username, in.Password,
			c.st.EncodeTOTP(in.TOTP), in.Recovery, in.Lang, in.Timezone, strings.Join(in.Replaces, ","), in.ChosenAt, in.Role, in.Disabled, in.Source,
			in.Email, groups, ext, in.MustChange, in.ExtCheckedAt, in.TOTPStep, id); err != nil {
			return "", err
		}
		var ch []string
		if l.u.Password != in.Password {
			ch = append(ch, "password")
		}
		if l.u.TOTP != in.TOTP {
			ch = append(ch, "2fa")
		}
		if a := adminChange(l.u, in); a != "" {
			ch = append(ch, a)
		}
		if len(ch) > 0 { // wie beim Aendern hier: andere Sitzungen enden (gesperrt: alle)
			k := keep
			if in.Disabled {
				k = ""
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND id != ?`, id, k); err != nil {
				return "", err
			}
		}
		if l.u.Recovery != in.Recovery && l.u.TOTP == in.TOTP {
			ch = append(ch, "recovery_codes")
		}
		if l.u.Lang != in.Lang || l.u.Timezone != in.Timezone {
			ch = append(ch, "lang="+in.Lang+" timezone="+in.Timezone)
		}
		if l.u.Email != in.Email {
			ch = append(ch, "email")
		}
		if l.u.MustChange != in.MustChange {
			ch = append(ch, "must_change")
		}
		if !l.u.same(in) && len(ch) == 0 {
			ch = append(ch, "sso_accounts")
		}
		if l.uid != uid {
			ch = append(ch, "uid="+short(l.uid)+"->"+short(uid))
		}
		details = strings.Join(ch, " ")
	}
	if err := c.setIdentities(ctx, tx, id, in.Identities); err != nil {
		return "", err
	}
	return details, tx.Commit()
}

// adminChange beschreibt geaenderte Rolle, Sperre, Herkunft und Gruppen fuers Audit ("" = gleich; sonst enden die
// Sitzungen).
func adminChange(a, b clusterUser) string {
	var ch []string
	if a.Role != b.Role {
		ch = append(ch, "role="+b.Role)
	}
	if a.Source != b.Source {
		ch = append(ch, "source="+b.Source)
	}
	if a.Disabled != b.Disabled {
		if b.Disabled {
			ch = append(ch, "disabled")
		} else {
			ch = append(ch, "enabled")
		}
	}
	if !slices.Equal(store.NormList(a.GroupUIDs), store.NormList(b.GroupUIDs)) || !slices.Equal(store.NormList(a.ExtGroupUIDs), store.NormList(b.ExtGroupUIDs)) {
		ch = append(ch, "groups")
	}
	return strings.Join(ch, " ")
}

// setIdentities: SSO-Konten des Benutzers genau wie angegeben (letzte Nutzung bleibt); ein Konto, das hier einem
// anderen Benutzer gehoert, bleibt dort.
func (c *Cluster) setIdentities(ctx context.Context, tx *sql.Tx, userID int64, list []identity) error {
	keep := map[string]bool{}
	for _, i := range list {
		if i.Provider == "" || i.Subject == "" {
			continue
		}
		var owner int64
		err := tx.QueryRowContext(ctx, `SELECT user_id FROM user_identities WHERE provider = ? AND subject = ?`, i.Provider, i.Subject).Scan(&owner)
		switch {
		case err == nil && owner != userID:
			c.log.Warn("cluster: sso identity belongs to another user here", "provider", i.Provider, "label", i.Label)
			continue
		case err == nil:
			_, err = tx.ExecContext(ctx, `UPDATE user_identities SET label = ? WHERE provider = ? AND subject = ?`, i.Label, i.Provider, i.Subject)
		case errors.Is(err, sql.ErrNoRows):
			_, err = tx.ExecContext(ctx, `INSERT INTO user_identities (user_id, provider, subject, label, created_at) VALUES (?,?,?,?,?)`,
				userID, i.Provider, i.Subject, i.Label, store.Now())
		}
		if err != nil {
			return err
		}
		keep[i.Provider+"\x00"+i.Subject] = true
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, provider, subject FROM user_identities WHERE user_id = ?`, userID)
	if err != nil {
		return err
	}
	var drop []int64
	for rows.Next() {
		var id int64
		var p, s string
		if rows.Scan(&id, &p, &s) == nil && !keep[p+"\x00"+s] {
			drop = append(drop, id)
		}
	}
	rows.Close()
	for _, id := range drop {
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_identities WHERE id = ?`, id); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------- Abweichungen und Wahl

type conflict struct {
	UID      string `json:"uid"`
	Node     string `json:"node"`
	Username string `json:"username"`
	Data     string `json:"data"` // clusterUser als JSON, verschluesselt
	SeenAt   string `json:"seen_at"`
}

func (c *Cluster) conflicts(ctx context.Context) []conflict {
	var l []conflict
	_ = json.Unmarshal([]byte(c.st.SettingOr(ctx, setConflicts, "[]")), &l)
	return l
}

func (c *Cluster) saveConflicts(ctx context.Context, l []conflict) error {
	if l == nil {
		l = []conflict{}
	}
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return c.st.SetSetting(ctx, setConflicts, string(b))
}

func (c *Cluster) dropConflicts(ctx context.Context, f func(conflict) bool) error {
	l := c.conflicts(ctx)
	n := len(l)
	l = slices.DeleteFunc(l, f)
	if len(l) == n {
		return nil
	}
	return c.saveConflicts(ctx, l)
}

// addConflict merkt einen abweichenden gleichnamigen Benutzer einer anderen Node zur Wahl vor (nichts wird
// ueberschrieben) und liefert ErrConflict.
func (c *Cluster) addConflict(ctx context.Context, uid string, in clusterUser) error {
	if c.box == nil {
		return ErrConflict
	}
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	node, _ := c.origin(ctx)
	l := c.conflicts(ctx)
	i := slices.IndexFunc(l, func(x conflict) bool { return x.UID == uid })
	x := conflict{UID: uid, Node: node, Username: in.Username, Data: c.box.Encrypt(string(b)), SeenAt: store.Now()}
	if i >= 0 {
		l[i] = x
	} else {
		l = append(l, x)
	}
	if err := c.saveConflicts(ctx, l); err != nil {
		return err
	}
	if i < 0 {
		c.log.Warn("user with the same name differs on another cluster node, choose one on the cluster page", "user", in.Username, "node", node)
		c.audit(ctx, "user.cluster.conflict", in.Username, "uid="+short(uid))
	}
	return ErrConflict
}

// Version ist ein Benutzer zur Wahl, wenn gleichnamige Benutzer im Cluster verschieden sind.
type Version struct {
	UID        string    `json:"uid"`
	Node       string    `json:"node_id"` // "" = diese Node
	Username   string    `json:"username"`
	CreatedAt  time.Time `json:"created_at,omitzero"`
	TwoFA      bool      `json:"two_fa"`
	Identities int       `json:"identities"`
	Own        bool      `json:"own"`
	Role       string    `json:"role"`     // eigene Rolle (aeltere Node: admin)
	Disabled   bool      `json:"disabled"` // gesperrt
	Source     string    `json:"source"`   // local, ldap, oidc
}

// Conflict ist ein Benutzername mit verschiedenen Versionen im Cluster (die eigene zuerst).
type Conflict struct {
	Username string    `json:"username"`
	Versions []Version `json:"versions"`
}

func version(uid, node string, u clusterUser, own bool) Version {
	u = u.norm()
	return Version{UID: uid, Node: node, Username: u.Username, CreatedAt: store.ParseTime(u.CreatedAt), TwoFA: u.TOTP != "", Identities: len(u.Identities), Own: own,
		Role: u.Role, Disabled: u.Disabled, Source: u.Source}
}

func (c *Cluster) open(x conflict) (clusterUser, bool) {
	var u clusterUser
	if c.box == nil {
		return u, false
	}
	plain, err := c.box.Decrypt(x.Data)
	if err != nil || json.Unmarshal([]byte(plain), &u) != nil {
		return u, false
	}
	return u, true
}

// Conflicts: gleichnamige Benutzer mit verschiedenen Versionen im Cluster (leer = keine Abweichung). Nur Namen, die es
// hier noch gibt; abweichende Versionen nach Namen gruppiert.
func (c *Cluster) Conflicts(ctx context.Context) []Conflict {
	var out []Conflict
	idx := map[string]int{}
	for _, x := range c.conflicts(ctx) {
		u, ok := c.open(x)
		if !ok {
			continue
		}
		key := strings.ToLower(x.Username)
		i, seen := idx[key]
		if !seen {
			own, err := c.byName(ctx, x.Username)
			if err != nil || own == nil {
				continue
			}
			out = append(out, Conflict{Username: own.u.Username, Versions: []Version{version(own.uid, "", own.u, true)}})
			i = len(out) - 1
			idx[key] = i
		}
		out[i].Versions = append(out[i].Versions, version(x.UID, x.Node, u, false))
	}
	return out
}

// Choose waehlt eine Version (Kennung aus Conflicts) fuer den ganzen Cluster: der Benutzer hier wird an Ort und Stelle
// zu dieser Version (lokale Nummer, Passkeys und die Sitzung keep bleiben), die anderen Versionen sind abgeloest. Die
// Wahl geht an die anderen Nodes. Liefert den Namen und die verworfenen Versionen (fuer das Audit).
func (c *Cluster) Choose(ctx context.Context, uid, keep string) (string, []Version, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	all := c.conflicts(ctx)
	var name string
	if own, err := c.byUID(ctx, uid); err != nil {
		return "", nil, err
	} else if own != nil {
		name = own.u.Username
	} else if i := slices.IndexFunc(all, func(x conflict) bool { return x.UID == uid }); i >= 0 {
		name = all[i].Username
	}
	if name == "" {
		return "", nil, ErrChoice
	}
	own, err := c.byName(ctx, name)
	if err != nil {
		return "", nil, err
	}
	var pick *clusterUser
	var dropped []Version
	replaces := []string{}
	for _, x := range all {
		if !strings.EqualFold(x.Username, name) {
			continue
		}
		u, ok := c.open(x)
		if x.UID == uid {
			if !ok {
				return "", nil, ErrChoice
			}
			pick = &u
			continue
		}
		replaces = append(replaces, x.UID)
		dropped = append(dropped, version(x.UID, x.Node, u, false))
	}
	if own == nil || pick == nil && own.uid != uid || len(replaces) == 0 && pick == nil {
		return "", nil, ErrChoice
	}
	now := store.Now()
	if pick == nil { // die eigene Version gilt
		pick = &own.u
	} else {
		replaces = append(replaces, own.uid)
		dropped = append([]Version{version(own.uid, "", own.u, true)}, dropped...)
	}
	for _, r := range append(pick.Replaces, own.u.Replaces...) {
		if r != uid && !slices.Contains(replaces, r) {
			replaces = append(replaces, r)
		}
	}
	sort.Strings(replaces)
	pick.Replaces, pick.ChosenAt = replaces, now
	if err := c.write(ctx, own, uid, *pick, keep, ""); err != nil {
		return "", nil, err
	}
	if err := c.dropConflicts(ctx, func(x conflict) bool { return strings.EqualFold(x.Username, name) }); err != nil {
		return "", nil, err
	}
	return own.u.Username, dropped, nil
}

// ---------------------------------------------------------------- SSO-Einrichtung

func (c *Cluster) applySSO(ctx context.Context, data json.RawMessage, deleted bool) error {
	var in clusterSSO
	if !deleted {
		if err := json.Unmarshal(data, &in); err != nil {
			return err
		}
		if in.Incomplete {
			return nil
		}
		u, err := url.Parse(in.Issuer)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || in.ClientID == "" {
			return errFormat
		}
	}
	if in.Scopes == "" {
		in.Scopes = defaultScopes
	}
	enc := ""
	if in.Secret != "" && c.box != nil {
		enc = c.box.Encrypt(in.Secret)
	}
	for k, v := range map[string]string{SetOIDCIssuer: in.Issuer, SetOIDCClient: in.ClientID, SetOIDCSecret: enc, SetOIDCLabel: in.Label, SetOIDCScopes: in.Scopes} {
		if err := c.st.SetSetting(ctx, k, v); err != nil {
			return err
		}
	}
	if in.JIT != nil { // aeltere Node ohne die Felder: hier unveraendert
		v := "0"
		if *in.JIT {
			v = "1"
		}
		if err := c.st.SetSetting(ctx, authcfg.SetOIDCJIT, v); err != nil {
			return err
		}
	}
	if in.GroupClaim != nil && len(*in.GroupClaim) <= 200 {
		if err := c.st.SetSetting(ctx, authcfg.SetOIDCGroupClaim, strings.TrimSpace(*in.GroupClaim)); err != nil {
			return err
		}
	}
	c.st.LoginChanged(ctx, ItemSSO, ssoID, deleted)
	if deleted {
		c.audit(ctx, "sso.cluster.delete", "", "")
	} else {
		c.audit(ctx, "sso.cluster.update", in.Issuer, in.ClientID)
	}
	return nil
}

// SSOChanged meldet eine geaenderte SSO-Einrichtung an den Cluster (web/auth_oidc.go nach dem Speichern; die Schalter
// auth.oidc.jit und auth.oidc.group_claim gehen mit, authcfg.SaveOIDCJIT meldet sie selbst).
func SSOChanged(ctx context.Context, st *store.Store) {
	st.LoginChanged(ctx, ItemSSO, ssoID, st.SettingOr(ctx, SetOIDCIssuer, "") == "")
}
