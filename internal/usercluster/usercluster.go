// Package usercluster gleicht Benutzer und Anmeldung ueber den Cluster ab (internal/peer, Modul users; Bereiche
// accounts und sso, ohne Einstellung aus). Benutzerkonten gehen mit Passwort-Hash, App-2FA (Geheimnis und gehashte
// Wiederherstellungscodes), Sprache, Zeitzone und den verknuepften SSO-Konten; die SSO-Einrichtung (OIDC) mit
// Client-Secret, das hier mit dem eigenen Schluessel verschluesselt wird. Ueber die Leitung geht alles im Klartext
// (HTTPS, an die Kopplung gebunden), gespeichert wird wie bisher (Hash und 2FA-Geheimnis wie lokal, Secret verschluesselt).
//
// Je Node bleiben: Passkeys (an den Hostnamen gebunden), Sitzungen, letzte Anmeldung, Sperren nach Fehlversuchen,
// API- und MCP-Keys, die feste Rueckleit-Adresse fuer SSO (base_url, enthaelt den eigenen Hostnamen) und Forward-Auth
// komplett (die Proxy-Adressen gehoeren zum Netz der Node).
//
// Kennung eines Benutzers im Cluster ist users.uid. Gleichnamige Benutzer mit verschiedener Kennung:
//   - exakt gleich (Name, Hash, 2FA, Codes, Sprache, Zeitzone, SSO-Konten): die kleinere Kennung gilt, die Node mit
//     der groesseren uebernimmt sie (lokale Nummer, Passkeys und Sitzungen bleiben);
//   - sonst Abweichung: nichts wird ueberschrieben, jede Node behaelt ihren Benutzer, die Seite Cluster stellt die
//     Versionen zur Wahl. Die Wahl geht mit dem gewaehlten Benutzer hinaus (abgeloeste Kennungen, Zeitpunkt); eine
//     Node, deren Benutzer darin abgeloest ist, uebernimmt den gewaehlten an seiner Stelle. Bei zwei Wahlen gilt die
//     juengere.
//
// Dieselbe Kennung auf beiden Seiten (also schon ueber den Cluster abgeglichen): die juengere Aenderung gewinnt.
//
// Schutz: Eine Loeschung aus dem Cluster entfernt nie den letzten Benutzer einer Node (alle Benutzer sind
// Administratoren, es gibt keine Rollen und kein Sperren). Die Wahl ersetzt den Benutzer an Ort und Stelle, die eigene
// Sitzung bleibt. Aendert eine Uebernahme Passwort oder 2FA, enden die Sitzungen dieses Benutzers auf der Node.
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

	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

// Kennungen fuer den Cluster.
const (
	ModuleID     = "users"
	ItemAccounts = "accounts"
	ItemSSO      = "sso"

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
	// ErrChoice: die gewaehlte Version gibt es (hier) nicht (mehr).
	ErrChoice = errors.New("unknown user version")

	errItem   = errors.New("cluster: unknown area")
	uidRe     = regexp.MustCompile(`^[0-9a-f]{16,64}$`)
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`) // wie web/handlers_core.go
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
}

// same: exakt gleicher Benutzer (ohne Kennung, Anlegezeit und Wahl).
func (u clusterUser) same(o clusterUser) bool {
	if !strings.EqualFold(u.Username, o.Username) || u.Password != o.Password || u.TOTP != o.TOTP || u.Recovery != o.Recovery ||
		u.Lang != o.Lang || u.Timezone != o.Timezone || len(u.Identities) != len(o.Identities) {
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
	id  int64
	uid string
	u   clusterUser
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
	var repl string
	err := c.st.Reader().QueryRowContext(ctx, `SELECT id, uid, username, password_hash, totp_secret, totp_recovery, lang, timezone, created_at,
		cluster_replaces, cluster_chosen_at FROM users WHERE `+where, arg).Scan(&l.id, &l.uid, &l.u.Username, &l.u.Password, &l.u.TOTP, &l.u.Recovery,
		&l.u.Lang, &l.u.Timezone, &l.u.CreatedAt, &repl, &l.u.ChosenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	l.u.Replaces = splitList(repl)
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

// ClusterIDs: alle Benutzer bzw. die SSO-Einrichtung, wenn eine da ist (erster Abgleich).
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
		b, err := json.Marshal(in)
		return b, err == nil, err
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
		if _, err := c.st.DeleteUser(ctx, cur.id); err != nil {
			return err
		}
		c.audit(ctx, "user.cluster.delete", cur.u.Username, "")
		return nil
	}
	var in clusterUser
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	if !nameRe.MatchString(in.Username) || in.Password == "" {
		return errFormat
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
			if _, err := c.st.DeleteUser(ctx, cur.id); err != nil {
				return err
			}
		}
		if err := c.write(ctx, same, uid, in, "", "user.cluster.choice"); err != nil {
			return err
		}
		return c.dropConflicts(ctx, func(x conflict) bool { return strings.EqualFold(x.Username, in.Username) })
	case slices.Contains(same.u.Replaces, uid):
		return ErrReplaced
	case cur == nil && same.u.same(in):
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

// write legt einen Benutzer an (l nil) oder ersetzt l (auch mit neuer Kennung) samt SSO-Konten. Aendern sich Passwort
// oder 2FA, enden seine Sitzungen hier (ausser keep). Meldet die Aenderung an den Cluster und ins Audit (action "" =
// kein Audit).
func (c *Cluster) write(ctx context.Context, l *localUser, uid string, in clusterUser, keep, action string) error {
	created := in.CreatedAt
	if store.ParseTime(created).IsZero() {
		created = store.Now()
	}
	tx, err := c.st.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id int64
	details := ""
	if l == nil {
		res, err := tx.ExecContext(ctx, `INSERT INTO users (uid, username, password_hash, totp_secret, totp_recovery, lang, timezone, created_at,
			cluster_replaces, cluster_chosen_at) VALUES (?,?,?,?,?,?,?,?,?,?)`, uid, in.Username, in.Password, in.TOTP, in.Recovery, in.Lang, in.Timezone,
			created, strings.Join(in.Replaces, ","), in.ChosenAt)
		if err != nil {
			return err
		}
		id, _ = res.LastInsertId()
	} else {
		id = l.id
		if _, err := tx.ExecContext(ctx, `UPDATE users SET uid = ?, username = ?, password_hash = ?, totp_secret = ?, totp_recovery = ?, lang = ?,
			timezone = ?, cluster_replaces = ?, cluster_chosen_at = ? WHERE id = ?`, uid, in.Username, in.Password, in.TOTP, in.Recovery, in.Lang, in.Timezone,
			strings.Join(in.Replaces, ","), in.ChosenAt, id); err != nil {
			return err
		}
		var ch []string
		if l.u.Password != in.Password {
			ch = append(ch, "password")
		}
		if l.u.TOTP != in.TOTP {
			ch = append(ch, "2fa")
		}
		if len(ch) > 0 { // wie beim Aendern hier: andere Sitzungen enden
			if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND id != ?`, id, keep); err != nil {
				return err
			}
		}
		if l.u.Recovery != in.Recovery && l.u.TOTP == in.TOTP {
			ch = append(ch, "recovery_codes")
		}
		if l.u.Lang != in.Lang || l.u.Timezone != in.Timezone {
			ch = append(ch, "lang="+in.Lang+" timezone="+in.Timezone)
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
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	c.st.LoginChanged(ctx, ItemAccounts, uid, false)
	if len(in.Replaces) > 0 { // durch die Wahl erledigte Abweichungen
		if err := c.dropConflicts(ctx, func(x conflict) bool { return slices.Contains(in.Replaces, x.UID) }); err != nil {
			return err
		}
	}
	if action != "" {
		c.audit(ctx, action, in.Username, details)
	}
	return nil
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
}

// Conflict ist ein Benutzername mit verschiedenen Versionen im Cluster (die eigene zuerst).
type Conflict struct {
	Username string    `json:"username"`
	Versions []Version `json:"versions"`
}

func version(uid, node string, u clusterUser, own bool) Version {
	return Version{UID: uid, Node: node, Username: u.Username, CreatedAt: store.ParseTime(u.CreatedAt), TwoFA: u.TOTP != "", Identities: len(u.Identities), Own: own}
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
	c.st.LoginChanged(ctx, ItemSSO, ssoID, deleted)
	if deleted {
		c.audit(ctx, "sso.cluster.delete", "", "")
	} else {
		c.audit(ctx, "sso.cluster.update", in.Issuer, in.ClientID)
	}
	return nil
}

// SSOChanged meldet eine geaenderte SSO-Einrichtung an den Cluster (web/auth_oidc.go nach dem Speichern).
func SSOChanged(ctx context.Context, st *store.Store) {
	st.LoginChanged(ctx, ItemSSO, ssoID, st.SettingOr(ctx, SetOIDCIssuer, "") == "")
}
