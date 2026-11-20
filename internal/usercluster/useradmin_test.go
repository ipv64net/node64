package usercluster

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/authcfg"
	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

const (
	gidLow  = "11111111111111111111111111111111"
	gidHigh = "99999999999999999999999999999999"
)

func (n *node) rawTOTP(t *testing.T, id int64) string {
	t.Helper()
	var v string
	_ = n.st.Reader().QueryRow(`SELECT totp_secret FROM users WHERE id = ?`, id).Scan(&v)
	return v
}

func (n *node) group(t *testing.T, uid string) *store.Group {
	t.Helper()
	g, err := n.st.GroupByUID(context.Background(), uid)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// legacyData: Stand wie von einer aelteren Node ohne Benutzerverwaltung (ohne die neuen Felder).
func legacyData(t *testing.T, data json.RawMessage) json.RawMessage {
	t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"role", "disabled", "source", "email", "group_uids", "ext_group_uids", "must_change", "jit", "group_claim", "admin_at", "password_at"} {
		delete(m, k)
	}
	b, _ := json.Marshal(m)
	return b
}

func apply(t *testing.T, from, to *node, item, id string, data json.RawMessage) error {
	t.Helper()
	return to.c.ClusterApply(peer.WithClusterOrigin(context.Background(), from.id, time.Now()), item, id, data, false)
}

// Rolle, Sperre, Herkunft, E-Mail und Gruppen kommen an; Rollenwechsel und Sperre beenden die Sitzungen; das
// TOTP-Geheimnis steht verschluesselt in der Datenbank, geht im Klartext hinaus und wird beim Empfaenger mit dessen
// Schluessel verschluesselt.
func TestUserAdminFieldsSync(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	_, _ = a.st.CreateUser(ctx, "admin", "$h0", "de", "UTC") // lokaler Administrator auf A
	g := &store.Group{UID: gidLow, Name: "Leser", Role: store.RoleRead}
	if err := a.st.SaveGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	u, err := a.st.CreateUserWith(ctx, store.NewUser{Username: "lena", PasswordHash: "$h1", Role: store.RoleRead, Email: "lena@example.org", GroupUIDs: []string{gidLow}})
	if err != nil {
		t.Fatal(err)
	}
	_ = a.st.SetUserTOTP(ctx, u.ID, "TOTPLENA", "r1")
	if raw := a.rawTOTP(t, u.ID); !secrets.IsEncrypted(raw) {
		t.Fatalf("totp encrypted on A: %q", raw)
	}
	data, _, _ := a.c.ClusterGet(ctx, ItemAccounts, u.UID)
	if !strings.Contains(string(data), `"totp_secret":"TOTPLENA"`) || !strings.Contains(string(data), `"role":"read"`) {
		t.Fatalf("payload: %s", data)
	}
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	got := b.user(t, "lena")
	if got == nil || got.Role != store.RoleRead || got.Source != store.SourceLocal || got.Email != "lena@example.org" ||
		!slices.Equal(got.GroupUIDs, []string{gidLow}) || got.TOTPSecret != "TOTPLENA" {
		t.Fatalf("user on B: %+v", got)
	}
	if raw := b.rawTOTP(t, got.ID); !secrets.IsEncrypted(raw) || raw == a.rawTOTP(t, u.ID) {
		t.Fatalf("totp re-encrypted with B's key: %q", raw)
	}
	if bg := b.group(t, gidLow); bg == nil || bg.Name != "Leser" || bg.Role != store.RoleRead {
		t.Fatalf("group on B: %+v", bg)
	}
	b.take()

	// Rolle auf A geaendert: Sitzungen von lena auf B enden
	b.addSession(t, "s1", got.ID)
	_ = a.st.UpdateUserAdmin(ctx, u.ID, store.UserAdmin{Role: store.RoleAdmin, Email: "lena@example.org", GroupUIDs: []string{gidLow}})
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	if x := b.user(t, "lena"); x.Role != store.RoleAdmin || b.sessions(t, got.ID) != 0 {
		t.Fatalf("role change on B ends sessions: %+v %d", x, b.sessions(t, got.ID))
	}
	if e := b.audit(t, "user.cluster.update"); e == nil || !strings.Contains(e.Details, "role=admin") {
		t.Fatalf("audit: %+v", e)
	}
	// Sprache geaendert: Sitzungen bleiben
	b.addSession(t, "s2", got.ID)
	_ = a.st.UpdateUserPrefs(ctx, u.ID, "en", "UTC")
	transfer(t, a, b)
	if b.sessions(t, got.ID) != 1 {
		t.Fatal("language change keeps sessions")
	}
	// gesperrt: alle Sitzungen enden
	_ = a.st.UpdateUserAdmin(ctx, u.ID, store.UserAdmin{Role: store.RoleAdmin, Disabled: true, Email: "lena@example.org"})
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	if x := b.user(t, "lena"); !x.Disabled || len(x.GroupUIDs) != 0 || b.sessions(t, got.ID) != 0 {
		t.Fatalf("disabled on B: %+v", x)
	}

	// LDAP-Benutzer ohne Passwort mit fester Kennung: auf beiden Nodes angelegt, kein Konflikt
	uid := store.ExternalUID(store.SourceLDAP, "0a1b2c3d")
	la, err := a.st.CreateUserWith(ctx, store.NewUser{UID: uid, Username: "max@firma.local", Role: store.RoleRead, Source: store.SourceLDAP, ExtGroupUIDs: []string{gidLow}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.st.CreateUserWith(ctx, store.NewUser{UID: uid, Username: "max@firma.local", Role: store.RoleRead, Source: store.SourceLDAP}); err != nil {
		t.Fatal(err)
	}
	b.take()
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	if x := b.user(t, "max@firma.local"); x.UID != la.UID || x.Source != store.SourceLDAP || !slices.Equal(x.ExtGroupUIDs, []string{gidLow}) || len(b.c.Conflicts(ctx)) != 0 {
		t.Fatalf("ldap user on B: %+v", x)
	}
	// lokaler Benutzer ohne Passwort wird abgewiesen, mit „beim naechsten Anmelden setzen“ angenommen
	bad, _ := json.Marshal(clusterUser{Username: "ohnepw", Role: store.RoleRead, Source: store.SourceLocal, Identities: []identity{}})
	if err := apply(t, a, b, ItemAccounts, "abcdefabcdefabcdefabcdefabcdef01", bad); !errors.Is(err, errFormat) {
		t.Fatalf("local user without password: %v", err)
	}
	ok, _ := json.Marshal(clusterUser{Username: "ohnepw", Role: store.RoleRead, Source: store.SourceLocal, MustChange: true, Identities: []identity{}})
	if err := apply(t, a, b, ItemAccounts, "abcdefabcdefabcdefabcdefabcdef01", ok); err != nil {
		t.Fatal(err)
	}
}

// Der letzte aktive lokale Administrator einer Node wird weder herabgestuft noch gesperrt noch geloescht, auch nicht
// ueber eine Gruppe; die Uebernahme fuer ihn bleibt aus (Audit keep_last), andere Benutzer gehen weiter.
func TestLastLocalAdminKept(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	anna, _ := a.st.CreateUser(ctx, "anna", "$h1", "", "UTC")
	bert, _ := a.st.CreateUserWith(ctx, store.NewUser{Username: "bert", PasswordHash: "$h2", Role: store.RoleRead})
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	// auf A gibt es einen weiteren Administrator (nur dort), dann wird anna auf A herabgestuft
	_, _ = a.st.CreateUser(ctx, "carl", "$h3", "", "UTC")
	a.take()
	_ = a.st.UpdateUserAdmin(ctx, anna.ID, store.UserAdmin{Role: store.RoleRead})
	errs := transfer(t, a, b)
	if !errors.Is(errs[anna.UID], ErrLastAdmin) || b.user(t, "anna").Role != store.RoleAdmin {
		t.Fatalf("last local admin on B stays admin: %v %+v", errs, b.user(t, "anna"))
	}
	if e := b.audit(t, "user.cluster.keep_last"); e == nil || e.Target != "anna" || e.Details != "role=read" {
		t.Fatalf("audit: %+v", e)
	}
	// gesperrt
	_ = a.st.UpdateUserAdmin(ctx, anna.ID, store.UserAdmin{Role: store.RoleAdmin, Disabled: true})
	if errs := transfer(t, a, b); !errors.Is(errs[anna.UID], ErrLastAdmin) || b.user(t, "anna").Disabled {
		t.Fatalf("not disabled: %v", errs)
	}
	// geloescht (B hat zwei Benutzer, die Regel „letzter Benutzer“ greift nicht)
	_, _ = a.st.DeleteUser(ctx, anna.ID)
	if errs := transfer(t, a, b); !errors.Is(errs[anna.UID], ErrLastAdmin) || b.user(t, "anna") == nil {
		t.Fatalf("not deleted: %v", errs)
	}
	// bert wird Administrator auf B: danach darf anna gehen
	bb := b.user(t, "bert")
	_ = b.st.UpdateUserAdmin(ctx, bb.ID, store.UserAdmin{Role: store.RoleAdmin})
	if err := b.c.ClusterApply(peer.WithClusterOrigin(ctx, "node-a", time.Now()), ItemAccounts, anna.UID, nil, true); err != nil || b.user(t, "anna") != nil {
		t.Fatalf("delete with another admin: %v", err)
	}
	_ = bert

	// ueber eine Gruppe: dora ist Administratorin nur ueber die Gruppe; deren Rolle wird nicht herabgestuft
	c, d := newTestNode(t, "node-c"), newTestNode(t, "node-d")
	g := &store.Group{UID: gidLow, Name: "Admins", Role: store.RoleAdmin}
	_ = c.st.SaveGroup(ctx, g)
	_, _ = c.st.CreateUserWith(ctx, store.NewUser{Username: "dora", PasswordHash: "$h", Role: store.RoleRead, GroupUIDs: []string{gidLow}})
	if errs := transfer(t, c, d); len(errs) > 0 {
		t.Fatal(errs)
	}
	if u := d.user(t, "dora"); d.st.EffectiveRole(ctx, u) != store.RoleAdmin {
		t.Fatal("dora is admin on D through the group")
	}
	_, _ = c.st.CreateUser(ctx, "emil", "$h", "", "UTC") // auf C noch ein Administrator
	c.take()
	g.Role = store.RoleRead
	_ = c.st.SaveGroup(ctx, g)
	if errs := transfer(t, c, d); !errors.Is(errs[gidLow], ErrLastAdmin) || d.group(t, gidLow).Role != store.RoleAdmin {
		t.Fatalf("group role on D stays: %v", errs)
	}
	_, _ = c.st.DeleteGroup(ctx, gidLow)
	if errs := transfer(t, c, d); !errors.Is(errs[gidLow], ErrLastAdmin) || d.group(t, gidLow) == nil {
		t.Fatalf("group on D stays: %v", errs)
	}
}

// Gemischter Cluster: eine aeltere Node sendet keine Rolle, Sperre, Gruppen - hier bleibt alles, wie es ist (nichts
// wird herauf- oder herabgestuft oder entsperrt); neu angelegt gilt der Stand der aelteren Node (Administrator, lokal).
func TestMixedClusterLegacyFields(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	_, _ = b.st.CreateUser(ctx, "chef", "$h0", "", "UTC")
	u, _ := a.st.CreateUserWith(ctx, store.NewUser{Username: "lena", PasswordHash: "$h1", Role: store.RoleRead})
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	bl := b.user(t, "lena")
	_ = b.st.UpdateUserAdmin(ctx, bl.ID, store.UserAdmin{Role: store.RoleRead, Disabled: true, Email: "x@example.org", GroupUIDs: []string{gidLow}})
	// A (aeltere Node) aendert das Passwort
	_ = a.st.UpdateUserPassword(ctx, u.ID, "$h-neu")
	data, _, _ := a.c.ClusterGet(ctx, ItemAccounts, u.UID)
	if err := apply(t, a, b, ItemAccounts, u.UID, legacyData(t, data)); err != nil {
		t.Fatal(err)
	}
	x := b.user(t, "lena")
	if x.PasswordHash != "$h-neu" || x.Role != store.RoleRead || !x.Disabled || x.Email != "x@example.org" || !slices.Equal(x.GroupUIDs, []string{gidLow}) {
		t.Fatalf("legacy update keeps the admin fields: %+v", x)
	}
	// neu von der aelteren Node: Administrator, lokal
	v, _ := a.st.CreateUser(ctx, "otto", "$h2", "", "UTC")
	data, _, _ = a.c.ClusterGet(ctx, ItemAccounts, v.UID)
	if err := apply(t, a, b, ItemAccounts, v.UID, legacyData(t, data)); err != nil {
		t.Fatal(err)
	}
	if o := b.user(t, "otto"); o.Role != store.RoleAdmin || o.Source != store.SourceLocal || o.Disabled {
		t.Fatalf("legacy create: %+v", o)
	}
	// exaktes Doppel eines Altstands: zusammengefuehrt; ein gesperrter gleichnamiger Benutzer dagegen zur Wahl
	c, d := newTestNode(t, "node-c"), newTestNode(t, "node-d")
	uc, _ := c.st.CreateUser(ctx, "admin", "$same", "de", "UTC")
	ud, _ := d.st.CreateUser(ctx, "admin", "$same", "de", "UTC")
	data, _, _ = c.c.ClusterGet(ctx, ItemAccounts, uc.UID)
	err := apply(t, c, d, ItemAccounts, uc.UID, legacyData(t, data))
	if err != nil {
		t.Fatalf("legacy exact duplicate merges: %v", err)
	}
	if uc.UID < ud.UID && d.user(t, "admin").UID != uc.UID {
		t.Fatal("merged to the smaller uid")
	}
	e, f := newTestNode(t, "node-e"), newTestNode(t, "node-f")
	ue, _ := e.st.CreateUser(ctx, "admin", "$same", "de", "UTC")
	uf, _ := f.st.CreateUser(ctx, "admin", "$same", "de", "UTC")
	_, _ = f.st.CreateUser(ctx, "zweit", "$h", "", "UTC")
	_ = f.st.UpdateUserAdmin(ctx, uf.ID, store.UserAdmin{Role: store.RoleAdmin, Disabled: true})
	data, _, _ = e.c.ClusterGet(ctx, ItemAccounts, ue.UID)
	if err := apply(t, e, f, ItemAccounts, ue.UID, legacyData(t, data)); !errors.Is(err, ErrConflict) {
		t.Fatalf("disabled vs legacy admin is a conflict: %v", err)
	}
	if vs := f.c.Conflicts(ctx); len(vs) != 1 || !vs[0].Versions[0].Disabled || vs[0].Versions[1].Role != store.RoleAdmin {
		t.Fatalf("versions: %+v", vs)
	}
}

// Gruppen: gleicher Name auf zwei Nodes - die kleinere Kennung gilt, die andere Node uebernimmt sie an Ort und Stelle
// und biegt ihre Benutzer um; die alte Kennung liefert eine Umleitung statt eines Loeschvermerks, eine dritte Node
// biegt ebenso um und verliert keine Mitgliedschaft.
func TestGroupNameConflict(t *testing.T) {
	ctx := context.Background()
	a, b, c := newTestNode(t, "node-a"), newTestNode(t, "node-b"), newTestNode(t, "node-c")
	for _, n := range []*node{a, b, c} {
		_, _ = n.st.CreateUser(ctx, "admin", "$h-"+n.id, "", "UTC")
		n.take()
	}
	_ = a.st.SaveGroup(ctx, &store.Group{UID: gidLow, Name: "Admins", Role: store.RoleAdmin, Description: "von A"})
	_ = b.st.SaveGroup(ctx, &store.Group{UID: gidHigh, Name: "admins", Role: store.RoleRead})
	bert, _ := b.st.CreateUserWith(ctx, store.NewUser{Username: "bert", PasswordHash: "$h", Role: store.RoleRead, GroupUIDs: []string{gidHigh}})
	// C hat die Gruppe von B schon samt bert
	if errs := transfer(t, b, c); len(errs) > 0 {
		t.Fatal(errs)
	}
	if c.group(t, gidHigh) == nil || !slices.Equal(c.user(t, "bert").GroupUIDs, []string{gidHigh}) {
		t.Fatal("C has B's group")
	}
	// B bekommt die Gruppe von A: erst beim erneuten Abholen zusammengefuehrt (die Gleichnamigkeit besteht noch), dann
	// gilt die kleinere Kennung, Inhalt von A, bert zeigt auf sie
	defer func(w time.Duration) { groupMergeWait = w }(groupMergeWait)
	groupMergeWait = 0
	ga, _, _ := a.c.ClusterGet(ctx, ItemGroups, gidLow)
	if errs := transfer(t, a, b); len(errs) != 1 || !errors.Is(errs[gidLow], errGroupWait) || b.group(t, gidHigh) == nil {
		t.Fatalf("first time: wait for the retry: %v", errs)
	}
	if err := apply(t, a, b, ItemGroups, gidLow, ga); err != nil {
		t.Fatal(err)
	}
	if b.group(t, gidHigh) != nil {
		t.Fatal("B: larger uid gone")
	}
	if g := b.group(t, gidLow); g == nil || g.Name != "Admins" || g.Role != store.RoleAdmin || g.Description != "von A" {
		t.Fatalf("B adopts the smaller uid: %+v", g)
	}
	if x := b.user(t, "bert"); !slices.Equal(x.GroupUIDs, []string{gidLow}) || b.st.EffectiveRole(ctx, x) != store.RoleAdmin {
		t.Fatalf("bert on B: %+v", x)
	}
	if e := b.audit(t, "group.cluster.merge"); e == nil {
		t.Fatal("merge in the audit log")
	}
	for _, ch := range b.take() {
		if ch.item == ItemAccounts || ch.deleted {
			t.Fatalf("no user changes and no deletion reported: %+v", ch)
		}
	}
	// die alte Kennung: Umleitung statt Loeschvermerk
	old, found, err := b.c.ClusterGet(ctx, ItemGroups, gidHigh)
	if err != nil || !found || !strings.Contains(string(old), `"into":"`+gidLow+`"`) {
		t.Fatalf("redirect for the old uid: %s %v %v", old, found, err)
	}
	if err := apply(t, b, c, ItemGroups, gidHigh, old); err != nil {
		t.Fatal(err)
	}
	if c.group(t, gidHigh) != nil || c.group(t, gidLow) == nil || !slices.Equal(c.user(t, "bert").GroupUIDs, []string{gidLow}) {
		t.Fatalf("C follows the redirect, bert keeps the membership: %+v", c.user(t, "bert"))
	}
	// ein Benutzer mit der alten Kennung (von einer Node, die noch nicht umgebogen hat) wird umgeleitet
	data, _, _ := b.c.ClusterGet(ctx, ItemAccounts, bert.UID)
	var cu clusterUser
	_ = json.Unmarshal(data, &cu)
	cu.GroupUIDs, cu.Lang = []string{gidHigh}, "en"
	data, _ = json.Marshal(cu)
	if err := apply(t, b, c, ItemAccounts, bert.UID, data); err != nil {
		t.Fatal(err)
	}
	if x := c.user(t, "bert"); !slices.Equal(x.GroupUIDs, []string{gidLow}) || x.Lang != "en" {
		t.Fatalf("old group uid redirected: %+v", x)
	}
	// A: die groessere Kennung von B kommt an (B hatte sie gemeldet) - A behaelt die eigene
	hi, _ := json.Marshal(clusterGroup{Name: "admins", Role: store.RoleRead})
	if err := apply(t, b, a, ItemGroups, gidHigh, hi); !errors.Is(err, errGroupWait) {
		t.Fatalf("first time: wait for the retry: %v", err)
	}
	if err := apply(t, b, a, ItemGroups, gidHigh, hi); err != nil {
		t.Fatal(err)
	}
	if a.group(t, gidHigh) != nil || a.group(t, gidLow).Role != store.RoleAdmin {
		t.Fatal("A keeps the smaller uid")
	}
	// Loeschen kommt an
	_, _ = a.st.DeleteGroup(ctx, gidLow)
	a.take()
	if err := a.c.ClusterApply(ctx, ItemGroups, gidLow, nil, false); err == nil {
		t.Fatal("empty data must fail")
	}
	if err := c.c.ClusterApply(peer.WithClusterOrigin(ctx, "node-a", time.Now()), ItemGroups, gidLow, nil, true); err != nil || c.group(t, gidLow) != nil {
		t.Fatalf("delete on C: %v", err)
	}
}

// directory: LDAP mit Bind-Passwort (beim Empfaenger neu verschluesselt) und 2FA-Pflicht; nicht lesbares
// Bind-Passwort geht als incomplete hinaus und aendert drueben nichts.
func TestDirectorySync(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	if ids, _ := a.c.ClusterIDs(ctx, ItemDirectory); len(ids) != 0 {
		t.Fatalf("nothing configured: %v", ids)
	}
	cfg := authcfg.LDAPConfig{Enabled: true, URLs: []string{"ldaps://dc.firma.local:636"}, Profile: authcfg.ProfileAD, BindDN: "CN=svc,DC=firma",
		BindPasswordEnc: a.box.Encrypt("bind-geheim"), BaseDN: "DC=firma", Nested: true, TimeoutSec: 5}
	_ = authcfg.SaveLDAP(ctx, a.st, cfg)
	_ = authcfg.SetTwoFARequired(ctx, a.st, true)
	if ids, _ := a.c.ClusterIDs(ctx, ItemDirectory); len(ids) != 1 || ids[0] != authcfg.DirectoryID {
		t.Fatalf("directory ids: %v", ids)
	}
	data, _, _ := a.c.ClusterGet(ctx, ItemDirectory, authcfg.DirectoryID)
	if strings.Contains(string(data), "enc:v1:") || !strings.Contains(string(data), "bind-geheim") {
		t.Fatalf("plain bind password over the cluster link: %s", data)
	}
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	got := authcfg.LoadLDAP(ctx, b.st)
	plain, _ := b.box.Decrypt(got.BindPasswordEnc)
	if !got.Enabled || got.BindDN != "CN=svc,DC=firma" || got.URLs[0] != "ldaps://dc.firma.local:636" || plain != "bind-geheim" ||
		got.BindPasswordEnc == cfg.BindPasswordEnc || !authcfg.TwoFARequired(ctx, b.st) {
		t.Fatalf("directory on B: %+v", got)
	}
	if e := b.audit(t, "auth.cluster.directory"); e == nil || e.Origin != "cluster" {
		t.Fatalf("audit: %+v", e)
	}
	// Bind-Passwort auf A nicht lesbar (fremder Schluessel): incomplete, B behaelt seinen Stand
	other, _ := secrets.New(make([]byte, 32))
	cfg.BindPasswordEnc, cfg.BindDN = other.Encrypt("x"), "CN=neu"
	_ = authcfg.SaveLDAP(ctx, a.st, cfg)
	_ = authcfg.SetTwoFARequired(ctx, a.st, false)
	data, _, _ = a.c.ClusterGet(ctx, ItemDirectory, authcfg.DirectoryID)
	if !strings.Contains(string(data), `"incomplete":true`) {
		t.Fatalf("incomplete: %s", data)
	}
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	if authcfg.LoadLDAP(ctx, b.st).BindDN != "CN=svc,DC=firma" || !authcfg.TwoFARequired(ctx, b.st) {
		t.Fatal("B keeps its directory while A's is incomplete")
	}
	// Loeschvermerk aendert nichts
	if err := b.c.ClusterApply(peer.WithClusterOrigin(ctx, "node-a", time.Now()), ItemDirectory, authcfg.DirectoryID, nil, true); err != nil || !authcfg.TwoFARequired(ctx, b.st) {
		t.Fatal("deletion keeps the settings")
	}
}

// SSO: „Benutzer ueber Gruppen anlegen“ und Claim-Name gehen mit; SaveOIDCJIT meldet die Einrichtung; eine aeltere
// Node ohne die Felder aendert sie nicht.
func TestSSOJITSync(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	// ohne SSO: keine Meldung (sie gaelte als Entfernen)
	_ = authcfg.SaveOIDCJIT(ctx, a.st, true, "roles")
	if ch := a.take(); len(ch) != 0 {
		t.Fatalf("no sso, nothing reported: %+v", ch)
	}
	for k, v := range map[string]string{SetOIDCIssuer: "https://auth.example", SetOIDCClient: "node64", SetOIDCSecret: a.box.Encrypt("s")} {
		_ = a.st.SetSetting(ctx, k, v)
	}
	_ = authcfg.SaveOIDCJIT(ctx, a.st, true, " roles ")
	if ch := a.take(); len(ch) != 1 || ch[0] != (change{ItemSSO, ssoID, false}) {
		t.Fatalf("SaveOIDCJIT reports sso: %+v", ch)
	}
	SSOChanged(ctx, a.st)
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	if on, claim := authcfg.OIDCJIT(ctx, b.st); !on || claim != "roles" {
		t.Fatalf("jit on B: %v %q", on, claim)
	}
	// aeltere Node: Felder fehlen, B behaelt sie
	data, _, _ := a.c.ClusterGet(ctx, ItemSSO, ssoID)
	if err := apply(t, a, b, ItemSSO, ssoID, legacyData(t, data)); err != nil {
		t.Fatal(err)
	}
	if on, claim := authcfg.OIDCJIT(ctx, b.st); !on || claim != "roles" {
		t.Fatalf("legacy sso keeps jit: %v %q", on, claim)
	}
	// ausgeschaltet, Claim zurueck auf Standard
	_ = authcfg.SaveOIDCJIT(ctx, a.st, false, "")
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	if on, claim := authcfg.OIDCJIT(ctx, b.st); on || claim != "groups" {
		t.Fatalf("jit off on B: %v %q", on, claim)
	}
}
