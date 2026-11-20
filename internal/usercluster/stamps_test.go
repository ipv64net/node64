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
	"github.com/ipv64net/node64/internal/store"
)

// withoutKeys: Stand ohne die genannten Felder (wie von einer Node, die sie noch nicht kennt).
func withoutKeys(t *testing.T, data json.RawMessage, keys ...string) json.RawMessage {
	t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		delete(m, k)
	}
	b, _ := json.Marshal(m)
	return b
}

// Sperre, Herabstufung und Passwort-Ruecksetzung auf A nimmt keine eigene Aenderung des Benutzers auf B zurueck
// (Anmeldung mit 2FA); A behaelt sie, meldet den zusammengefuehrten Stand neu, B uebernimmt ihn ohne erneute Meldung.
// Unveraenderte Einstellungen melden nichts; das eigene neue Passwort auf B kommt an. Eine Node ohne die Zeitpunkte:
// der Zeitpunkt ihrer Aenderung gilt (wie bisher).
func TestAdminFieldsNotUndoneBySelfService(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	_, _ = a.st.CreateUser(ctx, "admin", "$h0", "", "UTC")
	u, _ := a.st.CreateUserWith(ctx, store.NewUser{Username: "lena", PasswordHash: "$h1", Role: store.RoleAdmin})
	_ = a.st.SetUserTOTP(ctx, u.ID, "JBSWY3DPEHPK3PXP", "r1")
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	bl := b.user(t, "lena")
	b.take()

	_ = a.st.UpdateUserAdmin(ctx, u.ID, store.UserAdmin{Role: store.RoleRead, Disabled: true})
	_ = a.st.UpdateUserPassword(ctx, u.ID, "$h-reset")
	a.take()
	if ok, _ := b.st.UseTOTPStep(ctx, bl.ID, 2000); !ok {
		t.Fatal("step on B")
	}
	if errs := transfer(t, b, a); !superseded(errs[u.UID]) {
		t.Fatalf("A keeps its newer admin fields and announces them: %v", errs)
	}
	if x := a.user(t, "lena"); x.Role != store.RoleRead || !x.Disabled || x.PasswordHash != "$h-reset" || a.totpStep(t, x.ID) != 2000 {
		t.Fatalf("lena on A: %+v step %d", x, a.totpStep(t, x.ID))
	}
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatalf("B takes the merged state: %v", errs)
	}
	if y := b.user(t, "lena"); y.Role != store.RoleRead || !y.Disabled || y.PasswordHash != "$h-reset" {
		t.Fatalf("lena on B: %+v", y)
	}
	b.take()

	// unveraenderte Einstellungen: keine Meldung
	_ = b.st.UpdateUserPrefs(ctx, bl.ID, bl.Lang, bl.Timezone)
	if ch := b.take(); len(ch) != 0 {
		t.Fatalf("unchanged prefs reported: %+v", ch)
	}
	// eigenes neues Passwort auf B: kommt an, Sperre bleibt
	_ = b.st.UpdateUserPassword(ctx, bl.ID, "$h-own")
	if errs := transfer(t, b, a); len(errs) > 0 {
		t.Fatal(errs)
	}
	if x := a.user(t, "lena"); x.PasswordHash != "$h-own" || !x.Disabled || x.Role != store.RoleRead {
		t.Fatalf("own password on A: %+v", x)
	}

	// Node ohne die Zeitpunkte (bis 1.7.10): ihre Aenderung gilt als Ganzes, wie bisher
	_ = a.st.UpdateUserAdmin(ctx, u.ID, store.UserAdmin{Role: store.RoleRead, Disabled: true})
	data, _, _ := b.c.ClusterGet(ctx, ItemAccounts, bl.UID)
	var cu clusterUser
	_ = json.Unmarshal(withoutKeys(t, data, "admin_at", "password_at"), &cu)
	cu.Disabled = false
	old, _ := json.Marshal(cu)
	if err := apply(t, b, a, ItemAccounts, u.UID, old); err != nil {
		t.Fatal(err)
	}
	if x := a.user(t, "lena"); x.Disabled {
		t.Fatalf("change of an older node applies as before: %+v", x)
	}
}

// Ein auf A geloeschter Benutzer kommt durch eine spaetere eigene Aenderung auf B (die die Loeschung noch nicht kannte)
// nicht zurueck: A meldet die Loeschung erneut, B loescht. Eine juengere Aenderung der Benutzerverwaltung legt ihn
// wieder an.
func TestDeletedUserNotRevived(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	_, _ = a.st.CreateUser(ctx, "admin", "$h0", "", "UTC")
	u, _ := a.st.CreateUser(ctx, "lena", "$h1", "de", "UTC")
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	bl := b.user(t, "lena")
	b.take()
	if ok, _ := a.st.DeleteUser(ctx, u.ID); !ok || a.st.UserDeletedAt(ctx, u.UID).IsZero() {
		t.Fatal("deletion noted on A")
	}
	a.take()
	_ = b.st.UpdateUserPrefs(ctx, bl.ID, "en", "UTC")
	stale, _, _ := b.c.ClusterGet(ctx, ItemAccounts, bl.UID)
	if errs := transfer(t, b, a); !superseded(errs[u.UID]) || a.user(t, "lena") != nil {
		t.Fatalf("deleted user not revived on A: %v", errs)
	}
	if ch := a.take(); len(ch) != 1 || ch[0] != (change{ItemAccounts, u.UID, true}) {
		t.Fatalf("deletion announced again: %+v", ch)
	}
	if err := b.c.ClusterApply(peer.WithClusterOrigin(ctx, "node-a", time.Now()), ItemAccounts, u.UID, nil, true); err != nil || b.user(t, "lena") != nil {
		t.Fatalf("B deletes: %v", err)
	}
	// juengere Aenderung der Benutzerverwaltung (Node, die die Loeschung nicht kannte): legt ihn wieder an
	var cu clusterUser
	_ = json.Unmarshal(stale, &cu)
	cu.AdminAt = store.Now()
	newer, _ := json.Marshal(cu)
	if err := apply(t, b, a, ItemAccounts, u.UID, newer); err != nil || a.user(t, "lena") == nil {
		t.Fatalf("newer admin change recreates: %v", err)
	}
}

// Gemischter Cluster beim Update: Rolle auf A (Node64 1.7) vergeben, B hatte noch keine Benutzerverwaltung (nach dem
// Update: Administrator, Zeitpunkt unbekannt). Die erste Aenderung auf B nimmt die Rolle auf A nicht zurueck, B
// bekommt sie.
func TestMixedUpgradeRoleArrives(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	_, _ = a.st.CreateUser(ctx, "admin", "$h0", "", "UTC")
	g, _ := a.st.CreateUserWith(ctx, store.NewUser{Username: "gast", PasswordHash: "$h1", Role: store.RoleRead})
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	// Bestand nach dem Update wie die Migration: A (1.7) mit vergebener Rolle, B (<=1.6) mit admin
	_, _ = b.st.Writer().Exec(`UPDATE users SET role = 'admin'`)
	ms, _ := store.CoreMigrations()
	var seed string
	for _, m := range ms {
		for _, line := range strings.Split(m.SQL, "\n") {
			if m.Version == 10 && strings.HasPrefix(line, "UPDATE users SET admin_at") {
				seed = line
			}
		}
	}
	for _, n := range []*node{a, b} {
		_, _ = n.st.Writer().Exec(`UPDATE users SET admin_at = ''`)
		if _, err := n.st.Writer().Exec(seed); seed == "" || err != nil {
			t.Fatalf("migration 10: %q %v", seed, err)
		}
	}
	bg := b.user(t, "gast")
	b.take()
	_ = b.st.UpdateUserPrefs(ctx, bg.ID, "en", "UTC")
	if errs := transfer(t, b, a); !superseded(errs[g.UID]) {
		t.Fatalf("A keeps the role: %v", errs)
	}
	if x := a.user(t, "gast"); x.Role != store.RoleRead || x.Lang != "en" {
		t.Fatalf("gast on A: %+v", x)
	}
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	if x := b.user(t, "gast"); x.Role != store.RoleRead {
		t.Fatalf("role arrives on B: %+v", x)
	}
}

// Uebernommene Wahl, bei der die Node einen hoeheren 2FA-Schritt behaelt: die Abweichung ist trotzdem erledigt.
func TestChoiceKeptClearsConflict(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	ua, _ := a.st.CreateUser(ctx, "admin", "$argon2id$pw-a", "de", "UTC")
	ub, _ := b.st.CreateUser(ctx, "admin", "$argon2id$pw-b", "de", "UTC")
	_, _ = a.st.UseTOTPStep(ctx, ua.ID, 100)
	_, _ = b.st.UseTOTPStep(ctx, ub.ID, 200)
	for _, p := range [][2]*node{{a, b}, {b, a}} {
		if errs := transfer(t, p[0], p[1]); !errors.Is(errs[p[0].user(t, "admin").UID], ErrConflict) {
			t.Fatalf("conflict on %s: %v", p[1].id, errs)
		}
	}
	a.take()
	if _, _, err := a.c.Choose(ctx, ua.UID, "x"); err != nil {
		t.Fatal(err)
	}
	if errs := transfer(t, a, b); !superseded(errs[ua.UID]) {
		t.Fatalf("choice with a higher own step: %v", errs)
	}
	if x := b.user(t, "admin"); x.UID != ua.UID || x.PasswordHash != "$argon2id$pw-a" || b.totpStep(t, x.ID) != 200 {
		t.Fatalf("B adopts the choice: %+v", x)
	}
	if cs := b.c.Conflicts(ctx); len(cs) != 0 {
		t.Fatalf("conflict resolved on B: %+v", cs)
	}
}

// Umbenennen und Neuanlegen auf derselben Node: trifft die neue Gruppe auf einer nachholenden Node vor der
// Umbenennung der alten ein, verschmelzen sie nicht (die alten Mitglieder kommen nicht in die neue Gruppe).
func TestGroupRenameRecreateNoMerge(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	_, _ = a.st.CreateUser(ctx, "admin", "$h0", "", "UTC")
	_ = a.st.SaveGroup(ctx, &store.Group{UID: gidHigh, Name: "Admins", Role: store.RoleAdmin})
	_, _ = a.st.CreateUserWith(ctx, store.NewUser{Username: "bert", PasswordHash: "$h", Role: store.RoleRead, GroupUIDs: []string{gidHigh}})
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	_ = a.st.SaveGroup(ctx, &store.Group{UID: gidHigh, Name: "Admins-alt", Role: store.RoleRead})
	_ = a.st.SaveGroup(ctx, &store.Group{UID: gidLow, Name: "Admins", Role: store.RoleAdmin, Description: "neu"})
	a.take()
	// B holt nach: die neue Gruppe zuerst
	gc, _, _ := a.c.ClusterGet(ctx, ItemGroups, gidLow)
	if err := apply(t, a, b, ItemGroups, gidLow, gc); !errors.Is(err, errGroupWait) {
		t.Fatalf("same name: wait for the retry: %v", err)
	}
	gb, _, _ := a.c.ClusterGet(ctx, ItemGroups, gidHigh)
	if err := apply(t, a, b, ItemGroups, gidHigh, gb); err != nil {
		t.Fatal(err)
	}
	if err := apply(t, a, b, ItemGroups, gidLow, gc); err != nil {
		t.Fatalf("retry after the rename: %v", err)
	}
	if g := b.group(t, gidHigh); g == nil || g.Name != "Admins-alt" {
		t.Fatalf("old group renamed on B: %+v", g)
	}
	if g := b.group(t, gidLow); g == nil || g.Name != "Admins" || g.Description != "neu" {
		t.Fatalf("new group on B: %+v", g)
	}
	if x := b.user(t, "bert"); !slices.Equal(x.GroupUIDs, []string{gidHigh}) || b.st.EffectiveRole(ctx, x) != store.RoleRead || len(b.c.aliases(ctx)) != 0 {
		t.Fatalf("bert stays in the old group: %+v %v", x, b.c.aliases(ctx))
	}
}

// directory je Teil: eine Node ohne LDAP-Einrichtung verteilt beim Schalten der 2FA-Pflicht keine leere Anbindung;
// LDAP-Speichern nimmt eine juengere 2FA-Pflicht nicht zurueck; eine Node ohne die Felder gilt als Ganzes.
func TestDirectoryParts(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	cfg := authcfg.LDAPConfig{Enabled: true, URLs: []string{"ldaps://dc:636"}, Profile: authcfg.ProfileAD, BindDN: "CN=svc",
		BindPasswordEnc: a.box.Encrypt("bind-geheim"), BaseDN: "DC=firma"}
	_ = authcfg.SaveLDAP(ctx, a.st, cfg)
	_ = authcfg.SetTwoFARequired(ctx, b.st, true)
	data, _, _ := b.c.ClusterGet(ctx, ItemDirectory, authcfg.DirectoryID)
	if !strings.Contains(string(data), `"ldap_unset":true`) {
		t.Fatalf("payload: %s", data)
	}
	a.take()
	if err := apply(t, b, a, ItemDirectory, authcfg.DirectoryID, data); !superseded(err) {
		t.Fatalf("A keeps its LDAP and announces: %v", err)
	}
	if got := authcfg.LoadLDAP(ctx, a.st); !got.Enabled || got.BindDN != "CN=svc" || !authcfg.TwoFARequired(ctx, a.st) {
		t.Fatalf("A: %+v 2fa=%v", got, authcfg.TwoFARequired(ctx, a.st))
	}
	if ch := a.take(); len(ch) == 0 || ch[len(ch)-1] != (change{ItemDirectory, authcfg.DirectoryID, false}) {
		t.Fatalf("A announces the merged state: %+v", ch)
	}
	data, _, _ = a.c.ClusterGet(ctx, ItemDirectory, authcfg.DirectoryID)
	if err := apply(t, a, b, ItemDirectory, authcfg.DirectoryID, data); err != nil {
		t.Fatal(err)
	}
	got := authcfg.LoadLDAP(ctx, b.st)
	if plain, _ := b.box.Decrypt(got.BindPasswordEnc); !got.Enabled || plain != "bind-geheim" || !authcfg.TwoFARequired(ctx, b.st) {
		t.Fatalf("B: %+v", got)
	}

	// A schaltet die Pflicht ab, B speichert danach LDAP mit seinem aelteren Stand der Pflicht
	_ = authcfg.SetTwoFARequired(ctx, a.st, false)
	got.BaseDN = "DC=neu"
	_ = authcfg.SaveLDAP(ctx, b.st, got)
	data, _, _ = b.c.ClusterGet(ctx, ItemDirectory, authcfg.DirectoryID)
	if err := apply(t, b, a, ItemDirectory, authcfg.DirectoryID, data); !superseded(err) {
		t.Fatalf("A keeps its newer 2fa switch: %v", err)
	}
	if authcfg.LoadLDAP(ctx, a.st).BaseDN != "DC=neu" || authcfg.TwoFARequired(ctx, a.st) {
		t.Fatal("A: LDAP from B, own 2fa switch")
	}

	// Node ohne die Felder (bis 1.7.10): als Ganzes
	old := withoutKeys(t, data, "ldap_unset", "twofa_unset", "ldap_at", "twofa_at")
	if err := apply(t, b, a, ItemDirectory, authcfg.DirectoryID, old); err != nil || !authcfg.TwoFARequired(ctx, a.st) {
		t.Fatalf("older node as a whole: %v", err)
	}
}
