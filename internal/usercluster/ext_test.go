package usercluster

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/authcfg"
	"github.com/ipv64net/node64/internal/store"
)

// superseded wie peer: uebernommen bzw. bewusst nicht, eigener Stand neu gemeldet.
func superseded(err error) bool {
	s, ok := err.(interface{ Superseded() bool })
	return ok && s.Superseded()
}

func (n *node) setChecked(t *testing.T, id int64, at time.Time) {
	t.Helper()
	if _, err := n.st.Writer().Exec(`UPDATE users SET ext_checked_at = ? WHERE id = ?`, store.FormatTime(at), id); err != nil {
		t.Fatal(err)
	}
}

// Gruppen aus LDAP/SSO samt Pruefzeitpunkt: der neuere Zeitpunkt gewinnt mit seinen Gruppen; behaelt eine Node ihren
// neueren Stand, meldet sie den zusammengefuehrten Stand neu, die Gegenstelle nimmt ihn ohne erneute Meldung (keine
// Schleife). Eine Gegenstelle ohne das Feld ueberschreibt einen neueren Stand nicht.
func TestExtCheckedSync(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	_, _ = a.st.CreateUser(ctx, "admin", "$h0", "", "UTC")
	_ = a.st.SaveGroup(ctx, &store.Group{UID: gidLow, Name: "Admins", Role: store.RoleAdmin})
	uid := store.ExternalUID(store.SourceLDAP, "0a1b2c3d")
	la, _ := a.st.CreateUserWith(ctx, store.NewUser{UID: uid, Username: "max@firma.local", Role: store.RoleRead, Source: store.SourceLDAP})
	_ = a.st.SetUserExtGroups(ctx, la.ID, []string{gidLow})
	checkedA := a.user(t, "max@firma.local").ExtCheckedAt
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	lb := b.user(t, "max@firma.local")
	if lb == nil || !lb.ExtCheckedAt.Equal(checkedA) || !slices.Equal(lb.ExtGroupUIDs, []string{gidLow}) || b.st.EffectiveRole(ctx, lb) != store.RoleAdmin {
		t.Fatalf("ext groups with check time on B: %+v", lb)
	}

	// B prueft neu (keine Gruppe mehr), A aendert danach etwas anderes mit seinem aelteren Stand
	a.setChecked(t, la.ID, time.Now().Add(-2*time.Hour))
	b.setChecked(t, lb.ID, time.Now().Add(-2*time.Hour))
	_ = b.st.SetUserExtGroups(ctx, lb.ID, nil)
	b.take()
	_ = a.st.UpdateUserPrefs(ctx, la.ID, "en", "UTC")
	data, _, _ := a.c.ClusterGet(ctx, ItemAccounts, uid)
	if err := apply(t, a, b, ItemAccounts, uid, data); !superseded(err) {
		t.Fatalf("newer own check kept and announced: %v", err)
	}
	x := b.user(t, "max@firma.local")
	if x.Lang != "en" || len(x.ExtGroupUIDs) != 0 || time.Since(x.ExtCheckedAt) > time.Minute {
		t.Fatalf("merged on B: %+v", x)
	}
	if c := b.take(); len(c) != 1 || c[0] != (change{ItemAccounts, uid, false}) {
		t.Fatalf("B announces the merged state: %+v", c)
	}
	// A nimmt den neueren Stand ohne erneute Meldung als eigene Aenderung
	a.take()
	data, _, _ = b.c.ClusterGet(ctx, ItemAccounts, uid)
	if err := apply(t, b, a, ItemAccounts, uid, data); err != nil {
		t.Fatalf("A takes the newer check: %v", err)
	}
	y := a.user(t, "max@firma.local")
	if len(y.ExtGroupUIDs) != 0 || !y.ExtCheckedAt.Equal(x.ExtCheckedAt) || y.Lang != "en" {
		t.Fatalf("A after merge: %+v", y)
	}
	// noch einmal derselbe Stand: nichts behalten, keine neue Meldung
	if err := apply(t, b, a, ItemAccounts, uid, data); err != nil {
		t.Fatalf("replay: %v", err)
	}

	// Gegenstelle ohne das Feld (Node64 1.7.0) mit anderen Gruppen: B behaelt seinen neueren Stand
	_ = a.st.SetUserExtGroups(ctx, y.ID, []string{gidLow})
	data, _, _ = a.c.ClusterGet(ctx, ItemAccounts, uid)
	m := map[string]any{}
	_ = json.Unmarshal(data, &m)
	delete(m, "ext_checked_at")
	old, _ := json.Marshal(m)
	b.setChecked(t, lb.ID, time.Now())
	if err := apply(t, a, b, ItemAccounts, uid, old); !superseded(err) {
		t.Fatalf("peer without the field: %v", err)
	}
	if z := b.user(t, "max@firma.local"); len(z.ExtGroupUIDs) != 0 {
		t.Fatalf("older peer overwrote newer groups: %+v", z)
	}
	// neu angelegt von einer Gegenstelle ohne das Feld: Gruppen ohne Pruefzeitpunkt (zaehlen bei LDAP nicht)
	c := newTestNode(t, "node-c")
	_, _ = c.st.CreateUser(ctx, "admin", "$h0", "", "UTC")
	_ = c.st.SaveGroup(ctx, &store.Group{UID: gidLow, Name: "Admins", Role: store.RoleAdmin})
	if err := apply(t, a, c, ItemAccounts, uid, old); err != nil {
		t.Fatal(err)
	}
	if z := c.user(t, "max@firma.local"); !slices.Equal(z.ExtGroupUIDs, []string{gidLow}) || !z.ExtCheckedAt.IsZero() || c.st.EffectiveRole(ctx, z) != store.RoleRead {
		t.Fatalf("created from a peer without the field: %+v", z)
	}
}

// directory: AD/LDAP und 2FA-Pflicht ueber authcfg, eine Meldung je Uebernahme.
func TestDirectoryApplyReportsOnce(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	_ = authcfg.SaveLDAP(ctx, a.st, authcfg.LDAPConfig{Enabled: true, URLs: []string{"ldaps://dc:636"}, Profile: authcfg.ProfileLDAP, BaseDN: "dc=x"})
	_ = authcfg.SetTwoFARequired(ctx, a.st, true)
	data, _, _ := a.c.ClusterGet(ctx, ItemDirectory, authcfg.DirectoryID)
	if err := apply(t, a, b, ItemDirectory, authcfg.DirectoryID, data); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	n := len(b.log)
	b.mu.Unlock()
	if got := authcfg.LoadLDAP(ctx, b.st); n != 1 || !got.Enabled || got.Profile != authcfg.ProfileLDAP || !authcfg.TwoFARequired(ctx, b.st) {
		t.Fatalf("directory on B: %d reports, %+v", n, got)
	}
}
