package store

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Rollen und Gruppen: eigene Rolle, Gruppen von Hand und von aussen, letzter lokaler Administrator.
func TestUserRolesAndGroups(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	var changed []string
	s.SetLoginCluster(func(_ context.Context, item, id string, deleted bool) { changed = append(changed, item) })

	admin, err := s.CreateUser(ctx, "admin", "h", "de", "UTC")
	if err != nil || admin.Role != RoleAdmin || admin.Source != SourceLocal || admin.Disabled {
		t.Fatalf("legacy create: %+v %v", admin, err)
	}
	g := &Group{Name: "Technik", Role: RoleAdmin, LDAPGroups: []string{"CN=IT,OU=Groups,DC=firma,DC=lan", ""}}
	if err := s.SaveGroup(ctx, g); err != nil || g.UID == "" {
		t.Fatalf("group: %v", err)
	}
	if err := s.SaveGroup(ctx, &Group{Name: "technik"}); err != ErrGroupName {
		t.Fatalf("duplicate name: %v", err)
	}
	got, _ := s.GroupByUID(ctx, g.UID)
	if got == nil || len(got.LDAPGroups) != 1 || got.LDAPGroups[0] != "CN=IT,OU=Groups,DC=firma,DC=lan" {
		t.Fatalf("group read: %+v", got)
	}
	reader, err := s.CreateUserWith(ctx, NewUser{Username: "lisa", Role: RoleRead, Source: SourceLDAP, UID: "ldap-guid-1"})
	if err != nil || reader.UID != "ldap-guid-1" || s.EffectiveRole(ctx, reader) != RoleRead {
		t.Fatalf("reader: %+v %v", reader, err)
	}
	if err := s.SetUserExtGroups(ctx, reader.ID, []string{g.UID}); err != nil {
		t.Fatal(err)
	}
	reader, _ = s.UserByUID(ctx, "ldap-guid-1")
	if s.EffectiveRole(ctx, reader) != RoleAdmin {
		t.Fatal("group role not effective")
	}
	// LDAP-Admin zaehlt nicht als lokaler Admin; der einzige lokale bleibt Pflicht
	if err := s.GuardLastAdmin(ctx, AdminChange{User: func(u *User) *User {
		if u.ID == admin.ID {
			return nil
		}
		return u
	}}, func() error { t.Fatal("last local admin deleted"); return nil }); err != ErrLastAdmin {
		t.Fatalf("guard: %v", err)
	}
	if err := s.UpdateUserAdmin(ctx, admin.ID, UserAdmin{Role: RoleRead, Disabled: true, GroupUIDs: []string{g.UID, g.UID}}); err != nil {
		t.Fatal(err)
	}
	admin, _ = s.UserByID(ctx, admin.ID)
	if !admin.Disabled || len(admin.GroupUIDs) != 1 || s.EffectiveRole(ctx, admin) != RoleAdmin {
		t.Fatalf("admin update: %+v", admin)
	}
	if roles, _ := s.GroupRoles(ctx); ActiveLocalAdmin(admin, roles) {
		t.Fatal("disabled admin counted")
	}
	if ok, _ := s.DeleteGroup(ctx, g.UID); !ok {
		t.Fatal("delete group")
	}
	if s.EffectiveRole(ctx, admin) != RoleRead {
		t.Fatal("deleted group still effective")
	}
	if len(changed) == 0 || changed[0] != "accounts" {
		t.Fatalf("cluster hooks: %v", changed)
	}
}

func setChecked(t *testing.T, s *Store, id int64, at time.Time) {
	t.Helper()
	if _, err := s.Writer().Exec(`UPDATE users SET ext_checked_at = ? WHERE id = ?`, FormatTime(at), id); err != nil {
		t.Fatal(err)
	}
}

// Gruppen aus LDAP/SSO zaehlen nur, solange ihre letzte Pruefung frisch ist (LDAP 24 h, SSO 7 Tage); Gruppen von
// Hand und die eigene Rolle immer. SetUserExtGroups setzt den Zeitpunkt bei jedem Aufruf und meldet an den Cluster nur
// bei geaenderten Gruppen oder wenn die letzte Meldung (Pruefung) aelter als eine Stunde ist.
func TestExtGroupsFresh(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	var changed []string
	s.SetLoginCluster(func(_ context.Context, item, id string, deleted bool) { changed = append(changed, item+"/"+id) })
	g := &Group{Name: "Admins", Role: RoleAdmin}
	_ = s.SaveGroup(ctx, g)
	ldap, _ := s.CreateUserWith(ctx, NewUser{Username: "lisa", Role: RoleRead, Source: SourceLDAP, UID: "ldap-1"})
	oidc, _ := s.CreateUserWith(ctx, NewUser{Username: "otto", Role: RoleRead, Source: SourceOIDC, UID: "oidc-1"})
	local, _ := s.CreateUserWith(ctx, NewUser{Username: "lars", PasswordHash: "h", Role: RoleRead, ExtGroupUIDs: []string{g.UID}})
	role := func(id int64) string {
		u, _ := s.UserByID(ctx, id)
		return s.EffectiveRole(ctx, u)
	}
	// beim ersten Anmelden angelegt: mitgegebene Gruppen gelten als eben geprueft
	if jit, _ := s.CreateUserWith(ctx, NewUser{Username: "jana", Role: RoleRead, Source: SourceLDAP, UID: "ldap-2", ExtGroupUIDs: []string{g.UID}}); role(jit.ID) != RoleAdmin {
		t.Fatalf("created with directory groups: %+v", jit)
	}
	changed = nil
	if err := s.SetUserExtGroups(ctx, ldap.ID, []string{g.UID}); err != nil {
		t.Fatal(err)
	}
	_ = s.SetUserExtGroups(ctx, oidc.ID, []string{g.UID})
	if u, _ := s.UserByID(ctx, ldap.ID); time.Since(u.ExtCheckedAt) > time.Minute || role(ldap.ID) != RoleAdmin || role(oidc.ID) != RoleAdmin {
		t.Fatalf("fresh check: %+v", u)
	}
	if len(changed) != 2 {
		t.Fatalf("changed groups reported: %v", changed)
	}
	// Drossel: gleiche Gruppen, frische Meldung - nichts an den Cluster, Zeitpunkt trotzdem neu
	setChecked(t, s, ldap.ID, time.Now().Add(-30*time.Minute))
	changed = nil
	_ = s.SetUserExtGroups(ctx, ldap.ID, []string{g.UID})
	if u, _ := s.UserByID(ctx, ldap.ID); len(changed) != 0 || time.Since(u.ExtCheckedAt) > time.Minute {
		t.Fatalf("throttled: %v %+v", changed, u)
	}
	setChecked(t, s, ldap.ID, time.Now().Add(-61*time.Minute))
	_ = s.SetUserExtGroups(ctx, ldap.ID, []string{g.UID})
	if len(changed) != 1 {
		t.Fatalf("hourly report: %v", changed)
	}
	// leere Liste ist auch eine Pruefung
	changed = nil
	_ = s.SetUserExtGroups(ctx, oidc.ID, nil)
	if u, _ := s.UserByID(ctx, oidc.ID); len(u.ExtGroupUIDs) != 0 || time.Since(u.ExtCheckedAt) > time.Minute || len(changed) != 1 {
		t.Fatalf("empty check: %v %+v", changed, u)
	}
	_ = s.SetUserExtGroups(ctx, oidc.ID, []string{g.UID})

	// veraltet: LDAP nach 24 h, SSO nach 7 Tagen
	setChecked(t, s, ldap.ID, time.Now().Add(-25*time.Hour))
	setChecked(t, s, oidc.ID, time.Now().Add(-25*time.Hour))
	if role(ldap.ID) != RoleRead || role(oidc.ID) != RoleAdmin {
		t.Fatalf("after 25 h: ldap %s oidc %s", role(ldap.ID), role(oidc.ID))
	}
	setChecked(t, s, oidc.ID, time.Now().Add(-8*24*time.Hour))
	if role(oidc.ID) != RoleRead {
		t.Fatal("oidc groups after 8 days")
	}
	// Gruppe von Hand und eigene Rolle zaehlen immer; lokale Benutzer behalten frisch gepruefte Gruppen
	u, _ := s.UserByID(ctx, ldap.ID)
	_ = s.UpdateUserAdmin(ctx, ldap.ID, UserAdmin{Role: RoleRead, GroupUIDs: []string{g.UID}})
	if role(ldap.ID) != RoleAdmin {
		t.Fatal("manual group counts")
	}
	_ = s.UpdateUserAdmin(ctx, ldap.ID, UserAdmin{Role: RoleAdmin})
	if role(ldap.ID) != RoleAdmin || u.Role != RoleRead {
		t.Fatal("own role counts")
	}
	if role(local.ID) != RoleAdmin {
		t.Fatal("local user keeps its groups")
	}
	// Gruppen aus einem verknuepften SSO-Konto verfallen auch beim lokalen Benutzer nach 7 Tagen
	setChecked(t, s, local.ID, time.Now().Add(-8*24*time.Hour))
	if role(local.ID) != RoleRead {
		t.Fatal("sso groups of a local user after 8 days")
	}
}

// GuardLastAdmin: von gleichzeitigen Aenderungen, die je einen von zwei lokalen Administratoren nehmen, kommt nur eine
// durch.
func TestGuardLastAdminConcurrent(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		users, _ := s.Users(ctx)
		for _, u := range users {
			_, _ = s.DeleteUser(ctx, u.ID)
		}
		x, _ := s.CreateUserWith(ctx, NewUser{Username: "x", PasswordHash: "h"})
		y, _ := s.CreateUserWith(ctx, NewUser{Username: "y", PasswordHash: "h"})
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok := 0
		start := make(chan struct{})
		for _, id := range []int64{x.ID, y.ID} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				err := s.GuardLastAdmin(ctx, AdminChange{User: func(u *User) *User {
					if u.ID == id {
						u.Disabled = true
					}
					return u
				}}, func() error { return s.UpdateUserAdmin(ctx, id, UserAdmin{Role: RoleAdmin, Disabled: true}) })
				if err == nil {
					mu.Lock()
					ok++
					mu.Unlock()
				}
			}()
		}
		close(start)
		wg.Wait()
		if ok != 1 {
			t.Fatalf("round %d: %d changes passed", i, ok)
		}
	}
}
