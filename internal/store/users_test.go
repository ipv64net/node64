package store

import (
	"context"
	"testing"
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
	if n, _ := s.ActiveLocalAdmins(ctx, admin.ID); n != 0 {
		t.Fatalf("local admins without admin: %d", n)
	}
	if err := s.UpdateUserAdmin(ctx, admin.ID, UserAdmin{Role: RoleRead, Disabled: true, GroupUIDs: []string{g.UID, g.UID}}); err != nil {
		t.Fatal(err)
	}
	admin, _ = s.UserByID(ctx, admin.ID)
	if !admin.Disabled || len(admin.GroupUIDs) != 1 || s.EffectiveRole(ctx, admin) != RoleAdmin {
		t.Fatalf("admin update: %+v", admin)
	}
	if n, _ := s.ActiveLocalAdmins(ctx, 0); n != 0 {
		t.Fatalf("disabled admin counted: %d", n)
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
