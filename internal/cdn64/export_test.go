package cdn64

import (
	"context"
	"encoding/json"
	"testing"
)

// Export/Import zwischen zwei Nodes: Zugriffslisten (mit Hashes) kommen mit und Hosts/Locations zeigen auf die
// Listen der Ziel-Node; Blocklisten-/Limit-Einstellungen werden gesetzt, wo leer; ein festes Zertifikat wird nach
// Namen wiedergefunden.
func TestExportImportACLsSettingsCerts(t *testing.T) {
	ctx := context.Background()
	a := newEnv(t)
	a.enable(t)
	certPEM, keyPEM := selfSigned(t, "shop.test")
	ca, err := a.crt.Upload(ctx, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	acl := &AccessList{Name: "Buero", Rules: []AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}}
	if err := a.m.saveAccessList(ctx, acl, []UserInput{{Username: "anna", Password: "geheim123"}}); err != nil {
		t.Fatal(err)
	}
	acl2 := &AccessList{Name: "Nur Admin", Rules: []AccessRule{{Action: "allow", CIDR: "192.0.2.1"}}}
	if err := a.m.saveAccessList(ctx, acl2, nil); err != nil {
		t.Fatal(err)
	}
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID, h.AccessListID = []string{"shop.test"}, "192.168.1.10", 8080, ca.ID, acl.ID
	h.Locations = []Location{{Path: "/admin", Scheme: "http", TargetHost: "192.168.1.11", TargetPort: 80, AccessListID: acl2.ID}}
	if err := a.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if err := a.m.core.SetSetting(ctx, setBlocklists, "spamhaus_drop"); err != nil {
		t.Fatal(err)
	}
	if err := a.m.core.SetSetting(ctx, setLogDays, "30"); err != nil {
		t.Fatal(err)
	}
	exp, err := a.m.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(exp)

	b := newEnv(t)
	b.enable(t)
	other := &AccessList{Name: "Andere", Rules: []AccessRule{{Action: "deny", CIDR: "all"}}} // verschiebt die IDs
	if err := b.m.saveAccessList(ctx, other, nil); err != nil {
		t.Fatal(err)
	}
	if err := b.m.core.SetSetting(ctx, setLogDays, "3"); err != nil { // vorhandene Einstellung bleibt
		t.Fatal(err)
	}
	cb, err := b.crt.Upload(ctx, certPEM, keyPEM) // Zertifikat kam mit dem Backup des Kerns
	if err != nil {
		t.Fatal(err)
	}
	n, err := b.m.Import(ctx, raw)
	if err != nil || n != 3 { // 2 Listen + 1 Host
		t.Fatalf("import: n=%d err=%v", n, err)
	}
	list, _ := b.m.hosts(ctx)
	var got *Host
	for _, x := range list {
		if x.Names[0] == "shop.test" {
			got = x
		}
	}
	if got == nil {
		t.Fatal("host not imported")
	}
	acls, _ := b.m.accessLists(ctx)
	names := map[int64]*AccessList{}
	for _, x := range acls {
		names[x.ID] = x
	}
	if names[got.AccessListID] == nil || names[got.AccessListID].Name != "Buero" || len(names[got.AccessListID].Users) != 1 ||
		names[got.AccessListID].Users[0].Hash == "" {
		t.Fatalf("host acl: %d %+v", got.AccessListID, names[got.AccessListID])
	}
	if l := got.Locations[0]; names[l.AccessListID] == nil || names[l.AccessListID].Name != "Nur Admin" {
		t.Fatalf("location acl: %+v", l)
	}
	if got.CertID != cb.ID {
		t.Fatalf("fixed cert: %d, want %d", got.CertID, cb.ID)
	}
	if v := b.m.core.SettingOr(ctx, setBlocklists, ""); v != "spamhaus_drop" {
		t.Fatalf("blocklists: %q", v)
	}
	if v := b.m.core.SettingOr(ctx, setLogDays, ""); v != "3" {
		t.Fatalf("log days overwritten: %q", v)
	}
	// noch einmal: nichts doppelt
	if n, err := b.m.Import(ctx, raw); err != nil || n != 0 {
		t.Fatalf("second import: n=%d err=%v", n, err)
	}
}

// Import: Docker-Kennung der Quelle faellt weg, hier wird es ein normaler Host (sonst loeschte der Abgleich ihn).
func TestImportDropsDockerOrigin(t *testing.T) {
	ctx := context.Background()
	src := newEnv(t)
	src.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID, h.DockerContainer = []string{"imp.test"}, "127.0.0.1", 80, CertNone, "web"
	if err := src.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	exp, err := src.m.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(exp)
	dst := newEnv(t)
	dst.enable(t)
	if _, err := dst.m.Import(ctx, raw); err != nil {
		t.Fatal(err)
	}
	list, _ := dst.m.hosts(ctx)
	if len(list) != 1 || list[0].DockerContainer != "" || list[0].DockerRouter != "" {
		t.Fatalf("imported: %+v", list)
	}
}
