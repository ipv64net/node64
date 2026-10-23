package healthchecks

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/ipv64net/node64/internal/checks"
)

// Proxmox VE auf Statusseiten: Nodes und Gaeste aus dem letzten Abruf zur Auswahl, fehlende Checks werden beim
// Hinzufuegen angelegt (wie „auch als Check fuehren“); geloeschte Checks verschwinden von den Seiten.
func TestStatusPageResources(t *testing.T) {
	fake := newPVEFake()
	fsrv := startPVEFake(t, fake)
	m, srv, _ := newPVEModule(t, pveCore(t), pveBox(t, 1))
	id := pveCreate(t, srv, fsrv)
	pvePollNow(t, m, id)
	ctx := context.Background()
	names := func() map[string]string {
		out := map[string]string{}
		list, _ := m.st.Checks(ctx)
		for _, c := range list {
			out[c.Token] = c.Name
		}
		return out
	}
	linked := map[string]bool{}
	sys := m.statusResources(ctx, false, names(), map[string]bool{}, linked)
	if len(sys) != 1 || sys[0].Name != "lab" || len(sys[0].Items) == 0 || sys[0].Items[0].Type != "pve.type.node" || len(linked) != 0 {
		t.Fatalf("resources: %+v", sys)
	}
	var vm statusResOpt
	for _, o := range sys[0].Items {
		if o.Value == fmt.Sprint(id)+"|qemu/101" {
			vm = o
		}
	}
	if vm.Name != "db" || vm.Type != "pve.type.qemu" || vm.Token != "" {
		t.Fatalf("vm: %+v", vm)
	}
	if d := m.statusResources(ctx, true, names(), nil, linked); len(d) != 0 {
		t.Fatalf("docker: %+v", d)
	}

	// Hinzufuegen legt den Check einmal an (zweimal gewaehlt, ungueltige Werte ignoriert)
	r := httptest.NewRequest("POST", "/", nil)
	toks, err := m.statusResTokens(r, []string{vm.Value, "x|qemu/1", fmt.Sprint(id) + "|../etc", vm.Value})
	if err != nil || len(toks) != 2 || toks[0] != toks[1] {
		t.Fatalf("tokens: %v %v", toks, err)
	}
	c, _ := m.st.Check(ctx, toks[0])
	if c == nil || c.Type != checks.TypeProxmox || c.Target != "qemu/101" {
		t.Fatalf("check: %+v", c)
	}
	on := map[string]bool{c.Token: true}
	sys = m.statusResources(ctx, false, names(), on, linked)
	for _, o := range sys[0].Items {
		if o.Value == vm.Value && (o.Token != c.Token || !o.OnPage || !linked[c.Token]) {
			t.Fatalf("linked: %+v", o)
		}
	}

	// Check geloescht: von allen Statusseiten entfernt (Gruppe bleibt)
	p := &StatusPage{Slug: "lab", Title: "Lab", Groups: []StatusGroup{{Name: "VMs", Items: []StatusItem{{Token: c.Token}}}}}
	if err := m.st.SaveStatusPage(ctx, p, ""); err != nil {
		t.Fatal(err)
	}
	if err := m.st.Delete(ctx, c.Token); err != nil {
		t.Fatal(err)
	}
	p, _ = m.st.StatusPage(ctx, p.ID)
	if len(p.Groups) != 1 || len(p.Groups[0].Items) != 0 {
		t.Fatalf("after delete: %+v", p.Groups)
	}
}
