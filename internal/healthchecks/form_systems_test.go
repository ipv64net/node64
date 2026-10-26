package healthchecks

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/checks"
)

// Neuer Check: Typ „Docker-Container“ waehlt Host und Container aus der Ueberwachung; der rohe Typ docker fehlt.
func TestFormSystemCheck(t *testing.T) {
	fakeContainers(t, dockerHost, nil)
	fakeDockerSource(t)
	m, srv, last, _ := newDockerModuleRec(t, pveCore(t))
	ctx := context.Background()

	body := dockerGetPage(t, srv, "/healthchecks/new")
	d := (*last).(formData)
	for _, ty := range d.Types {
		if ty == checks.TypeDocker {
			t.Fatal("raw docker type offered for new checks")
		}
	}
	if !strings.Contains(body, `value="sys:docker"`) || !strings.Contains(body, `value="sys:proxmox"`) || !strings.Contains(body, "hc.pick.no_systems_docker") {
		t.Fatal("system types or empty hint missing")
	}

	dockerAddLocal(t, srv)
	id := dockerSysID(t, m)
	pvePollNow(t, m, id)
	sid := strconv.FormatInt(id, 10)
	body = dockerGetPage(t, srv, "/healthchecks/new?type=docker&sys="+sid) // alter Link: Auswahl ueber den Host
	d = (*last).(formData)
	if d.Form["type"] != "sys:docker" || len(d.PickDocker) != 1 || len(d.PickDocker[0].Res) != 3 || !strings.Contains(body, `data-sys="`+sid+`"`) || !strings.Contains(body, "docker/web") {
		t.Fatalf("picks: %+v", d.PickDocker)
	}
	if strings.Contains(body, "docker/tmp") { // node64.nomonitor
		t.Fatal("excluded container offered")
	}

	// ohne Auswahl: Fehler im Formular
	if code, _ := dockerPost(t, srv, "/healthchecks/new", url.Values{"type": {"sys:docker"}, "sys_id_docker": {sid}}); code != http.StatusUnprocessableEntity {
		t.Fatalf("without container: %d", code)
	}
	// anlegen mit eigenem Namen: Docker-Check des Containers, als Check gefuehrt
	code, loc := dockerPost(t, srv, "/healthchecks/new", url.Values{"type": {"sys:docker"}, "sys_id_docker": {sid}, "sys_key_docker": {"docker/web"}, "name": {"Webserver"}})
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/healthchecks/") {
		t.Fatalf("create: %d %q", code, loc)
	}
	tok := strings.TrimPrefix(loc, "/healthchecks/")
	c, err := m.st.Check(ctx, tok)
	if err != nil || c.Type != checks.TypeDocker || c.Target != "web" || c.Name != "Webserver" {
		t.Fatalf("check: %+v %v", c, err)
	}
	set, _ := m.pve.st.Settings(ctx, id)
	if it := set.Item("docker/web"); it == nil || !it.AsCheck || it.CheckToken != tok {
		t.Fatalf("not linked: %+v", it)
	}
	// danach im Formular als gefuehrt markiert; ohne Namen: "System – Container"
	dockerGetPage(t, srv, "/healthchecks/new")
	for _, r := range (*last).(formData).PickDocker[0].Res {
		if r.Key == "docker/web" && !r.Taken {
			t.Fatal("web not marked as taken")
		}
	}
	_, loc = dockerPost(t, srv, "/healthchecks/new", url.Values{"type": {"sys:docker"}, "sys_id_docker": {sid}, "sys_key_docker": {"docker/cache"}})
	if c, _ = m.st.Check(ctx, strings.TrimPrefix(loc, "/healthchecks/")); c == nil || c.Name != "Docker – cache" {
		t.Fatalf("auto name: %+v", c)
	}
	// falsche Art (Docker-Host als Proxmox-System)
	if code, _ := dockerPost(t, srv, "/healthchecks/new", url.Values{"type": {"sys:proxmox"}, "sys_id_proxmox": {sid}, "sys_key_proxmox": {"qemu/100"}}); code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong kind: %d", code)
	}
	// Bearbeiten eines Docker-Checks behaelt den Typ
	dockerGetPage(t, srv, "/healthchecks/"+tok+"/edit")
	found := false
	for _, ty := range (*last).(formData).Types {
		found = found || ty == checks.TypeDocker
	}
	if !found {
		t.Fatal("edit: docker type missing")
	}
}

// Liste: in den Gruppen „Proxmox VE“ und „Docker“ je System bzw. Host eine Untergruppe, andere Gruppen unveraendert.
func TestGroupRowsParts(t *testing.T) {
	mk := func(name, group, sub, state string) row {
		return row{Check: &Check{Name: name, Group: group, Description: sub}, State: state}
	}
	rows := []row{mk("a", "Proxmox VE", "Cluster B", "up"), mk("b", "Proxmox VE", "Cluster A", "down"), mk("c", "Proxmox VE", "", "up"),
		mk("d", "Web", "", "up"), mk("e", "Proxmox VE", "Cluster B", "up")}
	gs := groupRows(rows, []string{"Proxmox VE", "Web"}, "none", func(r row) string { return r.Check.Description })
	if len(gs) != 2 || len(gs[0].Rows) != 4 || gs[0].Up != 3 || gs[0].Down != 1 {
		t.Fatalf("groups: %+v", gs)
	}
	p := gs[0].Parts
	if len(p) != 3 || p[0].Name != "" || len(p[0].Rows) != 1 || p[1].Name != "Cluster A" || p[1].Down != 1 || p[2].Name != "Cluster B" || len(p[2].Rows) != 2 {
		t.Fatalf("parts: %+v", p)
	}
	if len(gs[1].Parts) != 1 || gs[1].Parts[0].Name != "" || len(gs[1].Parts[0].Rows) != 1 {
		t.Fatalf("web parts: %+v", gs[1].Parts)
	}
}
