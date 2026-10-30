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

// „Als Check“: der Name des Docker-Hosts steht in den Parametern und folgt einer Umbenennung beim naechsten Abruf.
func TestCheckSystemLabel(t *testing.T) {
	fakeContainers(t, dockerHost, nil)
	fakeDockerSource(t)
	m, srv, last, _ := newDockerModuleRec(t, pveCore(t))
	ctx := context.Background()
	dockerAddLocal(t, srv)
	id := dockerSysID(t, m)
	pvePollNow(t, m, id)
	sid := strconv.FormatInt(id, 10)
	_, loc := dockerPost(t, srv, "/healthchecks/new", url.Values{"type": {"sys:docker"}, "sys_id_docker": {sid}, "sys_key_docker": {"docker/web"}})
	tok := strings.TrimPrefix(loc, "/healthchecks/")
	if c, _ := m.st.Check(ctx, tok); c == nil || !strings.Contains(string(c.Params), `"system":"Docker"`) {
		t.Fatalf("params: %+v", c)
	}
	sys, _ := m.pve.st.System(ctx, id)
	sys.Name, sys.Secret = "Heimserver", ""
	if err := m.pve.st.SaveSystem(ctx, sys); err != nil {
		t.Fatal(err)
	}
	pvePollNow(t, m, id)
	if c, _ := m.st.Check(ctx, tok); c == nil || !strings.Contains(string(c.Params), `"system":"Heimserver"`) || c.Target != "web" {
		t.Fatalf("after rename: %s", c.Params)
	}
	if err := checks.Validate((&Check{Type: checks.TypeDocker, Target: "web", Params: []byte(`{"system":"Heimserver"}`)}).Definition()); err != nil {
		t.Fatalf("validate: %v", err)
	}
	// Untergruppe von Hand: bleibt beim naechsten Abruf, leer = wieder automatisch
	edit := func(label string) *Check {
		c, _ := m.st.Check(ctx, tok)
		form := url.Values{}
		for k, v := range formFromCheck(c) {
			form.Set(k, v)
		}
		form.Del("locations") // lokaler Check; im Formular einzelne Felder, nicht die Liste
		form.Set("sys_label", label)
		if code, loc := dockerPost(t, srv, "/healthchecks/"+tok+"/edit", form); code != http.StatusSeeOther {
			t.Fatalf("edit %q: %d %s %+v", label, code, loc, *last)
		}
		pvePollNow(t, m, id)
		c, _ = m.st.Check(ctx, tok)
		return c
	}
	if c := edit("Standort B"); c == nil || !strings.Contains(string(c.Params), `"system":"Standort B","system_custom":true`) {
		t.Fatalf("custom: %s", c.Params)
	}
	if err := checks.Validate((&Check{Type: checks.TypeDocker, Target: "web", Params: []byte(`{"system":"Standort B","system_custom":true}`)}).Definition()); err != nil {
		t.Fatalf("validate custom: %v", err)
	}
	if c := edit(""); c == nil || !strings.Contains(string(c.Params), `"system":"Heimserver"`) || strings.Contains(string(c.Params), "system_custom") {
		t.Fatalf("auto again: %s", c.Params)
	}
}

// Proxmox-Check: Untergruppe von Hand im Formular, die Liste gruppiert danach; leer = wieder automatisch.
func TestProxmoxSubgroupCustom(t *testing.T) {
	raw := `{"system_id":3,"key":"qemu/100","system":"Cluster 1","system_uid":"` + strings.Repeat("a", 32) + `"}`
	in, err := checkFromForm(formRequest(url.Values{"name": {"vm"}, "type": {"proxmox"}, "pve_params": {raw}, "sys_label": {" Cluster 1 Berlin "}}))
	if err != nil || !strings.Contains(string(in.Params), `"system":"Cluster 1 Berlin","system_uid"`) || !strings.Contains(string(in.Params), `"system_custom":true`) || in.Target != "qemu/100" {
		t.Fatalf("custom: %s %v", in.Params, err)
	}
	c := &Check{Type: checks.TypeProxmox, Target: in.Target, Params: in.Params, Group: pveCheckGroup}
	if err := checks.Validate(c.Definition()); err != nil {
		t.Fatalf("validate: %v", err)
	}
	f := formFromCheck(c)
	if f["sys_label"] != "Cluster 1 Berlin" {
		t.Fatalf("form back: %q", f["sys_label"])
	}
	fakeContainers(t, dockerHost, nil)
	fakeDockerSource(t)
	m, _, _, _ := newDockerModuleRec(t, pveCore(t))
	if n := m.subGroupOf(context.Background(), nil)(row{Check: c}); n != "Cluster 1 Berlin" {
		t.Fatalf("sub: %q", n)
	}
	in, err = checkFromForm(formRequest(url.Values{"name": {"vm"}, "type": {"proxmox"}, "pve_params": {f["pve_params"]}, "sys_label": {""}}))
	if err != nil || strings.Contains(string(in.Params), "system_custom") || strings.Contains(string(in.Params), "Berlin") {
		t.Fatalf("auto again: %s %v", in.Params, err)
	}
}

// Docker-Host aus: Container „als Check“ werden pausiert wie bei Proxmox VE, wieder an: laufen weiter.
func TestDockerPauseChecks(t *testing.T) {
	fakeContainers(t, dockerHost, nil)
	fakeDockerSource(t)
	m, srv, _, _ := newDockerModuleRec(t, pveCore(t))
	ctx := context.Background()
	dockerAddLocal(t, srv)
	id := dockerSysID(t, m)
	pvePollNow(t, m, id)
	sid := strconv.FormatInt(id, 10)
	_, loc := dockerPost(t, srv, "/healthchecks/new", url.Values{"type": {"sys:docker"}, "sys_id_docker": {sid}, "sys_key_docker": {"docker/web"}})
	tok := strings.TrimPrefix(loc, "/healthchecks/")
	toggle := "/healthchecks/proxmox/system/" + sid + "/toggle"
	dockerPost(t, srv, toggle, url.Values{})
	if c, _ := m.st.Check(ctx, tok); c == nil || !c.Paused {
		t.Fatalf("host off: check not paused: %+v", c)
	}
	dockerPost(t, srv, toggle, url.Values{})
	if c, _ := m.st.Check(ctx, tok); c == nil || c.Paused {
		t.Fatalf("host on: check still paused: %+v", c)
	}
}

// „Alle als Check aufnehmen“: jeder Container des letzten Abrufs ohne nomonitor bekommt einen Check, schon gefuehrte
// bleiben, ein zweiter Klick legt nichts doppelt an.
func TestAsCheckAll(t *testing.T) {
	fakeContainers(t, dockerHost, nil)
	fakeDockerSource(t)
	m, srv, last, _ := newDockerModuleRec(t, pveCore(t))
	ctx := context.Background()
	dockerAddLocal(t, srv)
	id := dockerSysID(t, m)
	pvePollNow(t, m, id)
	act := "/healthchecks/proxmox/system/" + strconv.FormatInt(id, 10)
	dockerPost(t, srv, act+"/ascheck", url.Values{"key": {"docker/web"}, "on": {"1"}})
	s := m.pveLast(id)
	want := 0
	for i := range s.Resources {
		if !s.Resources[i].Excluded() && s.Resources[i].Type != "node" {
			want++
		}
	}
	if want < 2 {
		t.Fatalf("test needs at least 2 containers: %d", want)
	}
	body := dockerGetPage(t, srv, dockerSysPath(id))
	if d := (*last).(dockerData); d.Add != want-1 || !strings.Contains(body, act+"/ascheck-all") {
		t.Fatalf("page: add %d (want %d)", d.Add, want-1)
	}
	set, _ := m.pve.st.Settings(ctx, id)
	webTok := set.Item("docker/web").CheckToken
	count := func() int {
		set, _ := m.pve.st.Settings(ctx, id)
		n := 0
		for i := range s.Resources {
			if it := set.Item(s.Resources[i].Key()); it != nil && it.AsCheck && it.CheckToken != "" {
				n++
			}
		}
		return n
	}
	if _, loc := dockerPost(t, srv, act+"/ascheck-all", url.Values{"scope": {"guests"}, "back": {dockerSysPath(id)}}); loc != dockerSysPath(id) || count() != want {
		t.Fatalf("all: %q %d/%d", loc, count(), want)
	}
	set, _ = m.pve.st.Settings(ctx, id)
	if set.Item("docker/web").CheckToken != webTok {
		t.Fatal("existing check replaced")
	}
	list, _ := m.st.Checks(ctx)
	dockerPost(t, srv, act+"/ascheck-all", url.Values{"scope": {"guests"}})
	if again, _ := m.st.Checks(ctx); len(again) != len(list) {
		t.Fatalf("second click: %d -> %d checks", len(list), len(again))
	}
	dockerGetPage(t, srv, dockerSysPath(id))
	if d := (*last).(dockerData); d.Add != 0 {
		t.Fatalf("after: add %d", d.Add)
	}
}
