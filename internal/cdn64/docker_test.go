package cdn64

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/proxmox"
)

// fakeC ist ein Container der nachgebauten Docker-API.
type fakeC struct {
	id, name, state string
	created         int64
	labels          map[string]string
	exposed         []string          // "80/tcp"
	nets            map[string]string // Netz -> IP
	published       map[string]string // "3000/tcp" -> Port auf dem Host
	mode            string            // NetworkMode
}

// fakeDocker ist eine nachgebaute Docker-API (nur GET), eigener Container "node64-self" im Netz "proxy".
type fakeDocker struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	list   []*fakeC
	fail   bool
	events chan string
}

func newFakeDocker(t *testing.T) *fakeDocker {
	f := &fakeDocker{t: t, events: make(chan string, 16)}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeDocker) set(cs ...*fakeC) {
	f.mu.Lock()
	f.list = cs
	f.mu.Unlock()
}

func (f *fakeDocker) inspect(c *fakeC) map[string]any {
	nets := map[string]any{}
	for n, ip := range c.nets {
		if c.state != "running" {
			ip = ""
		}
		nets[n] = map[string]string{"IPAddress": ip, "Gateway": strings.TrimSuffix(ip, ip[strings.LastIndex(ip, ".")+1:]) + "1"}
	}
	exp := map[string]any{}
	for _, p := range c.exposed {
		exp[p] = struct{}{}
	}
	ports := map[string]any{}
	for p, hp := range c.published {
		ports[p] = []map[string]string{{"HostIp": "0.0.0.0", "HostPort": hp}}
	}
	mode := c.mode
	if mode == "" {
		mode = "bridge"
	}
	return map[string]any{"Id": c.id, "Name": "/" + c.name, "State": map[string]any{"Running": c.state == "running", "Status": c.state},
		"Config": map[string]any{"ExposedPorts": exp, "Labels": c.labels}, "HostConfig": map[string]any{"NetworkMode": mode},
		"NetworkSettings": map[string]any{"Networks": nets, "Ports": ports}}
}

func (f *fakeDocker) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		f.t.Errorf("docker api: %s %s (only GET allowed)", r.Method, r.URL.Path)
		http.Error(w, "no", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == "/events" {
		if !strings.Contains(r.URL.Query().Get("filters"), `"container"`) {
			f.t.Errorf("events without filter: %s", r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case a := <-f.events:
				_ = json.NewEncoder(w).Encode(map[string]any{"Type": "container", "Action": a, "Actor": map[string]any{"ID": "x"}})
				w.(http.Flusher).Flush()
			}
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/containers/json" {
		if f.fail {
			http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
			return
		}
		out := []map[string]any{}
		for _, c := range f.list {
			out = append(out, map[string]any{"Id": c.id, "Names": []string{"/" + c.name}, "State": c.state, "Created": c.created, "Labels": c.labels})
		}
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	id, ok := strings.CutPrefix(r.URL.Path, "/containers/")
	id, ok2 := strings.CutSuffix(id, "/json")
	if ok && ok2 {
		if id == "node64-self" {
			_ = json.NewEncoder(w).Encode(f.inspect(&fakeC{id: "self", name: "node64-self", state: "running", nets: map[string]string{"proxy": "172.20.0.2"}}))
			return
		}
		for _, c := range f.list {
			if c.id == id || c.name == id {
				_ = json.NewEncoder(w).Encode(f.inspect(c))
				return
			}
		}
	}
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"message":"No such container"}`))
}

// dockerEnv: Modul mit eingeschaltetem Abgleich gegen die nachgebaute API; Zeiten fuer Tests.
func dockerEnv(t *testing.T) (*env, *fakeDocker) {
	t.Helper()
	oldSelf, oldWait, oldDeb := dockerSelf, dockerRemoveWait, dockerDebounce
	t.Cleanup(func() { dockerSelf, dockerRemoveWait, dockerDebounce = oldSelf, oldWait, oldDeb })
	dockerSelf = func() (string, error) { return "node64-self", nil }
	dockerRemoveWait, dockerDebounce = time.Hour, 20*time.Millisecond
	f := newFakeDocker(t)
	e := newEnv(t)
	ctx := context.Background()
	_ = e.st.SetSetting(ctx, setDockerHost, f.srv.URL)
	_ = e.st.SetSetting(ctx, setDocker, "on")
	e.enable(t)
	for i := 0; i < 200 && !e.m.dockerView(ctx).Connected; i++ { // erster Abgleich der Schleife (danach ruht sie)
		time.Sleep(10 * time.Millisecond)
	}
	return e, f
}

// dockerOnce gleicht einmal ab (wie die Schleife).
func dockerOnce(t *testing.T, m *Module) time.Duration {
	t.Helper()
	ctx := context.Background()
	host := m.dockerAddr(ctx)
	hc, base, err := proxmox.DockerClient(host)
	if err != nil {
		t.Fatal(err)
	}
	return m.dockerSync(ctx, hc, base, host)
}

func dockerHosts(t *testing.T, m *Module) []*Host {
	t.Helper()
	list, err := m.hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []*Host
	for _, h := range list {
		if h.DockerContainer != "" {
			out = append(out, h)
		}
	}
	return out
}

func goneLen(m *Module) int {
	m.dk.run.Lock()
	defer m.dk.run.Unlock()
	return len(m.dk.gone)
}

func viewOf(m *Module, name string) dockerContainerView {
	for _, c := range m.dockerView(context.Background()).Containers {
		if c.Name == name {
			return c
		}
	}
	return dockerContainerView{}
}

func TestDockerCreateUpdate(t *testing.T) {
	ctx := context.Background()
	e, f := dockerEnv(t)
	_ = e.st.SetSetting(ctx, setDockerCert, "http") // ohne Nutzungsbedingungen: kein Zertifikat
	web := &fakeC{id: "c1", name: "web", state: "running", created: 1, labels: map[string]string{LabelProxyHost: "App.Example.test", LabelProxyPort: "8080"},
		nets: map[string]string{"proxy": "172.20.0.5", "other": "10.9.0.5"}}
	f.set(web, &fakeC{id: "c0", name: "plain", state: "running", nets: map[string]string{"proxy": "172.20.0.9"}})
	dockerOnce(t, e.m)
	list := dockerHosts(t, e.m)
	if len(list) != 1 {
		t.Fatalf("hosts: %d", len(list))
	}
	h := list[0]
	if h.DockerContainer != "web" || h.DockerRouter != "" || h.Names[0] != "app.example.test" || h.Target() != "http://172.20.0.5:8080" || h.Kind != KindProxy || !h.Enabled {
		t.Fatalf("created: %+v", h)
	}
	v := e.m.dockerView(ctx)
	if !v.Enabled || !v.Connected || v.Error != "" || v.Synced.IsZero() || len(v.Containers) != 1 || v.Containers[0].HostID != h.ID ||
		v.Containers[0].Target != "http://172.20.0.5:8080" || v.Containers[0].Source != dockerSrcNode64 || v.Containers[0].State != "running" {
		t.Fatalf("view: %+v", v)
	}
	if len(e.m.certIndex(ctx)) != 0 {
		t.Fatal("certificate requested without accepted terms")
	}
	if e.m.dockerHostLabel(h) != "web" || e.m.dockerHostLabel(&Host{DockerContainer: "a", DockerRouter: "r"}) != "a / r" {
		t.Fatal("label")
	}

	// Einstellungen in der Oberflaeche bleiben beim Aendern der Labels erhalten
	r, err := e.st.Writer().ExecContext(ctx, `INSERT INTO cdn_access_lists (name, satisfy_any, pass_auth, login_page, users, rules, created_at, updated_at)
		VALUES ('lan', 0, 0, 0, '[]', '[]', '', '')`)
	if err != nil {
		t.Fatal(err)
	}
	acl, _ := r.LastInsertId()
	h.AccessListID, h.WebSockets, h.Advanced.Gzip, h.Enabled, h.CertID = acl, false, false, false, CertNone
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	web.labels = map[string]string{LabelProxyHost: "app2.example.test, www.example.test", LabelProxyPort: "8443", LabelProxyScheme: "https"}
	web.nets["proxy"] = "172.20.0.6"
	f.mu.Unlock()
	dockerOnce(t, e.m)
	got, _ := e.m.host(ctx, h.ID)
	if got.Target() != "https://172.20.0.6:8443" || !slices.Equal(got.Names, []string{"app2.example.test", "www.example.test"}) {
		t.Fatalf("not updated: %+v", got)
	}
	if got.AccessListID != acl || got.WebSockets || got.Advanced.Gzip || got.Enabled || got.CertID != CertNone || got.DockerContainer != "web" {
		t.Fatalf("settings lost: %+v", got)
	}

	// Container gestoppt: Host bleibt unveraendert
	f.mu.Lock()
	web.state = "exited"
	f.mu.Unlock()
	dockerOnce(t, e.m)
	if got2, _ := e.m.host(ctx, h.ID); got2.Target() != got.Target() || viewOf(e.m, "web").Problem != "" || viewOf(e.m, "web").State != "exited" {
		t.Fatalf("stopped: %+v %+v", got2, viewOf(e.m, "web"))
	}

	// neuer Container mit selbst signiertem Zertifikat (eingestellt)
	_ = e.st.SetSetting(ctx, setDockerCert, "self")
	f.set(web, &fakeC{id: "c2", name: "api", state: "running", created: 2, labels: map[string]string{LabelProxyHost: "api.example.test"},
		exposed: []string{"3000/tcp"}, nets: map[string]string{"proxy": "172.20.0.7"}})
	dockerOnce(t, e.m)
	if v := viewOf(e.m, "api"); v.HostID == 0 || v.Target != "http://172.20.0.7:3000" {
		t.Fatalf("api: %+v", v)
	}
	if e.m.certIndex(ctx)["api.example.test"] == 0 {
		t.Fatal("no certificate requested")
	}
}

func TestDockerRemove(t *testing.T) {
	ctx := context.Background()
	e, f := dockerEnv(t)
	web := &fakeC{id: "c1", name: "web", state: "running", labels: map[string]string{LabelProxyHost: "web.example.test", LabelProxyPort: "80"},
		nets: map[string]string{"proxy": "172.20.0.5"}}
	f.set(web)
	dockerOnce(t, e.m)
	if len(dockerHosts(t, e.m)) != 1 {
		t.Fatal("not created")
	}
	// Liste fehlerhaft: nichts loeschen, Fehler anzeigen
	dockerRemoveWait = 0
	f.mu.Lock()
	f.fail, f.list = true, nil
	f.mu.Unlock()
	dockerOnce(t, e.m)
	if len(dockerHosts(t, e.m)) != 1 {
		t.Fatal("deleted after a failed list")
	}
	if v := e.m.dockerView(ctx); v.Connected || !strings.Contains(v.Error, "boom") {
		t.Fatalf("error not shown: %+v", v)
	}
	// Container weg: erst nach der Wartezeit loeschen; kommt er vorher wieder, bleibt der Host
	dockerRemoveWait = time.Hour
	f.mu.Lock()
	f.fail = false
	f.mu.Unlock()
	if dockerOnce(t, e.m); len(dockerHosts(t, e.m)) != 1 || goneLen(e.m) != 1 {
		t.Fatal("deleted before waiting")
	}
	f.set(web)
	dockerOnce(t, e.m)
	if len(dockerHosts(t, e.m)) != 1 || goneLen(e.m) != 0 {
		t.Fatal("return not noticed")
	}
	// Label entfernt: wie Container entfernt
	f.set(&fakeC{id: "c9", name: "web", state: "running", nets: map[string]string{"proxy": "172.20.0.5"}})
	dockerOnce(t, e.m)
	if len(dockerHosts(t, e.m)) != 1 {
		t.Fatal("deleted before waiting")
	}
	dockerRemoveWait = time.Minute
	if w := dockerOnce(t, e.m); w > time.Minute || w < 50*time.Second || len(dockerHosts(t, e.m)) != 1 {
		t.Fatalf("next run in %v", w)
	}
	dockerRemoveWait = 30 * time.Millisecond
	time.Sleep(40 * time.Millisecond)
	dockerOnce(t, e.m)
	if n := len(dockerHosts(t, e.m)); n != 0 {
		t.Fatalf("not deleted after waiting: %d", n)
	}
}

func TestDockerConflicts(t *testing.T) {
	ctx := context.Background()
	e, f := dockerEnv(t)
	hand := newHost()
	hand.Names, hand.TargetHost, hand.TargetPort = []string{"hand.example.test"}, "192.168.1.5", 80
	if err := e.m.saveHost(ctx, hand); err != nil {
		t.Fatal(err)
	}
	run := func(id, name string, created int64, labels map[string]string, nets map[string]string, exposed ...string) *fakeC {
		return &fakeC{id: id, name: name, state: "running", created: created, labels: labels, nets: nets, exposed: exposed}
	}
	proxy := map[string]string{"proxy": "172.20.0.10"}
	f.set(
		run("a", "a", 1, map[string]string{LabelProxyHost: "hand.example.test", LabelProxyPort: "80"}, proxy),
		run("c", "c", 3, map[string]string{LabelProxyHost: "dup.example.test", LabelProxyPort: "80"}, proxy),
		run("b", "b", 2, map[string]string{LabelProxyHost: "dup.example.test", LabelProxyPort: "80"}, proxy),
		run("d", "d", 4, map[string]string{LabelProxyHost: "d.example.test"}, proxy, "80/tcp", "443/tcp"),
		run("e", "e", 5, map[string]string{LabelProxyHost: "e.example.test", LabelProxyPort: "80", LabelProxyNetwork: "nope"}, proxy),
		run("f", "f", 6, map[string]string{LabelProxyHost: "inv@lid.test", LabelProxyPort: "80"}, proxy),
		run("g", "g", 7, map[string]string{LabelProxyHost: "g.example.test", LabelProxyPort: "abc"}, proxy),
		run("h", "h", 8, map[string]string{LabelProxyPort: "80"}, proxy),
		&fakeC{id: "i", name: "i", state: "running", created: 9, labels: map[string]string{LabelProxyHost: "i.example.test"}, exposed: []string{"3000/tcp"},
			nets: map[string]string{"other": "10.9.0.4"}, published: map[string]string{"3000/tcp": "13000"}},
		run("j", "j", 10, map[string]string{LabelProxyHost: "j.example.test", LabelProxyPort: "80"}, map[string]string{"other": "10.9.0.5"}),
	)
	dockerOnce(t, e.m)
	want := map[string][2]string{"a": {dockerErrNameTaken, "hand.example.test"}, "b": {"", ""}, "c": {dockerErrDup, "b"}, "d": {dockerErrNoPort, ""},
		"e": {dockerErrNetwork, "nope"}, "f": {dockerErrName, "inv@lid.test"}, "g": {dockerErrPort, "abc"}, "h": {dockerErrHost, ""}, "i": {"", ""},
		"j": {dockerErrNoTarget, ""}}
	for n, w := range want {
		v := viewOf(e.m, n)
		if v.Name != n || v.Problem != w[0] || v.ProblemName != w[1] || (v.HostID != 0) != (w[0] == "") {
			t.Errorf("%s: %+v, want %v", n, v, w)
		}
	}
	if v := viewOf(e.m, "i"); v.Target != "http://172.20.0.1:13000" {
		t.Errorf("published port: %+v", v)
	}
	if len(dockerHosts(t, e.m)) != 2 {
		t.Fatalf("docker hosts: %d", len(dockerHosts(t, e.m)))
	}
	if got, _ := e.m.host(ctx, hand.ID); got.DockerContainer != "" || got.TargetHost != "192.168.1.5" {
		t.Fatalf("hand host changed: %+v", got)
	}
}

func TestDockerTarget(t *testing.T) {
	in := func(running bool, mode string, nets map[string]dockerNet) *dockerInspectC {
		var x dockerInspectC
		x.State.Running, x.HostConfig.NetworkMode, x.NetworkSettings.Networks = running, mode, nets
		return &x
	}
	c := in(true, "bridge", map[string]dockerNet{"b-net": {IPAddress: "10.1.0.3"}, "a-net": {IPAddress: "10.2.0.3"}})
	self := in(true, "bridge", map[string]dockerNet{"b-net": {IPAddress: "10.1.0.2", Gateway: "10.1.0.1"}})
	hostSelf := in(true, "host", map[string]dockerNet{"host": {}})
	cases := []struct {
		name    string
		s       dockerSpec
		c, self *dockerInspectC
		addr    string
		port    int
		key     string
	}{
		{"label network", dockerSpec{Network: "a-net"}, c, self, "10.2.0.3", 80, ""},
		{"shared network", dockerSpec{}, c, self, "10.1.0.3", 80, ""},
		{"node64 host mode", dockerSpec{}, c, hostSelf, "10.2.0.3", 80, ""},
		{"no own container", dockerSpec{}, c, nil, "10.2.0.3", 80, ""},
		{"container host mode", dockerSpec{}, in(true, "host", map[string]dockerNet{"host": {}}), hostSelf, "127.0.0.1", 80, ""},
		{"container host mode, node bridged", dockerSpec{}, in(true, "host", map[string]dockerNet{"host": {}}), self, "10.1.0.1", 80, ""},
		{"stopped", dockerSpec{}, in(false, "bridge", map[string]dockerNet{"b-net": {}}), self, "", 0, ""},
		{"no target", dockerSpec{}, in(true, "bridge", map[string]dockerNet{"x": {IPAddress: "10.3.0.3"}}), self, "", 0, dockerErrNoTarget},
		{"unknown network", dockerSpec{Network: "nope"}, c, self, "", 0, dockerErrNetwork},
	}
	for _, tc := range cases {
		addr, port, key, _ := dockerTarget(tc.s, tc.c, tc.self, 80)
		if addr != tc.addr || port != tc.port || key != tc.key {
			t.Errorf("%s: %s %d %q", tc.name, addr, port, key)
		}
	}
}

func TestDockerAPIProtect(t *testing.T) {
	ctx := context.Background()
	e, f := dockerEnv(t)
	f.set(&fakeC{id: "c1", name: "web", state: "running", labels: map[string]string{LabelProxyHost: "web.example.test", LabelProxyPort: "80"},
		nets: map[string]string{"proxy": "172.20.0.5"}})
	dockerOnce(t, e.m)
	h := dockerHosts(t, e.m)[0]
	call := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		e.mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec
	}
	hp := "/api/cdn64/hosts/" + strconv.FormatInt(h.ID, 10)
	rec := call("PUT", hp, `{"names":["evil.example.test"],"target_host":"1.2.3.4","target_port":22,"scheme":"https","kind":"redirect","websockets":false,"docker_container":""}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	got, _ := e.m.host(ctx, h.ID)
	if got.Names[0] != "web.example.test" || got.Target() != "http://172.20.0.5:80" || got.Kind != KindProxy || got.DockerContainer != "web" || got.WebSockets {
		t.Fatalf("put changed labels or kept settings: %+v", got)
	}
	if rec := call("DELETE", hp, ""); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "cdn64.docker.err.delete") {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	rec = call("POST", "/api/cdn64/hosts", `{"names":["new.example.test"],"target_host":"192.168.1.9","target_port":80,"docker_container":"web","docker_router":"x"}`)
	var created Host
	if err := json.Unmarshal(rec.Body.Bytes(), &created); rec.Code != http.StatusCreated || err != nil || created.DockerContainer != "" || created.DockerRouter != "" {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	rec = call("GET", "/api/cdn64/docker", "")
	var v dockerView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || !v.Enabled || len(v.Containers) != 1 || v.Containers[0].HostID != h.ID {
		t.Fatalf("docker view: %s", rec.Body)
	}
	// Schalter aus: Hosts bleiben und lassen sich loeschen
	_ = e.st.SetSetting(ctx, setDocker, "off")
	if rec := call("DELETE", hp, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete with docker off: %d %s", rec.Code, rec.Body)
	}
}

// Schleife: Schalter per dockerKick, Ereignisse loesen einen Abgleich aus.
func TestDockerLoopEvents(t *testing.T) {
	ctx := context.Background()
	oldSelf, oldDeb := dockerSelf, dockerDebounce
	t.Cleanup(func() { dockerSelf, dockerDebounce = oldSelf, oldDeb })
	dockerSelf = func() (string, error) { return "node64-self", nil }
	dockerDebounce = 20 * time.Millisecond
	f := newFakeDocker(t)
	e := newEnv(t)
	e.enable(t)
	web := &fakeC{id: "c1", name: "web", state: "running", labels: map[string]string{LabelProxyHost: "web.example.test", LabelProxyPort: "80"},
		nets: map[string]string{"proxy": "172.20.0.5"}}
	f.set(web)
	_ = e.st.SetSetting(ctx, setDockerHost, f.srv.URL)
	_ = e.st.SetSetting(ctx, setDocker, "on")
	e.m.dockerKick()
	wait := func(what string, ok func() bool) {
		t.Helper()
		for i := 0; i < 200; i++ {
			if ok() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal(what)
	}
	wait("not created after kick", func() bool { return len(dockerHosts(t, e.m)) == 1 && e.m.dockerView(ctx).Connected })
	f.set(web, &fakeC{id: "c2", name: "api", state: "running", created: 2, labels: map[string]string{LabelProxyHost: "api.example.test", LabelProxyPort: "80"},
		nets: map[string]string{"proxy": "172.20.0.6"}})
	time.Sleep(50 * time.Millisecond) // Ereignis-Stream verbunden
	f.events <- "create"              // zaehlt nicht
	f.events <- "start"
	wait("event did not trigger a sync", func() bool { return len(dockerHosts(t, e.m)) == 2 })
	// Schalter aus: Stand leer, Hosts bleiben
	_ = e.st.SetSetting(ctx, setDocker, "off")
	e.m.dockerKick()
	wait("not switched off", func() bool { v := e.m.dockerView(ctx); return !v.Enabled && len(v.Containers) == 0 })
	if len(dockerHosts(t, e.m)) != 2 {
		t.Fatal("hosts removed when switched off")
	}
}
