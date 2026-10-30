package healthchecks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/metrics"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/proxmox"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

// dockerView ergaenzt pveView um das, was die Healthchecks-Liste zusaetzlich braucht.
type dockerView struct{ pveView }

func (dockerView) Date(t time.Time) string { return t.Format("2006-01-02") }

// newDockerModule: Modul mit Render, das die Templates ausfuehrt und die Daten der letzten Seite merkt.
func newDockerModule(t *testing.T) (*httptest.Server, *any) {
	_, srv, last, _ := newDockerModuleRec(t, pveCore(t))
	return srv, last
}

// newDockerModuleRec: wie newDockerModule, mit Modul und abgefangenen Meldungen.
func newDockerModuleRec(t *testing.T, core *store.Store) (*Module, *httptest.Server, *any, *pveRec) {
	t.Helper()
	return newDockerModuleBox(t, core, nil)
}

// newDockerModuleBox: wie newDockerModuleRec, mit Schluessel fuer Zugangsdaten (nil = keiner).
func newDockerModuleBox(t *testing.T, core *store.Store, box *secrets.Box) (*Module, *httptest.Server, *any, *pveRec) {
	t.Helper()
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := New(core, lg, nil, nil, "test")
	if err := core.Migrate(context.Background(), Name, m.Migrations()); err != nil {
		t.Fatal(err)
	}
	if box != nil {
		m.SetSecrets(box)
	}
	rec := &pveRec{}
	m.pve.noRun, m.pve.alert = true, rec.add
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Stop(context.Background()) })
	last := new(any)
	var mu sync.Mutex
	funcs := template.FuncMap{"split": strings.Fields, "ms": func(f float64) string { return fmt.Sprint(f) }, "contains": strings.Contains, "join": strings.Join,
		"add": func(a, b int) int { return a + b }, "sub": func(a, b int) int { return a - b }}
	render := func(w http.ResponseWriter, r *http.Request, status int, page, titleKey string, data any) {
		mu.Lock()
		*last = data
		mu.Unlock()
		name := strings.TrimPrefix(page, Name+"/")
		tpl := template.Must(template.New("root").Funcs(funcs).Parse(`{{template "content" .}}{{block "scripts" .}}{{end}}`))
		if _, err := tpl.ParseFS(templateFS, "templates/pages/"+name+".html"); err != nil {
			t.Errorf("%s: %v", name, err)
			http.Error(w, err.Error(), 500)
			return
		}
		var buf bytes.Buffer
		if err := tpl.Execute(&buf, dockerView{pveView{Data: data, CSRF: "csrf", Version: "v"}}); err != nil {
			t.Errorf("%s: %v", name, err)
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write(buf.Bytes())
	}
	mux := http.NewServeMux()
	pass := func(h http.Handler) http.Handler { return h }
	m.Routes(mux, module.Guards{Enabled: pass, Auth: pass, Render: render,
		T:        func(r *http.Request, key string, args ...any) string { return key },
		Lang:     func(*http.Request) string { return "de" },
		Timezone: func(*http.Request) *time.Location { return time.UTC },
		Flash: func(w http.ResponseWriter, r *http.Request, kind, text string) {
			w.Header().Add("X-Flash", kind+":"+text)
		},
		Audit: func(*http.Request, string, string, string) {}})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return m, srv, last, rec
}

// fakeContainers ersetzt die Abfrage des Docker-Hosts fuer einen Test.
func fakeContainers(t *testing.T, cs []checks.Container, err error) *atomic.Int32 {
	t.Helper()
	calls := new(atomic.Int32)
	old := listContainers
	listContainers = func(context.Context, string) ([]checks.Container, error) {
		calls.Add(1)
		return cs, err
	}
	t.Cleanup(func() { listContainers = old })
	return calls
}

func dockerGetPage(t *testing.T, srv *httptest.Server, path string) string {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d %s", path, resp.StatusCode, b)
	}
	return string(b)
}

// dockerPost schickt ein Formular ohne Weiterleitung zu folgen und liefert das Ziel.
func dockerPost(t *testing.T, srv *httptest.Server, path string, form url.Values) (int, string) {
	t.Helper()
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.PostForm(srv.URL+path, form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

// dockerAddLocal richtet den lokalen Docker-Host ein (Knopf in der Uebersicht) und liefert den Pfad seiner Seite.
func dockerAddLocal(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	code, loc := dockerPost(t, srv, "/healthchecks/docker/enable", url.Values{})
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/healthchecks/docker/system/") {
		t.Fatalf("add local: %d %q", code, loc)
	}
	return loc
}

func dockerSeed(t *testing.T, srv *httptest.Server) {
	t.Helper()
	for _, c := range []map[string]any{
		{"name": "Web-Check", "type": "docker", "target": "web"},
		{"name": "Gone-Check", "type": "docker", "target": "gone"},
		{"name": "Remote-Check", "type": "docker", "target": "far", "params": map[string]any{"host": "tcp://other:2375"}},
		{"name": "HTTP-Check", "type": "http", "target": "http://127.0.0.1:9/"},
	} {
		if code, b := call(t, srv, "POST", "/api/checks", c); code != http.StatusCreated {
			t.Fatalf("create %v: %d %s", c["name"], code, b)
		}
	}
}

var dockerHost = []checks.Container{
	{ID: "aaaaaaaaaaaa", Name: "web", Image: "nginx:1", State: "running", Status: "Up 1 hour (healthy)", Created: 1700000000, Ports: []string{"8080->80/tcp"}},
	{ID: "bbbbbbbbbbbb", Name: "db", Image: "postgres:16", State: "exited", Status: "Exited (1) 2 hours ago", Created: 1700000000},
	{ID: "cccccccccccc", Name: "cache", Image: "redis:7", State: "running", Status: "Up 5 minutes (unhealthy)", Created: 1700000000},
}

// Ohne laufende Abfrage (wartet): Containerliste direkt; der Host kommt erst nach dem Hinzufuegen.
func TestDockerPage(t *testing.T) {
	fakeContainers(t, dockerHost, nil)
	srv, last := newDockerModule(t)
	dockerSeed(t, srv)

	ov := dockerGetPage(t, srv, "/healthchecks/docker") // Uebersicht, nichts automatisch eingerichtet
	if hd, ok := (*last).(dockerHostsData); !ok || len(hd.Hosts) != 0 || !hd.Socket || !strings.Contains(ov, "/healthchecks/docker/enable") || !strings.Contains(ov, "docker.empty") {
		t.Fatalf("overview: %T %+v", *last, *last)
	}
	hp := dockerAddLocal(t, srv)
	body := dockerGetPage(t, srv, hp)
	d := (*last).(dockerData)
	if d.Sys == nil || !d.Sys.IsDocker() || d.View.State != "pending" || d.Live {
		t.Fatalf("system: %+v state=%s live=%v", d.Sys, d.View.State, d.Live)
	}
	// db: beendet mit Fehler, nie laufend gesehen -> keine Stoerung; cache unhealthy und gone (fehlt) schon
	if !d.Socket || d.Total != 3 || d.Running != 1 || d.Bad != 2 || d.Missing != 1 || d.Watched != 3 || d.All != 5 || len(d.Rows) != 5 {
		t.Fatalf("kpi: socket=%v total=%d running=%d bad=%d missing=%d watched=%d all=%d rows=%d", d.Socket, d.Total, d.Running, d.Bad, d.Missing, d.Watched, d.All, len(d.Rows))
	}
	kinds := map[string]string{}
	for _, r := range d.Rows {
		k := r.Kind
		if r.Hc != nil {
			k += "+check"
		}
		kinds[r.Name] = k + "/" + r.R.Health
	}
	want := map[string]string{"web": "running+check/healthy", "db": "stopped/", "cache": "running/unhealthy", "gone": "missing+check/", "far": "remote+check/"}
	for n, k := range want {
		if kinds[n] != k {
			t.Errorf("%s: %q, want %q (%v)", n, kinds[n], k, kinds)
		}
	}
	act := fmt.Sprintf("/healthchecks/proxmox/system/%d", d.Sys.ID)
	for _, s := range []string{`data-container="web"`, "Web-Check", "8080-&gt;80/tcp", "hc.docker.kind.missing", "hc.docker.kind.remote",
		`name="back" value="docker"`, "hc.docker.socket_ok", "stat-value", act + "/ascheck", `name="key" value="docker/db"`, "docker.state.unhealthy",
		fmt.Sprintf("/healthchecks/docker/system/%d/c/web", d.Sys.ID), "pve.rules.level_docker_system", "docker.rule.crashed", "pve.pending"} {
		if !strings.Contains(body, s) {
			t.Errorf("page lacks %q", s)
		}
	}
	if strings.Contains(body, "HTTP-Check") || strings.Contains(body, "pve.rule.suspended") || strings.Contains(body, "hc.docker.watch") {
		t.Error("non-docker check, suspended rule or old watch button shown")
	}

	// Filter
	dockerGetPage(t, srv, hp+"?state=unwatched")
	if d := (*last).(dockerData); len(d.Rows) != 2 || d.Rows[0].Name != "cache" || d.Rows[1].Name != "db" {
		t.Fatalf("unwatched: %+v", d.Rows)
	}
	dockerGetPage(t, srv, hp+"?state=problem")
	if d := (*last).(dockerData); len(d.Rows) != 2 { // cache (unhealthy), gone (fehlt)
		t.Fatalf("problem: %d rows", len(d.Rows))
	}
	dockerGetPage(t, srv, hp+"?state=stopped")
	if d := (*last).(dockerData); len(d.Rows) != 1 || d.Rows[0].Name != "db" {
		t.Fatalf("stopped: %+v", d.Rows)
	}
	dockerGetPage(t, srv, hp+"?q=postgres")
	if d := (*last).(dockerData); len(d.Rows) != 1 || d.Rows[0].Name != "db" {
		t.Fatalf("search: %+v", d.Rows)
	}

	// API
	code, b := call(t, srv, "GET", "/api/healthchecks/docker/containers", nil)
	var out struct {
		Socket     bool         `json:"socket"`
		SystemID   int64        `json:"system_id"`
		Containers []dockerJSON `json:"containers"`
	}
	if code != http.StatusOK || json.Unmarshal(b, &out) != nil || !out.Socket || len(out.Containers) != 5 || out.SystemID != d.Sys.ID {
		t.Fatalf("api: %d %s", code, b)
	}
	for _, c := range out.Containers {
		switch c.Name {
		case "web":
			if c.Check == nil || c.Check.Name != "Web-Check" || c.Image != "nginx:1" || len(c.Ports) != 1 || c.Created == nil || c.Key != "docker/web" {
				t.Errorf("api web: %+v", c)
			}
		case "db", "cache":
			if c.Check != nil {
				t.Errorf("api %s: unexpected check", c.Name)
			}
		case "gone":
			if c.Kind != "missing" || c.Check == nil || !c.Bad {
				t.Errorf("api gone: %+v", c)
			}
		}
	}

	// Aktion von der Docker-Seite fuehrt dorthin zurueck
	tok := ""
	for _, r := range d.Rows {
		if r.Name == "web" {
			tok = r.Hc.Check.Token
		}
	}
	if _, loc := dockerPost(t, srv, "/healthchecks/"+tok+"/action", url.Values{"action": {"pause"}, "back": {"docker"}}); loc != dockerPath {
		t.Fatalf("back: %q", loc)
	}
}

// Ohne Socket: leere Uebersicht ohne Knopf fuer diese Maschine, Hinweis auf die Docker-Checks der Check-Liste.
func TestDockerPageNoSocket(t *testing.T) {
	fakeContainers(t, nil, errors.New("dial unix /var/run/docker.sock: connect: no such file or directory – mount the socket"))
	srv, last := newDockerModule(t)
	dockerSeed(t, srv)
	body := dockerGetPage(t, srv, "/healthchecks/docker")
	d := (*last).(dockerHostsData)
	if len(d.Hosts) != 0 || d.Socket || d.Orphans != 3 {
		t.Fatalf("no socket: %+v", d)
	}
	for _, s := range []string{`id="docker-empty"`, "docker.orphans", "/healthchecks?type=docker", "/healthchecks/docker/new"} {
		if !strings.Contains(body, s) {
			t.Errorf("page lacks %q", s)
		}
	}
	if strings.Contains(body, "/healthchecks/docker/enable") || strings.Contains(body, "docker-kpi") {
		t.Error("local button or kpi without socket/hosts")
	}
}

// Socket erreichbar: trotzdem nichts automatisch, die Uebersicht bietet die Maschine an.
func TestDockerPageEmpty(t *testing.T) {
	fakeContainers(t, nil, nil)
	m, srv, _, _ := newDockerModuleRec(t, pveCore(t))
	body := dockerGetPage(t, srv, "/healthchecks/docker")
	if !strings.Contains(body, "docker.empty") || !strings.Contains(body, "/healthchecks/docker/enable") || strings.Contains(body, "docker.orphans") {
		t.Fatal("empty overview")
	}
	if list, _ := m.dockerSystems(context.Background()); len(list) != 0 {
		t.Fatalf("set up automatically: %d", len(list))
	}
}

// Die Healthchecks-Liste zeigt Docker-Checks als normale Zeilen und fragt den Docker-Host nicht mehr ab.
func TestListWithoutDockerSection(t *testing.T) {
	calls := fakeContainers(t, dockerHost, nil)
	srv, last := newDockerModule(t)
	dockerSeed(t, srv)
	body := dockerGetPage(t, srv, "/healthchecks")
	if n := calls.Load(); n != 0 {
		t.Fatalf("list page queried docker %d times", n)
	}
	d := (*last).(listData)
	if len(d.Rows) != 4 {
		t.Fatalf("rows: %d", len(d.Rows))
	}
	for _, s := range []string{"hc.docker.unwatched", "hc-bulk-docker", "hc.docker.title"} {
		if strings.Contains(body, s) {
			t.Errorf("list still contains %q", s)
		}
	}
	if !strings.Contains(body, "Web-Check") || !strings.Contains(body, "Gone-Check") {
		t.Error("docker checks missing in main table")
	}
	dockerGetPage(t, srv, "/healthchecks?type=docker")
	if d := (*last).(listData); len(d.Rows) != 3 {
		t.Fatalf("type=docker: %d rows", len(d.Rows))
	}
}

// ---------------------------------------------------------------- Ueberwachung mit Abfrage (Docker-API nachgebildet)

// dockerAPI ist eine Docker-API (nur GET) mit veraenderbaren Containern.
type dockerAPI struct {
	mu      sync.Mutex
	cts     []*dockerCt
	started time.Time
}

type dockerCt struct {
	id, name, state, status, health string
	exit, restarts                  int
	cpu, sys, mem, rx               uint64
	labels                          map[string]string
}

func (f *dockerAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	enc := json.NewEncoder(w)
	switch p := r.URL.Path; {
	case p == "/info":
		_ = enc.Encode(map[string]any{"Name": "box", "NCPU": 2, "MemTotal": 4 << 30, "ServerVersion": "27.3.1"})
	case p == "/containers/json":
		var out []map[string]any
		for _, c := range f.cts {
			out = append(out, map[string]any{"Id": c.id, "Names": []string{"/" + c.name}, "Image": c.name + ":1", "State": c.state, "Status": c.status,
				"Created": 1700000000, "Labels": c.labels})
		}
		_ = enc.Encode(out)
	default:
		for _, c := range f.cts {
			switch p {
			case "/containers/" + c.id + "/json":
				st := map[string]any{"Status": c.state, "ExitCode": c.exit, "StartedAt": f.started.Format(time.RFC3339Nano)}
				if c.health != "" {
					st["Health"] = map[string]any{"Status": c.health}
				}
				_ = enc.Encode(map[string]any{"RestartCount": c.restarts, "State": st})
				return
			case "/containers/" + c.id + "/stats":
				_ = enc.Encode(map[string]any{"cpu_stats": map[string]any{"cpu_usage": map[string]any{"total_usage": c.cpu}, "system_cpu_usage": c.sys, "online_cpus": 2},
					"memory_stats": map[string]any{"usage": c.mem, "limit": 1 << 30, "stats": map[string]any{"inactive_file": 0}},
					"networks":     map[string]any{"eth0": map[string]any{"rx_bytes": c.rx, "tx_bytes": 0}}})
				return
			}
		}
		http.Error(w, `{"message":"No such container"}`, http.StatusNotFound)
	}
}

func (f *dockerAPI) set(name string, fn func(c *dockerCt)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cts {
		if c.name == name {
			fn(c)
		}
	}
}

// fakeDockerSource: Docker-Hosts fragen die nachgebildete API (statt des Sockets).
func fakeDockerSource(t *testing.T) *dockerAPI {
	t.Helper()
	api := &dockerAPI{cts: []*dockerCt{
		{id: "aaa1", name: "web", state: "running", status: "Up 1 hour (healthy)", health: "healthy", cpu: 1e9, sys: 100e9, mem: 256 << 20},
		{id: "bbb1", name: "db", state: "exited", status: "Exited (1) 2 hours ago", exit: 1},
		{id: "ccc1", name: "cache", state: "running", status: "Up 5 minutes (unhealthy)", health: "unhealthy", cpu: 1e9, sys: 100e9, mem: 64 << 20},
		{id: "ddd1", name: "tmp", state: "running", status: "Up 1 hour", labels: map[string]string{proxmox.LabelNoMonitor: "true"}, cpu: 1, sys: 1, mem: 1},
	}, started: time.Now().Add(-time.Hour)}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	old := pveNewSource
	pveNewSource = func(log *slog.Logger, sys proxmox.System, fn proxmox.SnapshotFunc) proxmox.Source {
		if sys.IsDocker() {
			return proxmox.NewDockerPollerClient(log, sys, fn, srv.Client(), srv.URL)
		}
		return old(log, sys, fn)
	}
	t.Cleanup(func() { pveNewSource = old })
	return api
}

func dockerSysID(t *testing.T, m *Module) int64 {
	t.Helper()
	list, err := m.dockerSystems(context.Background())
	if err != nil || len(list) != 1 {
		t.Fatalf("docker systems: %d %v", len(list), err)
	}
	return list[0].ID
}

func TestDockerMonitorLive(t *testing.T) {
	fakeContainers(t, dockerHost, nil) // Socket fuer die automatische Einrichtung
	api := fakeDockerSource(t)
	m, srv, last, rec := newDockerModuleRec(t, pveCore(t))
	dockerSeed(t, srv)
	hp := dockerAddLocal(t, srv)
	id := dockerSysID(t, m)
	ctx := context.Background()

	// erste Abfrage: cache unhealthy sofort gemeldet; db nie gelaufen: nichts; tmp ausgeschlossen
	pvePollNow(t, m, id)
	if got := pveKinds(rec.take()); got != "proxmox_down:docker/cache:unhealthy" {
		t.Fatalf("alerts: %q", got)
	}
	// vorhandener Docker-Check fuer web wird als Check gefuehrt (keine doppelte Meldung)
	set, _ := m.pve.st.Settings(ctx, id)
	if it := set.Item("docker/web"); it == nil || !it.AsCheck || it.CheckToken == "" {
		t.Fatalf("web nicht verknuepft: %+v", it)
	}
	time.Sleep(10 * time.Millisecond)
	pvePollNow(t, m, id)

	body := dockerGetPage(t, srv, hp)
	d := (*last).(dockerData)
	if !d.Live || d.Info == nil || d.Info.Name != "box" || d.Total != 4 || d.Bad != 2 || d.AsCheck != 1 { // cache + gone
		t.Fatalf("live: live=%v total=%d bad=%d ascheck=%d", d.Live, d.Total, d.Bad, d.AsCheck)
	}
	for _, r := range d.Rows {
		switch r.Name {
		case "web":
			if !r.Linked || r.Mem == "" || !r.MemUsed() || r.R.MaxMem != 1<<30 || !r.Rates {
				t.Errorf("web: %+v", r)
			}
		case "tmp":
			if !r.Excluded || r.Problem() {
				t.Errorf("tmp: %+v", r)
			}
		}
	}
	for _, s := range []string{"docker.live", "docker.kpi.load", "Docker 27.3.1", "box"} {
		if !strings.Contains(body, s) {
			t.Errorf("page lacks %q", s)
		}
	}
	// Uebersicht: neuere Docker-Version bekannt -> nur das kleine Badge an der Version
	latestSet(t, "docker", "28.5.1")
	if ov := dockerGetPage(t, srv, "/healthchecks/docker"); !strings.Contains(ov, "Docker 27.3.1") || !strings.Contains(ov, "bi-arrow-up-circle") || !strings.Contains(ov, "28.5.1") || !strings.Contains(ov, "pve.update_major_hint") {
		t.Errorf("overview update badge: %s", ov)
	}

	// Containerseite
	body = dockerGetPage(t, srv, fmt.Sprintf("/healthchecks/docker/system/%d/c/cache", id))
	d = (*last).(dockerData)
	if d.Res == nil || d.Res.Row.Name != "cache" || !d.Res.Row.Found || d.Rules.Level != "guest" || d.Rules.Text != "container" {
		t.Fatalf("container page: %+v", d.Res)
	}
	for _, s := range []string{fmt.Sprintf("/api/healthchecks/docker/systems/%d/series?key=docker/cache", id), "pve-chart-cpu", "pve.rules.level_container",
		"docker.state.unhealthy", "pve.check.add", "/static/js/proxmox.js"} {
		if !strings.Contains(body, s) {
			t.Errorf("container page lacks %q", s)
		}
	}
	dockerGetPage(t, srv, fmt.Sprintf("/healthchecks/docker/system/%d/c/nothere", id))
	if d := (*last).(dockerData); d.Res == nil || d.Res.Row.Found {
		t.Fatal("missing container page")
	}
	// Proxmox-Seiten leiten weiter, Proxmox-Uebersicht ohne Docker
	if _, loc := dockerPostGet(t, srv, fmt.Sprintf("/healthchecks/proxmox/system/%d", id)); loc != dockerSysPath(id) {
		t.Fatalf("redirect: %q", loc)
	}
	dockerGetPage(t, srv, "/healthchecks/proxmox")
	if o := (*last).(pveOverviewData); len(o.Systems) != 0 {
		t.Fatalf("proxmox overview lists docker: %d", len(o.Systems))
	}

	// Verlauf
	code, b := call(t, srv, "GET", fmt.Sprintf("/api/healthchecks/docker/systems/%d/series?key=docker/web&range=1h", id), nil)
	if code != http.StatusOK || !strings.Contains(string(b), `"points":[{`) {
		t.Fatalf("series: %d %s", code, b)
	}

	// Regeln je Container (Formular), Weiterleitung auf die Containerseite
	if _, loc := dockerPost(t, srv, fmt.Sprintf("/healthchecks/proxmox/system/%d/settings", id), url.Values{"key": {"docker/web"}, "r_mem": {"80"}, "r_mem_min": {"5"}}); loc != pveResPath(id, "docker/web") {
		t.Fatalf("settings back: %q", loc)
	}
	set, _ = m.pve.st.Settings(ctx, id)
	if it := set.Item("docker/web"); it.Rules.Mem == nil || it.Rules.Mem.Percent != 80 || !it.AsCheck {
		t.Fatalf("rules: %+v", it)
	}

	// Als Check: cache ist gemeldet -> der neue Docker-Check beginnt gestoert, die Engine meldet nichts mehr
	if _, loc := dockerPost(t, srv, fmt.Sprintf("/healthchecks/proxmox/system/%d/ascheck", id), url.Values{"key": {"docker/cache"}, "on": {"1"}, "back": {dockerPath}}); loc != dockerPath {
		t.Fatalf("ascheck back: %q", loc)
	}
	set, _ = m.pve.st.Settings(ctx, id)
	it := set.Item("docker/cache")
	c, _ := m.st.Check(ctx, it.CheckToken)
	if c == nil || c.Type != checks.TypeDocker || c.Target != "cache" || c.Group != dockerCheckGroup || c.Paused || c.Runtime.State != "down" {
		t.Fatalf("as check: %+v", c)
	}
	api.set("cache", func(c *dockerCt) { c.status, c.health = "Up 6 minutes (healthy)", "healthy" })
	pvePollNow(t, m, id)
	if got := rec.take(); len(got) != 0 {
		t.Fatalf("as check: engine meldet %q", pveKinds(got))
	}
	// wieder gestoert, dann Check entfernen (Check gestoert): die Engine uebernimmt und meldet nur die Entwarnung
	api.set("cache", func(c *dockerCt) { c.status, c.health = "Up 7 minutes (unhealthy)", "unhealthy" })
	pvePollNow(t, m, id)
	if s := m.scheduler(); s != nil {
		rt, _ := s.Runtime(c.Token)
		rt.State = "down"
		s.Upsert(c.SchedulerCheck(), &rt)
	}
	dockerPost(t, srv, fmt.Sprintf("/healthchecks/proxmox/system/%d/ascheck", id), url.Values{"key": {"docker/cache"}, "on": {"0"}})
	if c, _ := m.st.Check(ctx, c.Token); c != nil {
		t.Fatal("check not removed")
	}
	pvePollNow(t, m, id)
	if got := pveKinds(rec.take()); got != "" {
		t.Fatalf("adopt: no second down expected, got %q", got)
	}
	api.set("cache", func(c *dockerCt) { c.status, c.health = "Up 8 minutes (healthy)", "healthy" })
	pvePollNow(t, m, id)
	if got := pveKinds(rec.take()); got != "proxmox_up:docker/cache:unhealthy" {
		t.Fatalf("adopt up: %q", got)
	}

	// Meldung: Link auf die Docker-Seite, Typ docker
	api.set("web", func(c *dockerCt) { c.state, c.status, c.exit = "exited", "Exited (2) 1 second ago", 2 })
	if _, loc := dockerPost(t, srv, fmt.Sprintf("/healthchecks/proxmox/system/%d/ascheck", id), url.Values{"key": {"docker/web"}, "on": {"0"}}); loc == "" {
		t.Fatal("web as check off")
	}
	pvePollNow(t, m, id)
	al := rec.take()
	if len(al) != 1 || al[0].Data["what"] != "exited" || al[0].Data["type"] != "docker" || al[0].Data["detail"] != "2" ||
		al[0].Data["path"] != pveResPath(id, "docker/web") || al[0].Check.Type != "docker" {
		t.Fatalf("alert web: %+v", al)
	}
	if inc := m.lastIncident(ctx, dockerSettingLast); inc == nil || inc.Key != "docker/web" || m.pveLastIncident(ctx) != nil {
		t.Fatalf("last incident: %+v", inc)
	}

	// Metriken
	w := metrics.New()
	m.Metrics(ctx, w)
	var buf bytes.Buffer
	_, _ = w.WriteTo(&buf)
	sl := fmt.Sprintf(`system="Docker",system_id="%d"`, id)
	for _, want := range []string{`node64_docker_up{` + sl + `} 1`, `node64_docker_container_state{` + sl + `,name="web",state="error",detail="exited"} 1`,
		`node64_docker_container_memory_limit_bytes{` + sl + `,name="cache"} 1.073741824e+09`, `node64_docker_containers_bad{` + sl + `} 1`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("metrics: %q missing:\n%s", want, buf.String())
		}
	}
	if strings.Contains(buf.String(), "node64_pve_") {
		t.Error("docker in pve metrics")
	}

	// API: Proxmox-Liste ohne Docker, Docker-Liste mit kind
	code, b = call(t, srv, "GET", "/api/healthchecks/proxmox/systems", nil)
	if code != http.StatusOK || strings.TrimSpace(string(b)) != "[]" {
		t.Fatalf("pve list: %d %s", code, b)
	}
	code, b = call(t, srv, "GET", "/api/healthchecks/docker/systems", nil)
	if code != http.StatusOK || !strings.Contains(string(b), `"kind":"docker"`) || !strings.Contains(string(b), `"guests":3`) {
		t.Fatalf("docker list: %d %s", code, b)
	}
	if code, b = call(t, srv, "POST", "/api/healthchecks/proxmox/probe", map[string]any{"system_id": id}); code != http.StatusUnprocessableEntity {
		t.Fatalf("probe docker: %d %s", code, b)
	}

	// Abschalten (Schalter auf der Seite), Entfernen per API: Docker-Checks bleiben, keine neue Einrichtung
	if _, loc := dockerPost(t, srv, fmt.Sprintf("/healthchecks/proxmox/system/%d/toggle", id), url.Values{"back": {dockerPath}}); loc != dockerPath {
		t.Fatalf("toggle back: %q", loc)
	}
	body = dockerGetPage(t, srv, hp)
	if d := (*last).(dockerData); d.Sys == nil || d.Sys.Enabled || d.View.State != "off" || !strings.Contains(body, "docker-off") {
		t.Fatalf("off: %+v", d.Sys)
	}
	dockerPost(t, srv, fmt.Sprintf("/healthchecks/proxmox/system/%d/ascheck", id), url.Values{"key": {"docker/db"}, "on": {"1"}})
	if code, b := call(t, srv, "DELETE", fmt.Sprintf("/api/healthchecks/docker/systems/%d", id), nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", code, b)
	}
	if list, _ := m.dockerChecks(ctx); len(list) != 3 { // Gone, Remote und db (als Check); Web-Check wurde oben mit „Check entfernen“ geloescht
		t.Fatalf("docker checks after delete: %d", len(list))
	}
	body = dockerGetPage(t, srv, "/healthchecks/docker")
	if d := (*last).(dockerHostsData); len(d.Hosts) != 0 || !d.Socket || !strings.Contains(body, "/healthchecks/docker/enable") {
		t.Fatalf("after delete: %+v", d)
	}
	if list, _ := m.dockerSystems(ctx); len(list) != 0 {
		t.Fatal("recreated automatically")
	}
	dockerAddLocal(t, srv)
	if id2 := dockerSysID(t, m); id2 == id {
		t.Fatal("not recreated")
	}
}

// dockerPostGet: GET ohne Weiterleitung.
func dockerPostGet(t *testing.T, srv *httptest.Server, path string) (int, string) {
	t.Helper()
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

func TestDockerExportImport(t *testing.T) {
	fakeContainers(t, dockerHost, nil)
	fakeDockerSource(t)
	m, srv, _, _ := newDockerModuleRec(t, pveCore(t))
	dockerSeed(t, srv)
	dockerAddLocal(t, srv)
	id := dockerSysID(t, m)
	pvePollNow(t, m, id) // verknuepft Web-Check
	call(t, srv, "PUT", fmt.Sprintf("/api/healthchecks/docker/systems/%d/settings?key=docker/cache", id), map[string]any{"muted": true,
		"rules": map[string]any{"cpu": map[string]any{"percent": 70}}})
	data, err := m.Export(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(data)
	if !strings.Contains(string(raw), `"kind":"docker"`) {
		t.Fatalf("export: %s", raw)
	}
	// Ziel hat schon einen (automatisch eingerichteten) Docker-Host mit anderem Namen: wird uebernommen, nicht verdoppelt
	m2, _, _, _ := newDockerModuleRec(t, pveCore(t))
	pre := &proxmox.System{Kind: proxmox.KindDocker, Name: "Host", Enabled: true}
	if err := m2.pve.st.SaveSystem(context.Background(), pre); err != nil {
		t.Fatal(err)
	}
	if _, err := m2.Import(context.Background(), raw); err != nil {
		t.Fatalf("import: %v", err)
	}
	list, _ := m2.dockerSystems(context.Background())
	if len(list) != 1 || list[0].ID != pre.ID || list[0].Name != "Docker" || !list[0].Enabled {
		t.Fatalf("imported systems: %+v", list)
	}
	set, _ := m2.pve.st.Settings(context.Background(), pre.ID)
	if it := set.Item("docker/cache"); it == nil || !it.Muted || it.Rules.CPU == nil || it.Rules.CPU.Percent != 70 {
		t.Fatalf("imported settings: %+v", it)
	}
	it := set.Item("docker/web")
	if it == nil || !it.AsCheck {
		t.Fatalf("imported as check: %+v", it)
	}
	if c, _ := m2.st.Check(context.Background(), it.CheckToken); c == nil || c.Type != checks.TypeDocker {
		t.Fatalf("imported check: %+v", c)
	}
}
