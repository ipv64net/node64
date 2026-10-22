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
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/module"
)

// dockerView ergaenzt pveView um das, was die Healthchecks-Liste zusaetzlich braucht.
type dockerView struct{ pveView }

func (dockerView) Date(t time.Time) string { return t.Format("2006-01-02") }

// newDockerModule: Modul mit Render, das die Templates ausfuehrt und die Daten der letzten Seite merkt.
func newDockerModule(t *testing.T) (*httptest.Server, *any) {
	t.Helper()
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	core := pveCore(t)
	m := New(core, lg, nil, nil, "test")
	if err := core.Migrate(context.Background(), Name, m.Migrations()); err != nil {
		t.Fatal(err)
	}
	m.pve.noRun = true
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Stop(context.Background()) })
	last := new(any)
	funcs := template.FuncMap{"split": strings.Fields, "ms": func(f float64) string { return fmt.Sprint(f) }}
	render := func(w http.ResponseWriter, r *http.Request, status int, page, titleKey string, data any) {
		*last = data
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
		Flash:    func(http.ResponseWriter, *http.Request, string, string) {},
		Audit:    func(*http.Request, string, string, string) {}})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, last
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

func TestDockerPage(t *testing.T) {
	fakeContainers(t, dockerHost, nil)
	srv, last := newDockerModule(t)
	dockerSeed(t, srv)

	body := dockerGetPage(t, srv, "/healthchecks/docker")
	d := (*last).(dockerData)
	if !d.Socket || d.Total != 3 || d.Running != 2 || d.Bad != 3 || d.Missing != 1 || d.Watched != 3 || d.All != 5 || len(d.Rows) != 5 {
		t.Fatalf("kpi: socket=%v total=%d running=%d bad=%d missing=%d watched=%d all=%d rows=%d", d.Socket, d.Total, d.Running, d.Bad, d.Missing, d.Watched, d.All, len(d.Rows))
	}
	kinds := map[string]string{}
	for _, r := range d.Rows {
		k := r.Kind
		if r.Hc != nil {
			k += "+check"
		}
		kinds[r.Name] = k + "/" + r.Health
	}
	want := map[string]string{"web": "running+check/healthy", "db": "stopped/", "cache": "running/unhealthy", "gone": "missing+check/", "far": "remote+check/"}
	for n, k := range want {
		if kinds[n] != k {
			t.Errorf("%s: %q, want %q (%v)", n, kinds[n], k, kinds)
		}
	}
	for _, s := range []string{`data-container="web"`, "Web-Check", "8080-&gt;80/tcp", "hc.docker.kind.missing", "hc.docker.kind.remote",
		`/healthchecks/new?type=docker&target=db&name=db`, `name="back" value="docker"`, "hc.docker.socket_ok", "stat-value"} {
		if !strings.Contains(body, s) {
			t.Errorf("page lacks %q", s)
		}
	}
	if strings.Contains(body, "target=web&") || strings.Contains(body, "HTTP-Check") {
		t.Error("watched container offered again or non-docker check shown")
	}

	// Filter
	dockerGetPage(t, srv, "/healthchecks/docker?state=unwatched")
	if d := (*last).(dockerData); len(d.Rows) != 2 || d.Rows[0].Name != "cache" || d.Rows[1].Name != "db" {
		t.Fatalf("unwatched: %+v", d.Rows)
	}
	dockerGetPage(t, srv, "/healthchecks/docker?state=problem")
	if d := (*last).(dockerData); len(d.Rows) != 3 { // cache (unhealthy), db (gestoppt), gone (fehlt)
		t.Fatalf("problem: %d rows", len(d.Rows))
	}
	dockerGetPage(t, srv, "/healthchecks/docker?q=postgres")
	if d := (*last).(dockerData); len(d.Rows) != 1 || d.Rows[0].Name != "db" {
		t.Fatalf("search: %+v", d.Rows)
	}

	// API
	code, b := call(t, srv, "GET", "/api/healthchecks/docker/containers", nil)
	var out struct {
		Socket     bool         `json:"socket"`
		Containers []dockerJSON `json:"containers"`
	}
	if code != http.StatusOK || json.Unmarshal(b, &out) != nil || !out.Socket || len(out.Containers) != 5 {
		t.Fatalf("api: %d %s", code, b)
	}
	for _, c := range out.Containers {
		switch c.Name {
		case "web":
			if c.Check == nil || c.Check.Name != "Web-Check" || c.Image != "nginx:1" || len(c.Ports) != 1 || c.Created == nil {
				t.Errorf("api web: %+v", c)
			}
		case "db", "cache":
			if c.Check != nil {
				t.Errorf("api %s: unexpected check", c.Name)
			}
		case "gone":
			if c.Kind != "missing" || c.Check == nil {
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
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.PostForm(srv.URL+"/healthchecks/"+tok+"/action", url.Values{"action": {"pause"}, "back": {"docker"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != dockerPath {
		t.Fatalf("back: %d %q", resp.StatusCode, loc)
	}
}

func TestDockerPageNoSocket(t *testing.T) {
	fakeContainers(t, nil, errors.New("dial unix /var/run/docker.sock: connect: no such file or directory – mount the socket"))
	srv, last := newDockerModule(t)
	dockerSeed(t, srv)
	body := dockerGetPage(t, srv, "/healthchecks/docker")
	d := (*last).(dockerData)
	if d.Socket || d.SocketErr == "" || d.Total != 0 || len(d.Rows) != 3 || d.Missing != 0 {
		t.Fatalf("no socket: %+v", d)
	}
	for _, r := range d.Rows {
		if want := map[bool]string{true: "remote", false: "unknown"}[r.Name == "far"]; r.Kind != want {
			t.Errorf("%s: kind %s, want %s", r.Name, r.Kind, want)
		}
	}
	for _, s := range []string{"hc.docker.socket_missing", "/var/run/docker.sock:/var/run/docker.sock:ro", "mount the socket", "Web-Check"} {
		if !strings.Contains(body, s) {
			t.Errorf("page lacks %q", s)
		}
	}
	if strings.Contains(body, "hc.docker.watch") {
		t.Error("watch button without containers")
	}
}

func TestDockerPageEmpty(t *testing.T) {
	fakeContainers(t, nil, nil)
	srv, _ := newDockerModule(t)
	if body := dockerGetPage(t, srv, "/healthchecks/docker"); !strings.Contains(body, "hc.docker.empty") {
		t.Fatal("empty hint missing")
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
