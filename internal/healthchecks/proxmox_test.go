package healthchecks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/metrics"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/proxmox"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

// ---------------------------------------------------------------- nachgebautes Proxmox

const (
	pveTestToken  = "node64@pve!monitor"
	pveTestSecret = "0b1c2d3e-aaaa-bbbb-cccc-123456789abc"
)

type pveFake struct {
	mu        sync.Mutex
	down      bool // antwortet mit 500
	resources []map[string]any
	qmp       map[string]string // node/vmid -> qmpstatus
}

func newPVEFake() *pveFake {
	g := func(typ string, id int, node, name, status string, extra map[string]any) map[string]any {
		m := map[string]any{"id": fmt.Sprintf("%s/%d", typ, id), "type": typ, "vmid": id, "node": node, "name": name, "status": status,
			"cpu": 0.25, "maxcpu": 2, "mem": 1 << 30, "maxmem": 4 << 30, "disk": 0, "maxdisk": 32 << 30, "uptime": 5000,
			"netin": 1000, "netout": 2000, "diskread": 0, "diskwrite": 0}
		if typ == "lxc" {
			m["disk"] = 8 << 30
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	n := func(name string) map[string]any {
		return map[string]any{"id": "node/" + name, "type": "node", "node": name, "status": "online", "cpu": 0.1, "maxcpu": 8,
			"mem": 8 << 30, "maxmem": 32 << 30, "disk": 10 << 30, "maxdisk": 100 << 30, "uptime": 100000}
	}
	return &pveFake{
		resources: []map[string]any{n("pve1"), n("pve2"),
			g("qemu", 100, "pve1", "web", "running", map[string]any{"tags": "prod"}),
			g("qemu", 101, "pve2", "db", "running", nil),
			g("qemu", 102, "pve1", "app", "running", nil),
			g("lxc", 200, "pve2", "ct", "running", nil),
			g("qemu", 9000, "pve1", "tpl", "stopped", map[string]any{"template": 1}),
		},
		qmp: map[string]string{"pve1/100": "running", "pve2/101": "running", "pve1/102": "guest-panicked"},
	}
}

func (f *pveFake) set(key, field string, v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.resources {
		if r["id"] == key {
			r[field] = v
		}
	}
}

func (f *pveFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if f.down {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if r.Header.Get("Authorization") != "PVEAPIToken="+pveTestToken+"="+pveTestSecret {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/api2/json")
	var data any
	switch {
	case p == "/version":
		data = map[string]any{"version": "8.2.4", "release": "8.2"}
	case p == "/cluster/status":
		data = []map[string]any{{"type": "cluster", "name": "lab", "quorate": 1}, {"type": "node", "name": "pve1", "online": 1}, {"type": "node", "name": "pve2", "online": 1}}
	case p == "/cluster/resources":
		data = f.resources
	case strings.HasSuffix(p, "/status/current"):
		parts := strings.Split(p, "/")
		q, ok := f.qmp[parts[2]+"/"+parts[4]]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		data = map[string]any{"qmpstatus": q}
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func startPVEFake(t *testing.T, f *pveFake) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(f)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func pvePinOf(srv *httptest.Server) string { return proxmox.CertFingerprint(srv.Certificate().Raw) }

// ---------------------------------------------------------------- Modul mit Proxmox

type pveRec struct {
	mu     sync.Mutex
	alerts []notify.Alert
	audit  []string
}

func (r *pveRec) add(a notify.Alert) {
	r.mu.Lock()
	r.alerts = append(r.alerts, a)
	r.mu.Unlock()
}

func (r *pveRec) take() []notify.Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.alerts
	r.alerts = nil
	return out
}

// pveView bildet die Methoden der Oberflaeche nach, die die Proxmox-Templates nutzen.
type pveView struct {
	Data    any
	CSRF    string
	Version string
}

func (pveView) T(key string, args ...any) string {
	if len(args) == 0 {
		return key
	}
	return key + fmt.Sprint(args...)
}
func (pveView) Doc(string) template.HTML             { return "" }
func (pveView) Time(t time.Time) string              { return t.Format(time.RFC3339) }
func (pveView) Ago(t time.Time) string               { return "ago:" + t.Format(time.RFC3339) }
func (pveView) Duration(d time.Duration) string      { return d.String() }
func (pveView) Bytes(n int64) string                 { return fmt.Sprintf("%dB", n) }
func (pveView) Float(f float64, decimals int) string { return fmt.Sprint(f) }

var pveFuncs = template.FuncMap{"add": func(a, b int) int { return a + b }, "split": strings.Fields, "join": strings.Join, "contains": strings.Contains}

// pveRender fuehrt eine Seite des Moduls mit pveView aus (Fehler im Template brechen den Test ab).
func pveRender(t *testing.T) func(w http.ResponseWriter, r *http.Request, status int, page, titleKey string, data any) {
	return func(w http.ResponseWriter, r *http.Request, status int, page, titleKey string, data any) {
		name := strings.TrimPrefix(page, Name+"/")
		tpl := template.Must(template.New("root").Funcs(pveFuncs).Parse(`{{template "content" .}}{{block "scripts" .}}{{end}}`))
		if _, err := tpl.ParseFS(templateFS, "templates/pages/"+name+".html"); err != nil {
			t.Errorf("%s: %v", name, err)
			http.Error(w, err.Error(), 500)
			return
		}
		var buf bytes.Buffer
		if err := tpl.Execute(&buf, pveView{Data: data, CSRF: "csrf", Version: "v"}); err != nil {
			t.Errorf("%s: %v", name, err)
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write(buf.Bytes())
	}
}

func pveBox(t *testing.T, b byte) *secrets.Box {
	t.Helper()
	box, err := secrets.New(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

func newPVEModule(t *testing.T, core *store.Store, box *secrets.Box) (*Module, *httptest.Server, *pveRec) {
	t.Helper()
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := New(core, lg, nil, nil, "test")
	if err := core.Migrate(context.Background(), Name, m.Migrations()); err != nil {
		t.Fatal(err)
	}
	m.SetSecrets(box)
	rec := &pveRec{}
	m.pve.noRun, m.pve.alert = true, rec.add
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Stop(context.Background()) })
	mux := http.NewServeMux()
	pass := func(h http.Handler) http.Handler { return h }
	m.Routes(mux, module.Guards{Enabled: pass, Auth: pass, Render: pveRender(t),
		T:     func(r *http.Request, key string, args ...any) string { return key },
		Actor: func(*http.Request) string { return "test" },
		Flash: func(w http.ResponseWriter, r *http.Request, kind, text string) {
			w.Header().Add("X-Flash", kind+":"+text)
		},
		Audit: func(r *http.Request, action, target, details string) {
			rec.mu.Lock()
			rec.audit = append(rec.audit, action+" "+target)
			rec.mu.Unlock()
		}})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return m, srv, rec
}

func pveCore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(context.Background(), filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), lg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	cm, _ := store.CoreMigrations()
	if err := core.Migrate(context.Background(), "core", cm); err != nil {
		t.Fatal(err)
	}
	return core
}

// pveCreate legt das System ueber die API an und liefert seine ID.
func pveCreate(t *testing.T, srv *httptest.Server, fake *httptest.Server) int64 {
	t.Helper()
	code, b := call(t, srv, "POST", "/api/healthchecks/proxmox/systems", map[string]any{"name": "lab", "addresses": []string{fake.URL},
		"token_id": pveTestToken, "secret": pveTestSecret, "pin_sha256": pvePinOf(fake), "interval": 30})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, b)
	}
	if strings.Contains(string(b), pveTestSecret) {
		t.Fatal("secret in API output")
	}
	var out struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(b, &out)
	return out.ID
}

func pvePollNow(t *testing.T, m *Module, id int64) *proxmox.Snapshot {
	t.Helper()
	pp, reason := m.pvePollOf(id)
	if pp == nil {
		t.Fatalf("system %d not polled: %s", id, reason)
	}
	return pp.p.Poll(context.Background())
}

func pveKinds(list []notify.Alert) string {
	var s []string
	for _, a := range list {
		s = append(s, string(a.Kind)+":"+a.Check.Target+":"+a.Data["what"])
	}
	return strings.Join(s, " ")
}

// ---------------------------------------------------------------- Laufzeit und Benachrichtigung

func TestPVERuntimeNotifyRestartAsCheck(t *testing.T) {
	fake := newPVEFake()
	fsrv := startPVEFake(t, fake)
	core := pveCore(t)
	box := pveBox(t, 1)
	m, srv, rec := newPVEModule(t, core, box)
	id := pveCreate(t, srv, fsrv)

	// erste Abfrage: Absturz (qmpstatus guest-panicked) wird sofort gemeldet, hohe Prioritaet (kritisch), Detail
	s := pvePollNow(t, m, id)
	if !s.OK || len(s.Resources) != 7 {
		t.Fatalf("snapshot: %+v", s)
	}
	al := rec.take()
	if len(al) != 1 || al[0].Kind != notify.KindProxmoxDown || al[0].Data["what"] != "crashed" || al[0].Data["detail"] != "guest-panicked" ||
		al[0].Check.Critical || al[0].Check.Name != "lab – app" || al[0].Data["type"] != "qemu" || !al[0].Check.Local ||
		al[0].Data["path"] != "/healthchecks/proxmox/system/"+fmt.Sprint(id)+"/res/qemu/102" {
		t.Fatalf("crash alert: %+v", al)
	}
	if raw := core.SettingOr(context.Background(), pveSettingEngine+fmt.Sprint(id), ""); !strings.Contains(raw, "qemu/102") {
		t.Fatalf("engine state not persisted: %q", raw)
	}
	if m.pveLastIncident(context.Background()) == nil {
		t.Fatal("last incident")
	}
	// Verlauf geschrieben, Gaeste als „lief“ gemerkt
	var n int
	_ = core.Reader().QueryRow(`SELECT count(*) FROM pve_hist_1m WHERE system_id = ?`, id).Scan(&n)
	if n == 0 {
		t.Fatal("no history")
	}

	// gestoppt: nach der Verzoegerung (2 Abfragen)
	fake.set("qemu/101", "status", "stopped")
	pvePollNow(t, m, id)
	if al := rec.take(); len(al) != 0 {
		t.Fatalf("stopped too early: %s", pveKinds(al))
	}
	pvePollNow(t, m, id)
	if al := rec.take(); len(al) != 1 || al[0].Kind != notify.KindProxmoxDown || al[0].Data["what"] != "stopped" || al[0].Check.Critical {
		t.Fatalf("stopped: %s", pveKinds(al))
	}

	// Neustart der Node: offene Stoerungen werden nicht erneut gemeldet, nur die Entwarnung kommt
	if err := m.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	pvePollNow(t, m, id)
	pvePollNow(t, m, id)
	if al := rec.take(); len(al) != 0 {
		t.Fatalf("after restart: reported again: %s", pveKinds(al))
	}
	fake.set("qemu/101", "status", "running")
	pvePollNow(t, m, id)
	if al := rec.take(); len(al) != 1 || al[0].Kind != notify.KindProxmoxUp || al[0].Check.Target != "qemu/101" || al[0].Duration <= 0 {
		t.Fatalf("up after restart: %s %+v", pveKinds(al), al)
	}

	// „als Check“: Check vom Typ proxmox, Zustand kommt dann nur ueber den Check (keine doppelte Meldung)
	code, b := call(t, srv, "PUT", "/api/healthchecks/proxmox/systems/"+fmt.Sprint(id)+"/settings?key=qemu/101", map[string]any{"as_check": true})
	if code != 200 {
		t.Fatalf("as_check: %d %s", code, b)
	}
	set, _ := m.pve.st.Settings(context.Background(), id)
	it := set.Item("qemu/101")
	if it == nil || !it.AsCheck || it.CheckToken == "" {
		t.Fatalf("settings: %+v", it)
	}
	c, _ := m.st.Check(context.Background(), it.CheckToken)
	if c == nil || c.Type != checks.TypeProxmox || c.Name != "lab – db" || c.Target != "qemu/101" || c.Interval != 30*time.Second || c.Group != pveCheckGroup || c.Execution != "local" {
		t.Fatalf("check: %+v", c)
	}
	fake.set("qemu/101", "status", "stopped")
	pvePollNow(t, m, id)
	pvePollNow(t, m, id)
	pvePollNow(t, m, id)
	if al := rec.take(); len(al) != 0 {
		t.Fatalf("as check: state reported by proxmox too: %s", pveKinds(al))
	}
	// der Check sieht den Zustand aus dem letzten Snapshot
	runner := checks.NewRunner()
	runner.Proxmox = m.pveLookup
	res := runner.Run(context.Background(), c.Definition())
	if len(res) != 1 || res[0].Status != checks.Down || res[0].Reason != checks.ReasonPVEStopped {
		t.Fatalf("check result: %+v", res)
	}
	fake.set("qemu/101", "status", "running")
	pvePollNow(t, m, id)
	if res := runner.Run(context.Background(), c.Definition()); res[0].Status != checks.Up {
		t.Fatalf("check up: %+v", res)
	} else if res[0].Latency <= 0 || res[0].Details["latency_source"] != "api" { // ohne Gast-Adresse: Antwortzeit der API
		t.Fatalf("check latency: %v %v", res[0].Latency, res[0].Details)
	}
	if al := rec.take(); len(al) != 0 {
		t.Fatalf("as check: up reported by proxmox: %s", pveKinds(al))
	}
	// Check in der Liste geloescht: Gast wird wieder normal ueberwacht
	if err := m.st.Delete(context.Background(), c.Token); err != nil {
		t.Fatal(err)
	}
	pvePollNow(t, m, id)
	set, _ = m.pve.st.Settings(context.Background(), id)
	if it := set.Item("qemu/101"); it.AsCheck || it.CheckToken != "" {
		t.Fatalf("stale as_check: %+v", it)
	}

	// System nicht erreichbar: nach der Verzoegerung eine Meldung; der Check eines Gasts meldet pve_unreachable
	code, _ = call(t, srv, "PUT", "/api/healthchecks/proxmox/systems/"+fmt.Sprint(id)+"/settings?key=lxc/200", map[string]any{"as_check": true})
	if code != 200 {
		t.Fatal("as_check lxc")
	}
	set, _ = m.pve.st.Settings(context.Background(), id)
	c2, _ := m.st.Check(context.Background(), set.Item("lxc/200").CheckToken)
	fake.mu.Lock()
	fake.down = true
	fake.mu.Unlock()
	pvePollNow(t, m, id)
	pvePollNow(t, m, id)
	al = rec.take()
	if len(al) != 1 || al[0].Kind != notify.KindProxmoxDown || al[0].Data["what"] != "unreachable" || al[0].Check.Name != "lab" || al[0].Data["type"] != "" {
		t.Fatalf("unreachable: %s", pveKinds(al))
	}
	if res := runner.Run(context.Background(), c2.Definition()); res[0].Status != checks.Down || res[0].Reason != checks.ReasonPVEUnreachable {
		t.Fatalf("check unreachable: %+v", res)
	}

	// Abschalten: Abfrage endet, Checks pausiert, Stand der Regeln verworfen
	code, b = call(t, srv, "PUT", "/api/healthchecks/proxmox/systems/"+fmt.Sprint(id), map[string]any{"enabled": false})
	if code != 200 {
		t.Fatalf("disable: %d %s", code, b)
	}
	if pp, _ := m.pvePollOf(id); pp != nil {
		t.Fatal("still polled")
	}
	if c2, _ = m.st.Check(context.Background(), c2.Token); !c2.Paused {
		t.Fatal("check not paused")
	}
	if raw := core.SettingOr(context.Background(), pveSettingEngine+fmt.Sprint(id), ""); raw != "" {
		t.Fatalf("engine state kept: %s", raw)
	}
	if st := m.pveLookup(id, "lxc/200"); st.Polling || !strings.Contains(st.Error, "switched off") {
		t.Fatalf("lookup off: %+v", st)
	}
	// Einschalten: Checks laufen wieder
	code, _ = call(t, srv, "PUT", "/api/healthchecks/proxmox/systems/"+fmt.Sprint(id), map[string]any{"enabled": true})
	if c2, _ = m.st.Check(context.Background(), c2.Token); code != 200 || c2.Paused {
		t.Fatal("check not resumed")
	}
	// Loeschen: Checks und Einstellungen weg
	code, _ = call(t, srv, "DELETE", "/api/healthchecks/proxmox/systems/"+fmt.Sprint(id), nil)
	if code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if c2, _ = m.st.Check(context.Background(), c2.Token); c2 != nil {
		t.Fatal("check kept after delete")
	}
	if code, _ := call(t, srv, "GET", "/api/healthchecks/proxmox/systems/"+fmt.Sprint(id), nil); code != 404 {
		t.Fatalf("get deleted: %d", code)
	}
}

// Fehlt der Schluessel (anderer secret.key), zeigt das System einen Fehler statt still mit 401 abzufragen.
func TestPVESecretKeyMissing(t *testing.T) {
	fake := newPVEFake()
	fsrv := startPVEFake(t, fake)
	core := pveCore(t)
	m, srv, _ := newPVEModule(t, core, pveBox(t, 1))
	id := pveCreate(t, srv, fsrv)
	_ = m.Stop(context.Background())

	m2, srv2, _ := newPVEModule(t, core, pveBox(t, 2))
	if pp, reason := m2.pvePollOf(id); pp != nil || !strings.Contains(reason, "cannot be decrypted") {
		t.Fatalf("poll with wrong key: %v %q", pp, reason)
	}
	code, b := call(t, srv2, "GET", "/api/healthchecks/proxmox/systems/"+fmt.Sprint(id), nil)
	if code != 200 || !strings.Contains(string(b), `"state":"error"`) || !strings.Contains(string(b), "cannot be decrypted") || !strings.Contains(string(b), `"has_secret":false`) {
		t.Fatalf("api: %d %s", code, b)
	}
	if st := m2.pveLookup(id, "qemu/100"); st.Polling || !strings.Contains(st.Error, "decrypted") {
		t.Fatalf("lookup: %+v", st)
	}
	// Seite zeigt den Fehler
	resp, err := http.Get(srv2.URL + "/healthchecks/proxmox/system/" + fmt.Sprint(id))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "cannot be decrypted") || !strings.Contains(string(body), "pve.sys_state.error") {
		t.Fatalf("page: %s", body)
	}
	// Secret neu eintragen: Abfrage laeuft wieder
	code, b = call(t, srv2, "PUT", "/api/healthchecks/proxmox/systems/"+fmt.Sprint(id), map[string]any{"secret": pveTestSecret})
	if code != 200 {
		t.Fatalf("put secret: %d %s", code, b)
	}
	if s := pvePollNow(t, m2, id); !s.OK {
		t.Fatalf("poll after new secret: %+v", s)
	}
}

// ---------------------------------------------------------------- API

func TestPVEAPI(t *testing.T) {
	fake := newPVEFake()
	fsrv := startPVEFake(t, fake)
	core := pveCore(t)
	m, srv, rec := newPVEModule(t, core, pveBox(t, 1))
	base := "/api/healthchecks/proxmox"

	// Validierung
	for _, body := range []map[string]any{
		{"addresses": []string{"http://x"}, "token_id": pveTestToken, "secret": "s"},
		{"addresses": []string{fsrv.URL}, "token_id": "nobang", "secret": "s"},
		{"addresses": []string{fsrv.URL}, "token_id": pveTestToken},
		{"addresses": []string{fsrv.URL}, "token_id": pveTestToken, "secret": "s", "interval": 5},
		{"addresses": []string{fsrv.URL}, "token_id": pveTestToken, "secret": "s", "pin_sha256": "zz"},
	} {
		if code, b := call(t, srv, "POST", base+"/systems", body); code != 422 || !strings.Contains(string(b), `"key":"pve.err.`) {
			t.Fatalf("validation %v: %d %s", body, code, b)
		}
	}
	// Verbindung testen: selbstsigniert ohne Pin nur der Fingerabdruck (Token nicht gesendet), dann mit Pin:
	// Version, Cluster, Nodes, Gaeste (ohne Vorlage)
	code, b := call(t, srv, "POST", base+"/probe", map[string]any{"addresses": []string{fsrv.URL}, "token_id": pveTestToken, "secret": pveTestSecret})
	var pr proxmox.ProbeResult
	_ = json.Unmarshal(b, &pr)
	if code != 200 || pr.OK || !pr.NeedConfirm || pr.CertSHA256 != pvePinOf(fsrv) || pr.CertTrusted || pr.Version != "" {
		t.Fatalf("probe unconfirmed: %d %s", code, b)
	}
	code, b = call(t, srv, "POST", base+"/probe", map[string]any{"addresses": []string{fsrv.URL}, "token_id": pveTestToken, "secret": pveTestSecret,
		"pin_sha256": pr.CertSHA256})
	pr = proxmox.ProbeResult{}
	_ = json.Unmarshal(b, &pr)
	if code != 200 || !pr.OK || pr.NeedConfirm || pr.CertSHA256 != pvePinOf(fsrv) || pr.Version != "8.2.4" || pr.Cluster != "lab" || len(pr.Nodes) != 2 || pr.Guests != 4 {
		t.Fatalf("probe: %d %s", code, b)
	}
	code, b = call(t, srv, "POST", base+"/probe", map[string]any{"addresses": []string{fsrv.URL}, "token_id": pveTestToken, "secret": "wrong",
		"pin_sha256": pvePinOf(fsrv)})
	if _ = json.Unmarshal(b, &pr); code != 200 || pr.OK || !strings.Contains(pr.Error, "token") {
		t.Fatalf("probe wrong secret: %s", b)
	}

	id := pveCreate(t, srv, fsrv)
	// gespeichertes Secret nur fuer dieselben Adressen und denselben Pin
	if code, b := call(t, srv, "POST", base+"/probe", map[string]any{"system_id": id}); code != 200 || !strings.Contains(string(b), `"ok":true`) {
		t.Fatalf("probe stored: %d %s", code, b)
	}
	for _, body := range []map[string]any{{"system_id": id, "addresses": []string{"https://evil.example:8006"}}, {"system_id": id, "pin_sha256": ""}} {
		if code, b := call(t, srv, "POST", base+"/probe", body); code != 422 || !strings.Contains(string(b), "pve.err.secret_reenter") {
			t.Fatalf("probe changed target with stored secret %v: %d %s", body, code, b)
		}
	}
	pvePollNow(t, m, id)
	code, b = call(t, srv, "GET", base+"/systems", nil)
	if code != 200 || !strings.Contains(string(b), `"state":"warn"`) || !strings.Contains(string(b), `"guests_bad":1`) || !strings.Contains(string(b), `"cluster":"lab"`) ||
		strings.Contains(string(b), pveTestSecret) || !strings.Contains(string(b), `"has_secret":true`) {
		t.Fatalf("list: %d %s", code, b)
	}
	code, b = call(t, srv, "GET", base+"/systems/"+fmt.Sprint(id)+"/resources", nil)
	if code != 200 || !strings.Contains(string(b), `"key":"qemu/102"`) || !strings.Contains(string(b), `"state":"error"`) || !strings.Contains(string(b), `"excluded":true`) {
		t.Fatalf("resources: %d %s", code, b)
	}
	code, b = call(t, srv, "GET", base+"/systems/"+fmt.Sprint(id)+"/series?key=qemu/100&range=1h", nil)
	if code != 200 || !strings.Contains(string(b), `"step_seconds":60`) || !strings.Contains(string(b), `"cpu":25`) {
		t.Fatalf("series: %d %s", code, b)
	}
	if code, _ := call(t, srv, "GET", base+"/systems/"+fmt.Sprint(id)+"/series?key=bad", nil); code != 400 {
		t.Fatalf("series bad key: %d", code)
	}
	// Regeln: Node-Ebene vererbt an den Gast; Ungueltiges 422
	code, b = call(t, srv, "PUT", base+"/systems/"+fmt.Sprint(id)+"/settings?key=node/pve1", map[string]any{"rules": map[string]any{"cpu": map[string]any{"percent": 50, "minutes": 1}}})
	if code != 200 || !strings.Contains(string(b), `"percent":50`) {
		t.Fatalf("node rules: %d %s", code, b)
	}
	code, b = call(t, srv, "GET", base+"/systems/"+fmt.Sprint(id)+"/settings", nil)
	var sv struct {
		Effective map[string]proxmox.Rule `json:"effective"`
	}
	_ = json.Unmarshal(b, &sv)
	if code != 200 || sv.Effective["qemu/100"].CPU.Percent != 50 || sv.Effective["qemu/101"].CPU.Percent != 90 {
		t.Fatalf("effective: %d %s", code, b)
	}
	if code, b := call(t, srv, "PUT", base+"/systems/"+fmt.Sprint(id)+"/settings?key=qemu/100", map[string]any{"rules": map[string]any{"delay": 0}}); code != 422 {
		t.Fatalf("invalid delay: %d %s", code, b)
	}
	code, _ = call(t, srv, "PUT", base+"/systems/"+fmt.Sprint(id)+"/settings?key=qemu/100", map[string]any{"expect_running": false, "muted": true})
	set, _ := m.pve.st.Settings(context.Background(), id)
	if it := set.Item("qemu/100"); code != 200 || it == nil || !it.Muted || it.ExpectRunning == nil || *it.ExpectRunning {
		t.Fatalf("expect: %d %+v", code, it)
	}
	// PUT ohne expect_running laesst es stehen
	call(t, srv, "PUT", base+"/systems/"+fmt.Sprint(id)+"/settings?key=qemu/100", map[string]any{"muted": false})
	set, _ = m.pve.st.Settings(context.Background(), id)
	if it := set.Item("qemu/100"); it.ExpectRunning == nil || it.Muted {
		t.Fatalf("partial put: %+v", it)
	}
	if code, _ := call(t, srv, "DELETE", base+"/systems/"+fmt.Sprint(id)+"/settings?key=node/pve1", nil); code != 204 {
		t.Fatal("reset")
	}
	set, _ = m.pve.st.Settings(context.Background(), id)
	if it := set.Item("node/pve1"); it != nil && it.Rules.CPU != nil {
		t.Fatalf("reset kept rules: %+v", it)
	}
	// Aendern ohne Secret behaelt es
	code, b = call(t, srv, "PUT", base+"/systems/"+fmt.Sprint(id), map[string]any{"name": "lab2", "interval": 60})
	if sys, _ := m.pve.st.System(context.Background(), id); code != 200 || sys.Secret != pveTestSecret || sys.Name != "lab2" || sys.Interval != 60 {
		t.Fatalf("update: %d %s", code, b)
	}
	if code, _ := call(t, srv, "GET", base+"/systems/999", nil); code != 404 {
		t.Fatal("404")
	}
	rec.mu.Lock()
	audit := strings.Join(rec.audit, "|")
	rec.mu.Unlock()
	for _, a := range []string{"proxmox.create lab", "proxmox.probe", "proxmox.settings lab / node/pve1", "proxmox.update lab2", "proxmox.settings_reset"} {
		if !strings.Contains(audit, a) {
			t.Fatalf("audit %q missing: %s", a, audit)
		}
	}
}

// ---------------------------------------------------------------- Seiten und Assistent

func pveGet(t *testing.T, srv *httptest.Server, path string) (int, string) {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func pvePost(t *testing.T, srv *httptest.Server, path string, form url.Values) (*http.Response, string) {
	t.Helper()
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.PostForm(srv.URL+path, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestPVEPagesAndWizard(t *testing.T) {
	fake := newPVEFake()
	fsrv := startPVEFake(t, fake)
	core := pveCore(t)
	m, srv, _ := newPVEModule(t, core, pveBox(t, 1))

	// ohne Systeme
	if code, body := pveGet(t, srv, "/healthchecks/proxmox"); code != 200 || !strings.Contains(body, "pve.empty") || !strings.Contains(body, "/healthchecks/proxmox/new") {
		t.Fatalf("empty overview: %d %s", code, body)
	}
	if code, body := pveGet(t, srv, "/healthchecks/proxmox/new"); code != 200 || !strings.Contains(body, "pveum aclmod / -user node64@pve -role PVEAuditor") ||
		!strings.Contains(body, "pveum user token add node64@pve monitor --privsep 0") {
		t.Fatalf("wizard: %d %s", code, body)
	}
	if g := m.BoardGroups(context.Background()); len(g) != 0 {
		t.Fatal("dashboard tiles without systems")
	}

	// Assistent: Verbindung testen zeigt erst nur den Fingerabdruck (Token nicht gesendet); Speichern ohne
	// Bestaetigung geht nicht (selbstsigniert)
	form := url.Values{"addresses": {fsrv.URL}, "token_id": {pveTestToken}, "secret": {pveTestSecret}, "interval": {"30"}, "enabled": {"on"}, "op": {"probe"}}
	resp, body := pvePost(t, srv, "/healthchecks/proxmox/new", form)
	if resp.StatusCode != 200 || !strings.Contains(body, pveFingerprint(pvePinOf(fsrv))) || !strings.Contains(body, `name="probe_pin" value="`+pvePinOf(fsrv)) ||
		!strings.Contains(body, "pve.form.cert_untrusted") || !strings.Contains(body, "pve.form.probe_confirm_first") || strings.Contains(body, `value="lab"`) ||
		strings.Contains(body, "probe_trusted") {
		t.Fatalf("probe page: %d %s", resp.StatusCode, body)
	}
	form.Set("op", "save")
	form.Set("probe_pin", pvePinOf(fsrv))
	form.Set("name", "lab")
	resp, body = pvePost(t, srv, "/healthchecks/proxmox/new", form)
	if resp.StatusCode != 422 || !strings.Contains(body, "pve.err.pin_confirm") {
		t.Fatalf("save without confirm: %d %s", resp.StatusCode, body)
	}
	// bestaetigt und erneut getestet: jetzt mit Token (Name vorgeschlagen), Bestaetigung bleibt
	form.Set("pin_confirm", "on")
	form.Set("op", "probe")
	form.Del("name")
	resp, body = pvePost(t, srv, "/healthchecks/proxmox/new", form)
	if resp.StatusCode != 200 || !strings.Contains(body, "8.2.4") || !strings.Contains(body, `value="lab"`) || !strings.Contains(body, `name="pin_confirm" checked`) ||
		strings.Contains(body, "pve.form.probe_confirm_first") {
		t.Fatalf("confirmed probe: %d %s", resp.StatusCode, body)
	}
	form.Set("op", "save")
	form.Set("name", "lab")
	resp, _ = pvePost(t, srv, "/healthchecks/proxmox/new", form)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/healthchecks/proxmox/system/") {
		t.Fatalf("save: %d %v", resp.StatusCode, resp.Header)
	}
	list, _ := m.pve.st.Systems(context.Background())
	if len(list) != 1 || list[0].PinSHA256 != pvePinOf(fsrv) || list[0].Secret != pveTestSecret || list[0].Name != "lab" {
		t.Fatalf("saved: %+v", list)
	}
	id := list[0].ID
	sp := fmt.Sprintf("/healthchecks/proxmox/system/%d", id)

	// vor der ersten Abfrage: wartet
	if code, body := pveGet(t, srv, sp); code != 200 || !strings.Contains(body, "pve.pending") {
		t.Fatalf("pending: %d %s", code, body)
	}
	pvePollNow(t, m, id)
	pvePollNow(t, m, id) // zweite Abfrage: Raten und Verlauf
	// ein frueherer Wert, damit die Linie der letzten Stunde zwei Punkte hat
	if _, err := core.Writer().Exec(`INSERT INTO pve_hist_1m (system_id, key, t, n, cpu, cpu_max, mem, disk, net_in, net_out, disk_read, disk_write)
		VALUES (?, 'qemu/100', ?, 1, 5000, 5000, 1000, NULL, 0, 0, 0, 0)`, id, time.Now().Add(-20*time.Minute).Unix()/60*60); err != nil {
		t.Fatal(err)
	}
	code, body := pveGet(t, srv, "/healthchecks/proxmox")
	if code != 200 || !strings.Contains(body, `href="`+sp+`"`) || !strings.Contains(body, "pve.sys_state.warn") || !strings.Contains(body, "8.2.4") || !strings.Contains(body, "pve.quorum_ok") {
		t.Fatalf("overview: %s", body)
	}
	if strings.Contains(body, "bi-arrow-up-circle") { // neueste Version unbekannt: kein Hinweis
		t.Fatalf("update badge without known version: %s", body)
	}
	latestSet(t, "pve/8", "8.4.14") // neuere Version in der eigenen Linie: nur das kleine Badge
	if _, body := pveGet(t, srv, "/healthchecks/proxmox"); !strings.Contains(body, "bi-arrow-up-circle") || !strings.Contains(body, "8.4.14") || !strings.Contains(body, "pve.update_hint") {
		t.Fatalf("update badge: %s", body)
	}
	for _, want := range []string{`id="pve-kpi"`, "pve.kpi.nodes", "pve.kpi.load", "CPU "} { // Kacheln ueber alle Systeme
		if !strings.Contains(body, want) {
			t.Fatalf("overview kpi: %q missing", want)
		}
	}
	code, body = pveGet(t, srv, sp)
	for _, want := range []string{`id="pve-sys-kpi"`, "pve.kpi.nodes", "pve.kpi.load", "?state=problem", "pve1", "web", "app", "guest-panicked", "pve.state.error", "pve.template", `name="key" value="qemu/100"`, "pve-spark", "pve.rules.level_system",
		`name="r_unreachable"`, "pve.rules.from_default"} {
		if !strings.Contains(body, want) {
			t.Fatalf("system page: %q missing: %s", want, body)
		}
	}
	if strings.Contains(body, "[{") || strings.Contains(body, "&lt;nil&gt;") { // Kachel „Gaeste“ zeigte die Liste statt der Zahl
		t.Fatalf("system kpi shows a raw value: %s", body)
	}
	// Filter: nur gestoerte, Typ LXC, Suche
	if _, body = pveGet(t, srv, sp+"?state=problem"); !strings.Contains(body, ">app<") || strings.Contains(body, ">web<") {
		t.Fatalf("filter problem: %s", body)
	}
	if _, body = pveGet(t, srv, sp+"?type=lxc"); !strings.Contains(body, ">ct<") || strings.Contains(body, ">db<") {
		t.Fatalf("filter type: %s", body)
	}
	if _, body = pveGet(t, srv, sp+"?q=prod"); !strings.Contains(body, ">web<") || strings.Contains(body, ">db<") {
		t.Fatalf("filter search: %s", body)
	}
	if _, body = pveGet(t, srv, sp+"?state=running&node=pve2"); !strings.Contains(body, ">db<") || strings.Contains(body, ">web<") {
		t.Fatalf("filter node: %s", body)
	}

	// Regeln je Node speichern, Gast zeigt „vom Node geerbt“
	resp, _ = pvePost(t, srv, sp+"/settings", url.Values{"key": {"node/pve1"}, "r_cpu": {"70"}, "r_cpu_min": {"5"}, "r_offline": {"0"}, "op": {"save"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != sp+"/res/node/pve1" {
		t.Fatalf("node rules: %d %v", resp.StatusCode, resp.Header)
	}
	code, body = pveGet(t, srv, sp+"/res/qemu/100")
	if code != 200 || !strings.Contains(body, "pve.rules.from_node") || !strings.Contains(body, "70 % · 5 min") || !strings.Contains(body, "pve-chart-cpu") ||
		!strings.Contains(body, "proxmox.js") || !strings.Contains(body, "pve.rules.level_guest") || !strings.Contains(body, `name="expect"`) || strings.Contains(body, `name="r_unreachable"`) {
		t.Fatalf("guest page: %s", body)
	}
	if code, body = pveGet(t, srv, sp+"/res/node/pve1"); code != 200 || !strings.Contains(body, `name="r_cpu" value="70"`) || !strings.Contains(body, `name="r_offline"`) {
		t.Fatalf("node page: %s", body)
	}
	resp, _ = pvePost(t, srv, sp+"/settings", url.Values{"key": {"qemu/100"}, "r_delay": {"0"}})
	if !strings.Contains(resp.Header.Get("X-Flash"), "danger:pve.err.delay") {
		t.Fatalf("invalid rule: %v", resp.Header)
	}
	resp, _ = pvePost(t, srv, sp+"/settings", url.Values{"key": {"node/pve1"}, "op": {"reset"}})
	set, _ := m.pve.st.Settings(context.Background(), id)
	if it := set.Item("node/pve1"); resp.StatusCode != 303 || it.Rules.CPU != nil {
		t.Fatalf("reset: %+v", it)
	}
	// unbekannter Gast: Seite mit Hinweis
	if code, body = pveGet(t, srv, sp+"/res/qemu/555"); code != 200 || !strings.Contains(body, "pve.res_missing") {
		t.Fatalf("missing guest: %d %s", code, body)
	}
	if code, _ := pveGet(t, srv, sp+"/res/foo/bar"); code != 404 {
		t.Fatalf("bad key: %d", code)
	}

	// „als Check“ per Schalter
	resp, _ = pvePost(t, srv, sp+"/ascheck", url.Values{"key": {"lxc/200"}, "on": {"1"}, "back": {sp}})
	set, _ = m.pve.st.Settings(context.Background(), id)
	if it := set.Item("lxc/200"); resp.StatusCode != 303 || it == nil || !it.AsCheck {
		t.Fatalf("as check on: %+v", it)
	}
	_, body = pveGet(t, srv, sp)
	if !strings.Contains(body, "/healthchecks/"+set.Item("lxc/200").CheckToken) {
		t.Fatal("check link missing")
	}
	// Formular des Checks: Typ proxmox bleibt mit seinen Parametern bearbeitbar
	tok := set.Item("lxc/200").CheckToken
	c, _ := m.st.Check(context.Background(), tok)
	f := formFromCheck(c)
	if f["type"] != "proxmox" || !strings.Contains(f["pve_params"], `"key":"lxc/200"`) {
		t.Fatalf("form: %v", f)
	}
	resp, _ = pvePost(t, srv, sp+"/ascheck", url.Values{"key": {"lxc/200"}, "on": {"0"}})
	if c, _ := m.st.Check(context.Background(), tok); resp.StatusCode != 303 || c != nil {
		t.Fatal("as check off")
	}

	// Bearbeiten: Secret wird nie ausgegeben, Test mit gespeichertem Secret
	code, body = pveGet(t, srv, sp+"/edit")
	if code != 200 || strings.Contains(body, pveTestSecret) || !strings.Contains(body, "pve.form.secret_keep") {
		t.Fatalf("edit page: %s", body)
	}
	resp, body = pvePost(t, srv, sp+"/edit", url.Values{"addresses": {fsrv.URL}, "token_id": {pveTestToken}, "interval": {"30"}, "enabled": {"on"}, "name": {"lab"},
		"pin_sha256": {pveFingerprint(pvePinOf(fsrv))}, "op": {"probe"}})
	if resp.StatusCode != 200 || !strings.Contains(body, "pve.form.probe_result") || !strings.Contains(body, "8.2.4") || strings.Contains(body, "pve.form.pin_differs") ||
		strings.Contains(body, pveTestSecret) {
		t.Fatalf("edit probe: %d %s", resp.StatusCode, body)
	}
	// andere Adresse bzw. anderer Pin: gespeichertes Secret wird nicht benutzt
	resp, body = pvePost(t, srv, sp+"/edit", url.Values{"addresses": {fsrv.URL + "\nhttps://evil.example:8006"}, "token_id": {pveTestToken}, "interval": {"30"},
		"name": {"lab"}, "pin_sha256": {pveFingerprint(pvePinOf(fsrv))}, "op": {"probe"}})
	if resp.StatusCode != 422 || !strings.Contains(body, "pve.err.secret_reenter") || strings.Contains(body, "pve.form.probe_result") {
		t.Fatalf("edit probe other address: %d %s", resp.StatusCode, body)
	}
	// Kacheln auf dem Dashboard: nur ein Gast gestoert -> System ok, Gast gestoert (nicht doppelt)
	groups := m.BoardGroups(context.Background())
	if len(groups) != 1 || groups[0].Path != pvePath || len(groups[0].Tiles) != 4 || groups[0].Tiles[0].Value != 1 || groups[0].Tiles[1].Value != 0 ||
		groups[0].Tiles[3].Value != 1 {
		t.Fatalf("dashboard tiles: %+v", groups)
	}
	// Ausschalten und Loeschen ueber die Oberflaeche
	resp, _ = pvePost(t, srv, sp+"/toggle", url.Values{"back": {"/healthchecks/proxmox"}})
	if sys, _ := m.pve.st.System(context.Background(), id); resp.StatusCode != 303 || sys.Enabled || resp.Header.Get("Location") != "/healthchecks/proxmox" {
		t.Fatal("toggle")
	}
	if _, body = pveGet(t, srv, sp); !strings.Contains(body, "pve.off_hint") {
		t.Fatal("off page")
	}
	resp, _ = pvePost(t, srv, sp+"/delete", nil)
	if list, _ := m.pve.st.Systems(context.Background()); resp.StatusCode != 303 || len(list) != 0 {
		t.Fatal("delete")
	}
	if resp, _ := pvePost(t, srv, sp+"/delete", nil); resp.StatusCode != 303 || resp.Header.Get("Location") != pvePath {
		t.Fatal("delete unknown")
	}
}

// Ohne secret.key lassen sich keine Systeme speichern; die Seiten sagen das.
func TestPVENoBox(t *testing.T) {
	core := pveCore(t)
	m, srv, _ := newPVEModule(t, core, nil)
	if _, body := pveGet(t, srv, "/healthchecks/proxmox"); !strings.Contains(body, "pve.err.no_box") {
		t.Fatalf("overview: %s", body)
	}
	code, b := call(t, srv, "POST", "/api/healthchecks/proxmox/systems", map[string]any{"addresses": []string{"https://pve:8006"}, "token_id": pveTestToken, "secret": "x"})
	if code != 409 {
		t.Fatalf("create without box: %d %s", code, b)
	}
	_ = m
}

// ---------------------------------------------------------------- Metriken, Export/Import

func TestPVEMetricsAndExport(t *testing.T) {
	fake := newPVEFake()
	fsrv := startPVEFake(t, fake)
	core := pveCore(t)
	m, srv, _ := newPVEModule(t, core, pveBox(t, 1))
	id := pveCreate(t, srv, fsrv)
	pvePollNow(t, m, id)
	w := metrics.New()
	m.Metrics(context.Background(), w)
	var buf bytes.Buffer
	_, _ = w.WriteTo(&buf)
	out := buf.String()
	sl := fmt.Sprintf(`system="lab",system_id="%d"`, id)
	for _, want := range []string{`node64_pve_up{` + sl + `} 1`, `node64_pve_guest_state{` + sl + `,node="pve1",type="qemu",vmid="102",name="app",state="error"} 1`,
		`node64_pve_guest_cpu_ratio{` + sl + `,type="qemu",vmid="100"} 0.25`, `node64_pve_node_up{` + sl + `,node="pve2"} 1`, `node64_pve_poll_failures_total{` + sl + `} 0`,
		`node64_pve_guests_bad{` + sl + `} 1`, `node64_pve_quorate{` + sl + `} 1`, `node64_pve_node_memory_ratio{` + sl + `,node="pve1"} 0.25`} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics: %q missing:\n%s", want, out)
		}
	}
	if strings.Contains(out, `vmid="9000"`) {
		t.Fatal("template in metrics")
	}
	fake.mu.Lock()
	fake.down = true
	fake.mu.Unlock()
	pvePollNow(t, m, id)
	w = metrics.New()
	m.Metrics(context.Background(), w)
	buf.Reset()
	_, _ = w.WriteTo(&buf)
	if !strings.Contains(buf.String(), `node64_pve_up{`+sl+`} 0`) || !strings.Contains(buf.String(), `node64_pve_poll_failures_total{`+sl+`} 1`) {
		t.Fatalf("metrics down: %s", buf.String())
	}
	fake.mu.Lock()
	fake.down = false
	fake.mu.Unlock()

	// als Check + Regel, dann Export ohne Passwort: kein Secret
	call(t, srv, "PUT", "/api/healthchecks/proxmox/systems/"+fmt.Sprint(id)+"/settings?key=qemu/100", map[string]any{"as_check": true, "rules": map[string]any{"cpu": map[string]any{"percent": 60}}})
	data, err := m.Export(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(data)
	if strings.Contains(string(raw), pveTestSecret) || !strings.Contains(string(raw), `"proxmox":[`) || strings.Contains(string(raw), `"secret":`) {
		t.Fatalf("export: %s", raw)
	}
	// Import in eine frische Node: System ohne Secret abgeschaltet, Check zeigt auf die neue ID
	core2 := pveCore(t)
	m2, _, _ := newPVEModule(t, core2, pveBox(t, 3))
	// eine andere ID erzwingen
	_ = m2.pveInsertNoSecret(context.Background(), &proxmox.System{Name: "other", Addresses: []string{"https://x:8006"}, TokenID: pveTestToken, Interval: 30})
	n, err := m2.Import(context.Background(), raw)
	if n < 2 || err == nil || !strings.Contains(err.Error(), "token secret not in the export") {
		t.Fatalf("import without secret: %d %v", n, err)
	}
	list, _ := m2.pve.st.Systems(context.Background())
	var imp *proxmox.System
	for _, s := range list {
		if s.Name == "lab" {
			imp = s
		}
	}
	if imp == nil || imp.Enabled || imp.Secret != "" || imp.PinSHA256 != pvePinOf(fsrv) {
		t.Fatalf("imported: %+v", imp)
	}
	set, _ := m2.pve.st.Settings(context.Background(), imp.ID)
	it := set.Item("qemu/100")
	if it == nil || !it.AsCheck || it.Rules.CPU == nil || it.Rules.CPU.Percent != 60 {
		t.Fatalf("imported settings: %+v", it)
	}
	c, _ := m2.st.Check(context.Background(), it.CheckToken)
	var p checks.ProxmoxParams
	_ = json.Unmarshal(c.Params, &p)
	if c == nil || p.SystemID != imp.ID {
		t.Fatalf("check params: %+v %s", c, c.Params)
	}
	// Export mit Passwort: Secret verschluesselt dabei, Import stellt es her
	seal := pveBox(t, 9)
	data, _ = m.Export(module.WithSecretSealer(context.Background(), seal))
	raw, _ = json.Marshal(data)
	if strings.Contains(string(raw), pveTestSecret) || !strings.Contains(string(raw), `"secret":"enc:`) {
		t.Fatalf("export with password: %s", raw)
	}
	core3 := pveCore(t)
	m3, _, _ := newPVEModule(t, core3, pveBox(t, 4))
	if _, err := m3.Import(module.WithSecretSealer(context.Background(), seal), raw); err != nil {
		t.Fatalf("import with password: %v", err)
	}
	list, _ = m3.pve.st.Systems(context.Background())
	if len(list) != 1 || list[0].Secret != pveTestSecret || !list[0].Enabled {
		t.Fatalf("imported with secret: %+v", list)
	}
	if pp, _ := m3.pvePollOf(list[0].ID); pp == nil {
		t.Fatal("imported system not polled")
	}
}

// Kanalwahl je Ebene: Vererbung System → Node → Gast, bestimmte Kanaele, Standardkanaele, geloeschte Kanaele
// (beim Senden uebergangen), Formular, API und Export/Import (Kanal-IDs wie bei Checks umgeschrieben).
func TestPVEChannels(t *testing.T) {
	fake := newPVEFake()
	fsrv := startPVEFake(t, fake)
	core := pveCore(t)
	box := pveBox(t, 1)
	m, srv, rec := newPVEModule(t, core, box)
	ctx := context.Background()
	ms, _ := notify.Migrations()
	if err := core.Migrate(ctx, "notify", ms); err != nil {
		t.Fatal(err)
	}
	m.notifyStore = notify.NewStore(core, box)
	addCh := func(name string, def bool) int64 {
		t.Helper()
		c := &notify.Channel{Type: notify.TypeWebhook, Name: name, Config: map[string]string{"url": "http://x/", "method": "POST"}, Enabled: true, Default: def, NotifyDown: true, NotifyUp: true}
		if err := m.notifyStore.Insert(ctx, c); err != nil {
			t.Fatal(err)
		}
		return c.ID
	}
	addCh("std", true)
	b, c := addCh("ops", false), addCh("dev", false)
	id := pveCreate(t, srv, fsrv)
	base := "/api/healthchecks/proxmox/systems/" + fmt.Sprint(id) + "/settings"
	sp := pveResPath(id, "")

	// API: System mit Kanal b und einem nicht (mehr) vorhandenen Kanal 999
	code, body := call(t, srv, "PUT", base, map[string]any{"rules": map[string]any{"channels": []int64{999, b, b}}})
	if code != 200 || !strings.Contains(string(body), fmt.Sprintf(`"channels":[%d,999]`, b)) {
		t.Fatalf("api system channels: %d %s", code, body)
	}
	// Formular: Node pve1 eigene Auswahl ohne Haken (= Standardkanaele), Gast qemu/101 eigene Auswahl c
	resp, _ := pvePost(t, srv, sp+"/settings", url.Values{"key": {"node/pve1"}, "ch_mode": {"own"}, "op": {"save"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("node form: %d", resp.StatusCode)
	}
	pvePost(t, srv, sp+"/settings", url.Values{"key": {"qemu/101"}, "ch_mode": {"own"}, "channels": {fmt.Sprint(c)}, "op": {"save"}})
	// Gast ohne ch_mode erbt (Haken werden dann ignoriert)
	pvePost(t, srv, sp+"/settings", url.Values{"key": {"lxc/200"}, "channels": {fmt.Sprint(c)}, "op": {"save"}})
	if resp, _ := pvePost(t, srv, sp+"/settings", url.Values{"key": {"qemu/100"}, "ch_mode": {"own"}, "channels": {"x"}}); !strings.Contains(resp.Header.Get("X-Flash"), "danger:pve.err.channels") {
		t.Fatalf("invalid channel: %v", resp.Header)
	}
	set, _ := m.pve.st.Settings(ctx, id)
	if it := set.Item("node/pve1"); it == nil || it.Rules.Channels == nil || len(*it.Rules.Channels) != 0 {
		t.Fatalf("node channels: %+v", it)
	}
	if it := set.Item("qemu/101"); it == nil || it.Rules.Channels == nil || fmt.Sprint(*it.Rules.Channels) != fmt.Sprint([]int64{c}) {
		t.Fatalf("guest channels: %+v", it)
	}
	if it := set.Item("lxc/200"); it == nil || it.Rules.Channels != nil {
		t.Fatalf("inherit: %+v", it)
	}
	code, body = call(t, srv, "GET", base, nil)
	var sv struct {
		Effective map[string]proxmox.Rule `json:"effective"`
	}
	_ = json.Unmarshal(body, &sv)
	if code != 200 || fmt.Sprint(sv.Effective["qemu/101"].Channels) != fmt.Sprint([]int64{c}) || len(sv.Effective["qemu/100"].Channels) != 0 ||
		fmt.Sprint(sv.Effective["lxc/200"].Channels) != fmt.Sprint([]int64{b, 999}) {
		t.Fatalf("effective: %d %s", code, body)
	}

	// Seiten: System mit Haken bei b, Gast mit eigener Auswahl, Gast auf pve1 erbt vom Node (Standardkanaele)
	pvePollNow(t, m, id)
	if _, page := pveGet(t, srv, sp); !strings.Contains(page, fmt.Sprintf(`id="pvech%d" checked`, b)) || strings.Contains(page, `name="ch_mode"`) ||
		!strings.Contains(page, "hc.form.channels_hint") {
		t.Fatalf("system page: %s", page)
	}
	if _, page := pveGet(t, srv, sp+"/res/qemu/101"); !strings.Contains(page, `value="own" selected`) || !strings.Contains(page, fmt.Sprintf(`id="pvech%d" checked`, c)) ||
		strings.Contains(page, fmt.Sprintf(`id="pvech%d" checked`, b)) {
		t.Fatalf("guest page own: %s", page)
	}
	if _, page := pveGet(t, srv, sp+"/res/qemu/100"); !strings.Contains(page, `value="" selected`) || !strings.Contains(page, "pve.rules.channels_default (std) · pve.rules.from_node") {
		t.Fatalf("guest page inherited: %s", page)
	}
	if _, page := pveGet(t, srv, sp+"/res/lxc/200"); !strings.Contains(page, "ops · pve.rules.from_system") || !strings.Contains(page, fmt.Sprintf(`id="pvech%d" checked`, b)) {
		t.Fatalf("guest page from system: %s", page)
	}

	// Meldungen: Absturz qemu/102 (pve1, Node mit Standardkanaelen) bei der ersten Abfrage
	al := rec.take()
	if len(al) != 1 || al[0].Check.Target != "qemu/102" || al[0].Check.Channels != nil {
		t.Fatalf("crash alert channels: %+v", al)
	}
	fake.set("qemu/101", "status", "stopped") // pve2, eigene Auswahl c
	fake.set("lxc/200", "status", "stopped")  // pve2, vom System: b (999 entfaellt)
	pvePollNow(t, m, id)
	pvePollNow(t, m, id)
	got := map[string]string{}
	for _, a := range rec.take() {
		got[a.Check.Target] = fmt.Sprint(a.Check.Channels)
	}
	if got["qemu/101"] != fmt.Sprint([]int64{c}) || got["lxc/200"] != fmt.Sprint([]int64{b}) {
		t.Fatalf("channels: %v", got)
	}

	// Export/Import: Kanal-IDs wie bei Checks umschreiben (b → 42, c und 999 unbekannt)
	data, err := m.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(data)
	m2, _, _ := newPVEModule(t, pveCore(t), pveBox(t, 3))
	_, _ = m2.Import(module.WithChannelMap(ctx, map[int64]int64{b: 42}), raw)
	list, _ := m2.pve.st.Systems(ctx)
	if len(list) != 1 {
		t.Fatalf("imported: %+v", list)
	}
	set2, _ := m2.pve.st.Settings(ctx, list[0].ID)
	if it := set2.Item(""); it == nil || it.Rules.Channels == nil || fmt.Sprint(*it.Rules.Channels) != "[42]" {
		t.Fatalf("imported system channels: %+v", it)
	}
	if it := set2.Item("qemu/101"); it == nil || it.Rules.Channels == nil || len(*it.Rules.Channels) != 0 {
		t.Fatalf("imported guest channels: %+v", it)
	}
	if it := set2.Item("lxc/200"); it != nil && it.Rules.Channels != nil {
		t.Fatalf("imported inherit: %+v", it)
	}

	// Kanal c geloescht: Entwarnung fuer qemu/101 geht an die Standardkanaele
	if err := m.notifyStore.Delete(ctx, c); err != nil {
		t.Fatal(err)
	}
	fake.set("qemu/101", "status", "running")
	pvePollNow(t, m, id)
	up := false
	for _, a := range rec.take() {
		if a.Check.Target == "qemu/101" && a.Kind == notify.KindProxmoxUp {
			up = true
			if a.Check.Channels != nil {
				t.Fatalf("deleted channel not ignored: %+v", a.Check)
			}
		}
	}
	if !up {
		t.Fatal("no recovery for qemu/101")
	}
	if _, page := pveGet(t, srv, sp+"/res/qemu/101"); strings.Contains(page, fmt.Sprintf(`id="pvech%d"`, c)) {
		t.Fatalf("deleted channel offered: %s", page)
	}

	// Systemebene im Formular ohne Haken: Standardkanaele (nichts gespeichert)
	pvePost(t, srv, sp+"/settings", url.Values{"key": {""}, "op": {"save"}})
	set, _ = m.pve.st.Settings(ctx, id)
	if it := set.Item(""); it == nil || it.Rules.Channels != nil {
		t.Fatalf("system default: %+v", it)
	}
	// API: leere Liste = Standardkanaele, ungueltige ID 422
	code, body = call(t, srv, "PUT", base+"?key=lxc/200", map[string]any{"rules": map[string]any{"channels": []int64{}}})
	if code != 200 || !strings.Contains(string(body), `"rules":{"channels":[]}`) {
		t.Fatalf("api empty list: %d %s", code, body)
	}
	if code, body = call(t, srv, "PUT", base+"?key=lxc/200", map[string]any{"rules": map[string]any{"channels": []int64{-1}}}); code != 422 {
		t.Fatalf("api invalid channel: %d %s", code, body)
	}
}

// Cluster ohne Recht auf cluster/status (403, Sys.Audit auf „/“ fehlt): mehrere Nodes gelten als Cluster mit unbekanntem
// Quorum, nicht als Einzel-Node; Token-Teile fuer die pveum-Befehle.
func TestPVEClusterUnknown(t *testing.T) {
	sys := &proxmox.System{TokenID: "node64@pve!monitor"}
	row := pveSysRow{Sys: sys, Nodes: 3, Snap: &proxmox.Snapshot{OK: true}}
	if !row.ClusterUnknown() || row.TokenUser() != "node64@pve" || row.TokenName() != "monitor" {
		t.Fatalf("cluster unknown: %v %q %q", row.ClusterUnknown(), row.TokenUser(), row.TokenName())
	}
	ok := true
	row.Snap.Quorate, row.Snap.Cluster = &ok, "benny"
	if row.ClusterUnknown() {
		t.Fatal("cluster mit status gilt als unbekannt")
	}
	if (pveSysRow{Sys: sys, Nodes: 1, Snap: &proxmox.Snapshot{OK: true}}).ClusterUnknown() {
		t.Fatal("einzel-node als cluster")
	}
}
