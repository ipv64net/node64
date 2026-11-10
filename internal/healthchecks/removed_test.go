package healthchecks

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/scheduler"
	"github.com/ipv64net/node64/internal/store"
	"github.com/ipv64net/node64/internal/wire"
)

// removedCheck legt einen Check direkt im Store an (ohne Pruefung, wie ihn eine aeltere Version gespeichert hat).
func removedCheck(t *testing.T, st *Store, typ checks.Type, owner, name string) *Check {
	t.Helper()
	c := &Check{Token: NewToken(), Type: typ, Name: name, Target: "x", Params: json.RawMessage("{}"), Interval: time.Minute, RetryInterval: 20 * time.Second,
		ConnectTimeout: time.Second, TotalTimeout: 2 * time.Second, Stabilize: 1, IPMode: checks.IPAuto, Owner: owner, Execution: "local"}
	if err := st.Insert(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c
}

func count(t *testing.T, core *store.Store, q string, args ...any) int {
	t.Helper()
	var n int
	if err := core.Reader().QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// Update auf 3.0.0: eine Datenbank aus 2.x mit Docker- und Proxmox-Checks, Systemen der Ueberwachung, Statusseiten-
// Eintraegen und Wartungsfenstern. Danach ist von Proxmox VE und Docker nichts mehr da, andere Checks bleiben
// unveraendert, der Hinweis ist gesetzt und eigene Checks gehen nach dem Start als geloescht an hub und Cluster.
func TestMigrationRemovesProxmoxDocker(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(ctx, filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), lg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	cm, _ := store.CoreMigrations()
	if err := core.Migrate(ctx, "core", cm); err != nil {
		t.Fatal(err)
	}
	m := New(core, lg, nil, nil, "test")
	all := m.Migrations()
	old := slices.DeleteFunc(slices.Clone(all), func(x store.Migration) bool { return x.Version > 21 })
	if len(old) != 21 {
		t.Fatalf("migrations before 3.0.0: %d", len(old))
	}
	if err := core.Migrate(ctx, Name, old); err != nil {
		t.Fatal(err)
	}
	st := m.st
	web := removedCheck(t, st, checks.TypeHTTP, "self", "web")
	dock := removedCheck(t, st, checks.TypeDocker, "self", "nginx")
	pve := removedCheck(t, st, checks.TypeProxmox, "self", "vm 101")
	foreign := removedCheck(t, st, checks.TypeDocker, "other", "fremd")
	child := removedCheck(t, st, checks.TypeICMP, "self", "kind")
	if _, err := core.Writer().Exec(`UPDATE hc_checks SET parent_token = ? WHERE token = ?`, dock.Token, child.Token); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, c := range []*Check{web, dock, pve, foreign} {
		if err := st.SaveMeasurement(ctx, scheduler.Measurement{Token: c.Token, Time: now, Status: checks.Up}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.OpenIncident(ctx, c.Token, now, checks.ReasonTimeout, "x"); err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{
			`INSERT INTO hc_events (event_id, token, kind, time) VALUES (?2, ?1, 'down', '2026-11-01T00:00:00.000Z')`,
			`INSERT INTO hc_hourly (token, hour, count, up_count, min_ms, avg_ms, max_ms) VALUES (?, ?, 1, 1, 1, 1, 1)`,
			`INSERT INTO hc_daily (token, day, count, up_count, min_ms, avg_ms, max_ms) VALUES (?, ?, 1, 1, 1, 1, 1)`,
			`INSERT INTO hc_sources (token, source) VALUES (?, ?)`,
			`INSERT INTO hc_source_points (token, source, time, status) VALUES (?, ?, '2026-11-01T00:00:00.000Z', 1)`,
			`INSERT INTO hc_source_hourly (token, source, hour, count, up_count) VALUES (?, ?, '2026-11-01T00:00:00.000Z', 1, 1)`,
			`INSERT INTO hc_outbox (entity, entity_id, op, created_at) VALUES ('check', ?, ?, '2026-11-01T00:00:00.000Z')`,
		} {
			if _, err := core.Writer().Exec(q, c.Token, "a"+c.Token); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
	}
	p := &StatusPage{Slug: "lab", Title: "Lab", Groups: []StatusGroup{{Name: "A", Items: []StatusItem{{Token: web.Token}, {Token: dock.Token}, {Token: pve.Token}, {Token: foreign.Token}}}}}
	if err := st.SaveStatusPage(ctx, p, ""); err != nil {
		t.Fatal(err)
	}
	onlyDock := Maintenance{Name: "nur docker", StartAt: now, EndAt: now.Add(time.Hour), Repeat: "none", Active: true, Tokens: []string{dock.Token}}
	mixed := Maintenance{Name: "gemischt", StartAt: now, EndAt: now.Add(time.Hour), Repeat: "none", Active: true, Tokens: []string{web.Token, pve.Token, foreign.Token}}
	for _, mw := range []*Maintenance{&onlyDock, &mixed} {
		if err := st.MaintenanceInsert(ctx, mw); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{
		`INSERT INTO pve_systems (id, name, token_id, created_at, updated_at, kind, uid) VALUES (1, 'lab', 'root@pam!n', 'x', 'x', 'pve', 'u1')`,
		`INSERT INTO pve_settings (system_id, key, as_check, check_token, updated_at) VALUES (1, 'qemu/101', 1, '` + pve.Token + `', 'x')`,
		`INSERT INTO pve_hist_1m (system_id, key, t, n, cpu, cpu_max, mem, net_in, net_out, disk_read, disk_write) VALUES (1, 'qemu/101', 1, 1, 1, 1, 1, 1, 1, 1, 1)`,
	} {
		if _, err := core.Writer().Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for _, k := range []string{"pve.engine.1", "pve.last_incident", "docker.last_incident", "docker.monitor", "hc.raw_days"} {
		if err := core.SetSetting(ctx, k, "1"); err != nil {
			t.Fatal(err)
		}
	}

	// Update
	if err := core.Migrate(ctx, Name, all); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{dock.Token, pve.Token, foreign.Token} {
		for _, tbl := range []string{"hc_checks", "hc_measurements", "hc_events", "hc_incidents", "hc_sources", "hc_source_points", "hc_source_hourly", "hc_hourly", "hc_daily", "hc_status_items"} {
			if n := count(t, core, `SELECT count(*) FROM `+tbl+` WHERE token = ?`, tok); n != 0 {
				t.Fatalf("%s still has %d rows of a removed check", tbl, n)
			}
		}
		if n := count(t, core, `SELECT count(*) FROM hc_outbox WHERE entity_id = ?`, tok); n != 0 {
			t.Fatal("pending hub changes of removed checks must go")
		}
	}
	for _, tbl := range []string{"hc_checks", "hc_measurements", "hc_events", "hc_incidents", "hc_sources", "hc_source_points", "hc_source_hourly", "hc_hourly", "hc_daily", "hc_status_items"} {
		if n := count(t, core, `SELECT count(*) FROM `+tbl+` WHERE token = ?`, web.Token); n != 1 {
			t.Fatalf("%s: other check must stay (%d rows)", tbl, n)
		}
	}
	if n := count(t, core, `SELECT count(*) FROM hc_outbox WHERE entity_id = ?`, web.Token); n != 1 {
		t.Fatal("pending change of another check must stay")
	}
	if c, _ := st.Check(ctx, child.Token); c == nil || c.Parent != "" {
		t.Fatalf("parent of a removed check must be cleared: %+v", c)
	}
	if c, _ := st.Check(ctx, web.Token); c == nil || c.Name != "web" || c.Type != checks.TypeHTTP {
		t.Fatalf("other check unchanged: %+v", c)
	}
	if n := count(t, core, `SELECT count(*) FROM sqlite_master WHERE name LIKE 'pve_%'`); n != 0 {
		t.Fatalf("pve tables and indexes left: %d", n)
	}
	for _, k := range []string{"pve.engine.1", "pve.last_incident", "docker.last_incident", "docker.monitor"} {
		if v := core.SettingOr(ctx, k, ""); v != "" {
			t.Fatalf("setting %s left", k)
		}
	}
	if core.SettingOr(ctx, "hc.raw_days", "") != "1" {
		t.Fatal("other settings stay")
	}
	got, err := st.StatusPage(ctx, p.ID)
	if err != nil || len(got.Groups) != 1 || len(got.Groups[0].Items) != 1 || got.Groups[0].Items[0].Token != web.Token {
		t.Fatalf("status page items: %+v %v", got, err)
	}
	if !m.removedNotice(ctx) {
		t.Fatal("notice must be set")
	}
	own := strings.Split(core.SettingOr(ctx, settingRemovedTokens, ""), ",")
	slices.Sort(own)
	want := []string{dock.Token, pve.Token}
	slices.Sort(want)
	if !slices.Equal(own, want) {
		t.Fatalf("own removed tokens: %v, want %v", own, want)
	}
	if m.TombstoneAt(ctx, dock.Token).IsZero() || m.TombstoneAt(ctx, pve.Token).IsZero() || !m.TombstoneAt(ctx, foreign.Token).IsZero() {
		t.Fatal("tombstones only for own checks (another node's check is not deleted in the cluster)")
	}

	// nach dem Start: Loeschmeldung der eigenen Checks an hub (OnChange) und Cluster (OnAnyChange), Wartungsfenster
	var toHub, toCluster []string
	st.OnChange = func(_ context.Context, entity, id, op string) { toHub = append(toHub, entity+"/"+op+"/"+id) }
	st.OnAnyChange = func(_ context.Context, entity, id, op string) { toCluster = append(toCluster, entity+"/"+op+"/"+id) }
	m.announceRemoved(ctx)
	for _, l := range [][]string{toHub, toCluster} {
		for _, tok := range []string{dock.Token, pve.Token} {
			if !slices.Contains(l, "check/delete/"+tok) {
				t.Fatalf("delete of %s not announced: %v", tok, l)
			}
		}
		if slices.ContainsFunc(l, func(s string) bool { return strings.HasSuffix(s, foreign.Token) || strings.HasSuffix(s, web.Token) }) {
			t.Fatalf("only own removed checks: %v", l)
		}
		if !slices.Contains(l, "maintenance/delete/"+jsonID(onlyDock.ID)) || !slices.Contains(l, "maintenance/upsert/"+jsonID(mixed.ID)) {
			t.Fatalf("maintenance windows: %v", l)
		}
	}
	list, _ := st.MaintenanceList(ctx)
	if len(list) != 1 || list[0].ID != mixed.ID || !slices.Equal(list[0].Tokens, []string{web.Token, foreign.Token}) {
		t.Fatalf("maintenance after removal: %+v", list)
	}
	if core.SettingOr(ctx, settingRemovedTokens, "") != "" {
		t.Fatal("token list must be cleared")
	}
	toHub, toCluster = nil, nil
	m.announceRemoved(ctx) // nur einmal
	if len(toHub)+len(toCluster) != 0 {
		t.Fatalf("second run: %v %v", toHub, toCluster)
	}
}

func jsonID(id int64) string { return strconv.FormatInt(id, 10) }

// Neue Installation bzw. ohne Proxmox VE und Docker: kein Hinweis, keine Liste.
func TestMigrationRemovedNothing(t *testing.T) {
	m, _ := newTestModule(t)
	ctx := context.Background()
	if m.removedNotice(ctx) || m.core.SettingOr(ctx, settingRemovedTokens, "") != "" {
		t.Fatal("nothing removed: no notice")
	}
}

// Eingaenge: hub (ApplyWireCheck), Cluster (ApplyPeerCheck), API und Import nehmen docker/proxmox nicht an.
func TestRemovedTypesIgnored(t *testing.T) {
	m, srv := newTestModule(t)
	ctx := context.Background()
	for _, typ := range []string{"docker", "proxmox", " Docker "} {
		w := wire.Check{Token: NewToken(), Name: "x", Type: typ, Target: "c", Params: json.RawMessage(`{"system_id":1,"key":"qemu/1"}`), IntervalSeconds: 60,
			RetryIntervalSeconds: 20, Retries: 1, ConnectTimeoutSeconds: 5, TimeoutSeconds: 10, Stabilize: 1, Owner: "self"}
		if err := m.ApplyWireCheck(ctx, w, nil); err != nil {
			t.Fatalf("hub %s: %v", typ, err)
		}
		if ok, err := m.ApplyPeerCheck(ctx, w, time.Now(), "nodeB_0123456789abcdef", "nodeA_0123456789abcdef"); ok || err != nil {
			t.Fatalf("cluster %s: %v %v", typ, ok, err)
		}
		if c, _ := m.st.Check(ctx, w.Token); c != nil {
			t.Fatalf("%s must not be stored", typ)
		}
		if _, ok := m.scheduler().Runtime(w.Token); ok {
			t.Fatalf("%s must not be scheduled", typ)
		}
	}
	if n := count(t, m.core, `SELECT count(*) FROM hc_conflicts`); n != 0 {
		t.Fatal("no conflicts")
	}

	// lokale API: 400 mit Hinweis
	for _, typ := range []string{"docker", "proxmox"} {
		code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": "x", "type": typ, "target": "c"})
		if code != http.StatusBadRequest || !strings.Contains(string(b), "Monitor64") {
			t.Fatalf("create %s: %d %s", typ, code, b)
		}
	}
	code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": "web", "type": "http", "target": "http://example.com/"})
	if code != http.StatusCreated {
		t.Fatalf("create http: %d %s", code, b)
	}
	var c checkJSON
	_ = json.Unmarshal(b, &c)
	if code, b := call(t, srv, "PUT", "/api/checks/"+c.Token, map[string]any{"name": "web", "type": "docker", "target": "c"}); code != http.StatusBadRequest {
		t.Fatalf("change to docker: %d %s", code, b)
	}
	if code, b := call(t, srv, "GET", "/api/check-types", nil); code != 200 || strings.Contains(string(b), "docker") || strings.Contains(string(b), "proxmox") {
		t.Fatalf("check types: %d %s", code, b)
	}
	for _, path := range []string{"/api/healthchecks/proxmox/systems", "/api/healthchecks/docker/systems/1/resources", "/api/healthchecks/docker"} {
		if code, _ := call(t, srv, "GET", path, nil); code != http.StatusGone {
			t.Fatalf("%s: %d", path, code)
		}
	}
	if code, _ := call(t, srv, "POST", "/api/healthchecks/proxmox/systems", map[string]any{}); code != http.StatusGone {
		t.Fatalf("post proxmox: %d", code)
	}
}

// Export einer 2.x mit Proxmox-Systemen und Docker-/Proxmox-Checks: laesst sich importieren, diese Teile fallen weg.
func TestImportOldExportWithProxmox(t *testing.T) {
	m, _ := newTestModule(t)
	ctx := context.Background()
	web, dock, pve := NewToken(), NewToken(), NewToken()
	raw := `{"checks":[
		{"token":"` + web + `","name":"web","type":"http","target":"http://example.com/","tags":[],"description":"","locations":[],"channels":[]},
		{"token":"` + dock + `","name":"nginx","type":"docker","target":"nginx","params":{"host":"unix:///var/run/docker.sock","system":"nas"},"tags":[],"description":"","locations":[],"channels":[]},
		{"token":"` + pve + `","name":"vm","type":"proxmox","target":"qemu/101","params":{"system_id":1,"key":"qemu/101","system_uid":"u"},"tags":[],"description":"","locations":[],"channels":[],"parent":"` + web + `"}],
	"maintenance":[
		{"name":"nur docker","start_at":"2026-01-01T00:00:00Z","end_at":"2026-01-01T01:00:00Z","repeat":"none","tokens":["` + dock + `"],"active":true},
		{"name":"beide","start_at":"2026-01-01T00:00:00Z","end_at":"2026-01-01T01:00:00Z","repeat":"none","tokens":["` + dock + `","` + web + `"],"active":true}],
	"proxmox":[{"kind":"pve","name":"lab","addresses":["https://192.0.2.1:8006"],"token_id":"root@pam!n","secret":"enc:v1:x","interval":30,"enabled":true,"settings":[{"key":"qemu/101","as_check":true}]}],
	"status_pages":[{"slug":"lab","title":"Lab","layout":"list","theme":"auto","days":90,"refresh_sec":60,"groups":[{"name":"A","items":[{"token":"` + web + `"},{"token":"` + dock + `"}]}]}]}`
	n, err := m.Import(ctx, json.RawMessage(raw))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if n != 3 { // ein Check, ein Wartungsfenster, eine Statusseite
		t.Fatalf("imported: %d", n)
	}
	list, _ := m.st.Checks(ctx)
	if len(list) != 1 || list[0].Token != web {
		t.Fatalf("checks: %+v", list)
	}
	mw, _ := m.st.MaintenanceList(ctx)
	if len(mw) != 1 || mw[0].Name != "beide" || !slices.Equal(mw[0].Tokens, []string{web}) {
		t.Fatalf("maintenance: %+v", mw)
	}
	p, err := m.st.StatusPageBySlug(ctx, "lab")
	if err != nil || len(p.Groups) != 1 || len(p.Groups[0].Items) != 1 || p.Groups[0].Items[0].Token != web {
		t.Fatalf("status page: %+v %v", p, err)
	}
	out, err := m.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), `"proxmox"`) {
		t.Fatalf("export without proxmox: %s", b)
	}
}

// renderView bildet die Methoden der Oberflaeche nach, die Uebersicht und Formular nutzen.
type renderView struct {
	Data    any
	CSRF    string
	Version string
}

func (renderView) T(key string, args ...any) string { return key }
func (renderView) Doc(string) template.HTML         { return "" }
func (renderView) Time(t time.Time) string          { return t.Format(time.RFC3339) }
func (renderView) Date(t time.Time) string          { return t.Format("2006-01-02") }
func (renderView) Ago(t time.Time) string           { return t.Format(time.RFC3339) }
func (renderView) Int(n int64) string               { return strconv.FormatInt(n, 10) }

// Seiten der Healthchecks ohne Proxmox VE und Docker: Uebersicht mit Hinweis (schliessbar), Formular ohne die
// Typen docker/proxmox, alte Seiten fuehren zur Uebersicht.
func TestRemovedPages(t *testing.T) {
	m, _ := newTestModule(t)
	ctx := context.Background()
	funcs := template.FuncMap{"add": func(a, b int) int { return a + b }, "sub": func(a, b int) int { return a - b }, "join": strings.Join,
		"split": strings.Fields, "contains": strings.Contains, "ms": func(f float64) string { return strconv.FormatFloat(f, 'f', 1, 64) }}
	render := func(w http.ResponseWriter, r *http.Request, status int, page, titleKey string, data any) {
		tpl := template.Must(template.New("root").Funcs(funcs).Parse(`{{template "content" .}}{{block "scripts" .}}{{end}}`))
		if _, err := tpl.ParseFS(templateFS, "templates/pages/"+strings.TrimPrefix(page, Name+"/")+".html"); err != nil {
			t.Fatalf("%s: %v", page, err)
		}
		var buf bytes.Buffer
		if err := tpl.Execute(&buf, renderView{Data: data, CSRF: "csrf", Version: "v"}); err != nil {
			t.Fatalf("%s: %v", page, err)
		}
		w.WriteHeader(status)
		_, _ = w.Write(buf.Bytes())
	}
	pass := func(h http.Handler) http.Handler { return h }
	mux := http.NewServeMux()
	m.Routes(mux, module.Guards{Enabled: pass, Auth: pass, Render: render, T: func(r *http.Request, key string, args ...any) string { return key },
		Actor: func(*http.Request) string { return "test" }, Lang: func(*http.Request) string { return "de" }, Timezone: func(*http.Request) *time.Location { return time.UTC },
		Flash: func(w http.ResponseWriter, r *http.Request, kind, text string) {
			w.Header().Add("X-Flash", kind+":"+text)
		}})
	get := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w
	}
	removedCheck(t, m.st, checks.TypeHTTP, "self", "web")
	if w := get("GET", "/healthchecks"); w.Code != 200 || strings.Contains(w.Body.String(), "hc-moved") {
		t.Fatalf("list without notice: %d", w.Code)
	}
	if err := m.core.SetSetting(ctx, settingRemovedNotice, "1"); err != nil {
		t.Fatal(err)
	}
	w := get("GET", "/healthchecks")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "hc.moved.notice") || !strings.Contains(w.Body.String(), `action="/healthchecks/notice/monitor64"`) {
		t.Fatalf("list with notice: %d %s", w.Code, w.Body.String())
	}
	if w := get("POST", "/healthchecks/notice/monitor64"); w.Code != http.StatusSeeOther || m.removedNotice(ctx) {
		t.Fatalf("dismiss: %d %v", w.Code, m.removedNotice(ctx))
	}
	if w := get("GET", "/healthchecks"); strings.Contains(w.Body.String(), "hc-moved") {
		t.Fatal("notice must be gone")
	}
	for _, path := range []string{"/healthchecks/new", "/healthchecks/new?type=docker"} {
		w := get("GET", path)
		if w.Code != 200 || strings.Contains(w.Body.String(), `value="docker"`) || strings.Contains(w.Body.String(), `value="proxmox"`) || strings.Contains(w.Body.String(), "sys:") ||
			!strings.Contains(w.Body.String(), `value="http"`) {
			t.Fatalf("form %s: %d", path, w.Code)
		}
	}
	for _, path := range []string{"/healthchecks/proxmox", "/healthchecks/docker", "/healthchecks/proxmox/system/1", "/healthchecks/docker/system/2/c/web", "/healthchecks/proxmox/new"} {
		if w := get("GET", path); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/healthchecks" || !strings.Contains(w.Header().Get("X-Flash"), "hc.moved.page") {
			t.Fatalf("%s: %d %v", path, w.Code, w.Header())
		}
	}
}
