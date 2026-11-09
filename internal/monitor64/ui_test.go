package monitor64

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/module"
)

var reTplKey = regexp.MustCompile(`\.T "(monitor64\.[a-z0-9_.]+)"`)

// tplView ersetzt die View des Kerns in den Render-Tests (Texte kommen als Schluessel zurueck).
type tplView struct {
	Data          any
	CSRF, Version string
}

func (tplView) T(key string, _ ...any) string { return key }

// renderPage fuehrt eine Seite des Moduls aus (Bausteine + Seite, "content" und "scripts").
func renderPage(t *testing.T, page string, data any) string {
	t.Helper()
	tp, err := template.New(page).ParseFS(templateFS, "templates/partials/*.html", "templates/pages/"+page+".html")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	for _, name := range []string{"content", "scripts"} {
		if err := tp.ExecuteTemplate(&buf, name, tplView{Data: data, CSRF: "tok", Version: "t1"}); err != nil {
			t.Fatalf("%s/%s: %v", page, name, err)
		}
	}
	return buf.String()
}

// testEnv ist ein gestartetes Modul mit Oberflaeche und API hinter einem ServeMux (ohne Anmeldung).
type testEnv struct {
	m      *Module
	mux    *http.ServeMux
	mu     sync.Mutex
	audits []string
	pages  map[string]string
	t      *testing.T
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	return newEnvWith(t, nil)
}

// newEnvWith: wie newEnv, before laeuft vor dem Start (z. B. Cluster anhaengen).
func newEnvWith(t *testing.T, before func(*Module)) *testEnv {
	t.Helper()
	m, _, _ := newTestModule(t)
	ctx := context.Background()
	if before != nil {
		before(m)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	e := &testEnv{m: m, mux: http.NewServeMux(), pages: map[string]string{}, t: t}
	pass := func(h http.Handler) http.Handler { return h }
	g := module.Guards{Enabled: pass, Auth: pass,
		T:        func(_ *http.Request, key string, _ ...any) string { return key },
		Actor:    func(*http.Request) string { return "dennis" },
		ClientIP: func(*http.Request) string { return "10.0.0.42" },
		CSRF:     func(*http.Request) string { return "tok" },
		Lang:     func(*http.Request) string { return "de" },
		Timezone: func(*http.Request) *time.Location { return time.UTC },
		Audit: func(_ *http.Request, action, target, details string) {
			e.mu.Lock()
			e.audits = append(e.audits, action+"|"+target+"|"+details)
			e.mu.Unlock()
		},
		Render: func(w http.ResponseWriter, _ *http.Request, status int, page, _ string, data any) {
			name := strings.TrimPrefix(page, "monitor64/")
			body := renderPage(t, name, data)
			e.mu.Lock()
			e.pages[name] = body
			e.mu.Unlock()
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		},
	}
	m.Routes(e.mux, g)
	return e
}

// do schickt eine Anfrage an die Oberflaeche bzw. API.
func (e *testEnv) do(method, path string, body any, hdr ...string) *httptest.ResponseRecorder {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func (e *testEnv) audited(prefix string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, a := range e.audits {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

func mustContain(t *testing.T, what, body string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Fatalf("%s misses %q", what, w)
		}
	}
}

// Alle Seiten rendern mit Reitern, Startdaten und den Elementen, die das Skript fuellt.
func TestPagesRender(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	by := Actor{Kind: "user", Name: "dennis"}
	h := &Host{Name: "nas<01>", Address: "192.0.2.20", Kind: "ssh", Group: "Keller", Tags: []string{"backup"}, IntervalSec: 60, Paused: true}
	if err := e.m.store.SaveHost(ctx, h, by); err != nil {
		t.Fatal(err)
	}
	if err := e.m.store.SaveAccess(ctx, &Access{HostUID: h.UID, Type: "ssh", Config: json.RawMessage(`{"user":"monitor64"}`), Secret: e.m.box.Encrypt("geheim-123"), Enabled: true}, false, by); err != nil {
		t.Fatal(err)
	}
	e.m.ReloadHost(ctx, h.UID)
	accs, _ := e.m.store.Accesses(ctx, h.UID)
	stored := accs[0].Secret

	tabs := []string{`href="/monitor64"`, `href="/monitor64/problems"`, `href="/monitor64/maintenance"`, `href="/monitor64/rules"`, `href="/monitor64/notify"`, `href="/monitor64/settings"`,
		`/monitor64/monitor64.css?v=t1`, `/monitor64/monitor64.js?v=t1`, `/static/js/chart.umd.js`, `id="m64-data"`, `id="m64-modal"`, `id="m64-toast"`}
	cases := []struct {
		path, page string
		wants      []string
	}{
		{"/monitor64", "overview", []string{`data-m64-page="overview"`, `id="m64-stats"`, `id="m64-problems"`, `id="m64-recent"`, `id="m64-hosts"`, `href="/monitor64/new"`, "monitor64.ov.add", `nas\u003c01\u003e`}},
		{"/monitor64/host/" + h.UID, "host", []string{`data-m64-page="host"`, `data-host="` + h.UID + `"`, `nas&lt;01&gt;`, `id="m64-svcs"`, `id="m64-charts"`, `data-range="1y"`, `id="m64-detail"`, `data-act="discover"`, `data-act="delete"`, `"secret_set":true`}},
		{"/monitor64/problems", "problems", []string{`data-m64-page="problems"`, `data-tab="closed"`, `id="m64-who"`, `id="m64-csv"`, `id="m64-pb"`}},
		{"/monitor64/maintenance", "maintenance", []string{`data-m64-page="maint"`, `id="m64-maint-new"`, `id="m64-maint-list"`}},
		{"/monitor64/rules", "rules", []string{`data-m64-page="rules"`, `data-kind="fs.used"`, `name="warn" value="80"`, `name="crit" value="90"`, `data-kind="ups.runtime" data-factor="60"`, `name="crit" value="10"`,
			`data-kind="smart.failed"`, `value="crit" selected`, `id="m64-ovr"`, "monitor64.rgroup.storage", `value="900" selected`}},
		{"/monitor64/notify", "notify", []string{`data-m64-page="notify"`, `id="m64-nf-channels"`, `id="m64-remind-crit"`, `id="m64-crit-quiet"`, `data-pv="f"`, `id="m64-nf-test"`}},
		{"/monitor64/settings", "settings", []string{`data-m64-page="settings"`, `id="m64-settings-form"`, `id="m64-status"`, `value="60" selected`, `id="m64-pubkey"`, "ssh-ed25519 ", `id="m64-fp"`, "SHA256:"}},
		{"/monitor64/new", "new", []string{`data-m64-page="new"`, `data-kind="linux-agent"`, `data-kind="snmp"`, `kind-tile" data-kind="nas"`, `id="m64-next"`, `"public_key":"ssh-ed25519 `}},
	}
	for _, c := range cases {
		rec := e.do("GET", c.path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", c.path, rec.Code)
		}
		body := rec.Body.String()
		mustContain(t, c.page, body, tabs...)
		mustContain(t, c.page, body, c.wants...)
		if strings.Contains(body, "geheim-123") || strings.Contains(body, stored) || strings.Contains(body, `"secret":`) {
			t.Fatalf("%s leaks a secret", c.page)
		}
	}
	// Unbekannter Host: zurueck zur Uebersicht
	if rec := e.do("GET", "/monitor64/host/nope", nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("unknown host: %d", rec.Code)
	}
	// Skript und Stil von der eigenen Adresse
	if rec := e.do("GET", "/monitor64/monitor64.js", nil); rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/javascript") || rec.Body.Len() < 1000 {
		t.Fatalf("js: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec := e.do("GET", "/monitor64/monitor64.css", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), ".host-tile") {
		t.Fatalf("css: %d", rec.Code)
	}
}

// Brotkrumen: Host-Seite liefert den Namen als letzte Stufe.
func TestCrumb(t *testing.T) {
	d := &pageData{Title: "nas01"}
	var c interface{ Crumb() string } = d
	if c.Crumb() != "nas01" {
		t.Fatal(c.Crumb())
	}
}

// Jeder Text, den Skript, Seiten und Server nutzen, steht deutsch und englisch in den Sprachdateien.
func TestTextsComplete(t *testing.T) {
	b, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for _, k := range textKeys() {
		keys = append(keys, "monitor64."+k)
	}
	if len(keys) < 200 {
		t.Fatalf("only %d script texts found", len(keys))
	}
	for _, k := range ruleKinds {
		keys = append(keys, "monitor64.kind."+kindKey(k.Kind))
	}
	for _, k := range coreTexts {
		keys = append(keys, "monitor64."+k)
	}
	for _, c := range svcCategories {
		keys = append(keys, "monitor64.cat."+c)
	}
	for _, k := range hostKinds {
		keys = append(keys, "monitor64.hostkind."+k.Kind+".title", "monitor64.hostkind."+k.Kind+".sub")
	}
	for _, a := range append(append([]string{}, accessTypes...), "snmp", "prom") {
		keys = append(keys, "monitor64.access."+a)
	}
	for _, g := range ruleGroups {
		keys = append(keys, "monitor64.rgroup."+g)
	}
	for _, s := range durChoices {
		keys = append(keys, "monitor64.dur."+strconv.Itoa(s))
	}
	// Seiten-Templates
	for _, re := range []string{"templates/pages", "templates/partials"} {
		ents, _ := templateFS.ReadDir(re)
		for _, en := range ents {
			raw, _ := templateFS.ReadFile(re + "/" + en.Name())
			for _, mm := range reTplKey.FindAllSubmatch(raw, -1) {
				keys = append(keys, string(mm[1]))
			}
		}
	}
	for _, code := range []string{"json", "internal", "not_found", "not_running", "name", "address", "kind", "rule", "target", "channel", "maint_time", "interval", "workers", "cluster_node"} {
		keys = append(keys, "monitor64.err."+code)
	}
	for _, lang := range []string{"de", "en"} {
		for _, k := range keys {
			if strings.Contains(k, "%") { // printf-Schluessel aus Templates (oben einzeln geprueft)
				continue
			}
			if b.T(lang, k) == k {
				t.Errorf("%s: missing %s", lang, k)
			}
		}
	}
}
