package healthchecks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"image"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/module"
)

// spEnv: Modul mit vollstaendigen Guards (Render/Flash/Audit werden mitgeschrieben), Aufrufe direkt am Mux.
type spEnv struct {
	t     *testing.T
	m     *Module
	mux   *http.ServeMux
	mu    sync.Mutex
	page  string
	data  any
	audit []string
}

func newSPEnv(t *testing.T) *spEnv {
	t.Helper()
	m, _ := newTestModule(t)
	e := &spEnv{t: t, m: m, mux: http.NewServeMux()}
	pass := func(h http.Handler) http.Handler { return h }
	key := func(_ *http.Request, k string, _ ...any) string { return k }
	m.Routes(e.mux, module.Guards{Enabled: pass, Auth: pass,
		Render: func(w http.ResponseWriter, r *http.Request, status int, page, titleKey string, data any) {
			e.mu.Lock()
			e.page, e.data = page, data
			e.mu.Unlock()
			w.WriteHeader(status)
			fmt.Fprint(w, page)
		},
		T:         key,
		Translate: func(lang, k string, _ ...any) string { return k },
		Flash:     func(http.ResponseWriter, *http.Request, string, string) {},
		Audit: func(r *http.Request, action, target, details string) {
			e.mu.Lock()
			e.audit = append(e.audit, action+" "+target)
			e.mu.Unlock()
		},
	})
	return e
}

func (e *spEnv) do(method, path string, body io.Reader, ctype string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, body)
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	return w
}

func (e *spEnv) form(path string, v url.Values) *httptest.ResponseRecorder {
	return e.do("POST", path, strings.NewReader(v.Encode()), "application/x-www-form-urlencoded")
}

func (e *spEnv) api(method, path string, body any) (int, []byte) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	w := e.do(method, path, rd, "application/json")
	return w.Code, w.Body.Bytes()
}

func (e *spEnv) formData() statusFormData {
	e.mu.Lock()
	defer e.mu.Unlock()
	d, ok := e.data.(statusFormData)
	if !ok {
		e.t.Fatalf("no form data (page %s)", e.page)
	}
	return d
}

func (e *spEnv) audited(action string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, a := range e.audit {
		if strings.HasPrefix(a, action+" ") {
			return true
		}
	}
	return false
}

// check legt einen Push-Check an und liefert den Token.
func (e *spEnv) check(name, group string, tags ...string) string {
	e.t.Helper()
	code, b := e.api("POST", "/api/checks", map[string]any{"name": name, "type": "push", "interval_seconds": 60, "tags": tags, "group": group})
	if code != 201 {
		e.t.Fatalf("create check: %d %s", code, b)
	}
	var c struct{ Token string }
	_ = json.Unmarshal(b, &c)
	return c.Token
}

// baseForm: Pflichtfelder des Formulars plus Gruppen/Eintraege aus p.
func baseForm(p *StatusPage) url.Values {
	v := url.Values{"title": {p.Title}, "slug": {p.Slug}, "layout": {"list"}, "theme": {"auto"}, "days": {"90"}, "refresh_sec": {"60"}}
	for gi, g := range p.Groups {
		v.Add("gr_name", g.Name)
		for _, it := range g.Items {
			v.Add("it_g", strconv.Itoa(gi))
			v.Add("it_tok", it.Token)
			v.Add("it_lbl", it.Label)
		}
	}
	return v
}

func TestStatusPagesForm(t *testing.T) {
	e := newSPEnv(t)
	ctx := t.Context()
	a := e.check("Alpha", "Web", "prod")
	b := e.check("Beta", "Web", "prod", "dmz")
	c := e.check("Gamma", "LAN")

	if w := e.do("GET", "/healthchecks/status-pages", nil, ""); w.Code != 200 || e.page != Name+"/status_pages" {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if w := e.do("GET", "/healthchecks/status-pages/new", nil, ""); w.Code != 200 || len(e.formData().Checks) != 3 {
		t.Fatalf("new form: %d", w.Code)
	}
	if d := e.formData(); !d.Page.PublishNode || d.Page.HCGroups {
		t.Fatalf("new form defaults: publish_node %v hc_groups %v", d.Page.PublishNode, d.Page.HCGroups)
	}

	// Gruppe anlegen (nur Formular, nichts gespeichert)
	v := baseForm(&StatusPage{Title: "Meine Dienste"})
	v.Set("op", "gadd")
	v.Set("new_group", "Webseiten")
	if w := e.form("/healthchecks/status-pages/new", v); w.Code != 200 {
		t.Fatalf("gadd: %d", w.Code)
	}
	d := e.formData()
	if !d.Dirty || len(d.Page.Groups) != 1 || d.Page.Groups[0].Name != "Webseiten" {
		t.Fatalf("gadd: %+v", d.Page.Groups)
	}
	if list, _ := e.m.st.StatusPages(ctx); len(list) != 0 {
		t.Fatal("op must not save")
	}
	// alle aus Tag "prod" hinzufuegen, dann eine zweite Gruppe mit Healthchecks-Gruppe "LAN"
	v = baseForm(d.Page)
	v.Set("op", "addtag")
	v.Set("add_tag", "prod")
	v.Set("add_to", "0")
	e.form("/healthchecks/status-pages/new", v)
	d = e.formData()
	if len(d.Page.Groups[0].Items) != 2 {
		t.Fatalf("addtag: %+v", d.Page.Groups)
	}
	v = baseForm(d.Page)
	v.Set("op", "gadd")
	v.Set("new_group", "Heimnetz")
	e.form("/healthchecks/status-pages/new", v)
	d = e.formData()
	if d.AddTo != 1 {
		t.Fatalf("new group should be preselected: %d", d.AddTo)
	}
	v = baseForm(d.Page)
	v.Set("op", "addhcg")
	v.Set("add_hcg", "LAN")
	v.Set("add_to", "1")
	e.form("/healthchecks/status-pages/new", v)
	d = e.formData()
	if len(d.Page.Groups) != 2 || len(d.Page.Groups[1].Items) != 1 || d.Page.Groups[1].Items[0].Token != c {
		t.Fatalf("addhcg: %+v", d.Page.Groups)
	}
	// einzelne Auswahl: schon vorhandene Checks werden nicht doppelt eingetragen
	v = baseForm(d.Page)
	v.Set("op", "add")
	v["add_tok"] = []string{a, c}
	v.Set("add_to", "1")
	e.form("/healthchecks/status-pages/new", v)
	d = e.formData()
	if len(d.Page.Groups[1].Items) != 2 || d.Page.Groups[1].Items[1].Token != a {
		t.Fatalf("add: %+v", d.Page.Groups[1])
	}
	// Reihenfolge: Eintrag hoch, Gruppe runter, Eintrag entfernen
	v = baseForm(d.Page)
	v.Set("op", "iup-1-1")
	e.form("/healthchecks/status-pages/new", v)
	d = e.formData()
	if d.Page.Groups[1].Items[0].Token != a {
		t.Fatalf("iup: %+v", d.Page.Groups[1])
	}
	v = baseForm(d.Page)
	v.Set("op", "gdown-0")
	e.form("/healthchecks/status-pages/new", v)
	d = e.formData()
	if d.Page.Groups[0].Name != "Heimnetz" || d.Page.Groups[1].Name != "Webseiten" {
		t.Fatalf("gdown: %+v", d.Page.Groups)
	}
	v = baseForm(d.Page)
	v.Set("op", "idel-0-0")
	e.form("/healthchecks/status-pages/new", v)
	d = e.formData()
	if len(d.Page.Groups[0].Items) != 1 || d.Page.Groups[0].Items[0].Token != c {
		t.Fatalf("idel: %+v", d.Page.Groups[0])
	}

	// Speichern: Slug aus dem Titel, Anzeigename, Passwort
	d.Page.Groups[1].Items[0].Label = "Shop"
	v = baseForm(d.Page)
	v.Set("enabled", "on")
	v.Set("noindex", "on")
	v.Set("accent_on", "on")
	v.Set("accent", "#ff8800")
	v.Set("password", "geheim123")
	v.Set("hc_groups", "on")
	w := e.form("/healthchecks/status-pages/new", v)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	list, _ := e.m.st.StatusPages(ctx)
	if len(list) != 1 {
		t.Fatalf("pages: %d", len(list))
	}
	p, _ := e.m.st.StatusPage(ctx, list[0].ID)
	if p.Slug != "meine-dienste" || !p.Enabled || p.PublishNode || p.Accent != "#ff8800" || !p.HasPassword || !p.NoIndex || p.PoweredBy || !p.HCGroups {
		t.Fatalf("saved: %+v", p)
	}
	if len(p.Groups) != 2 || p.Groups[1].Name != "Webseiten" || p.Groups[1].Items[0].Token != a || p.Groups[1].Items[0].Label != "Shop" || p.Groups[1].Items[1].Token != b {
		t.Fatalf("groups: %+v", p.Groups)
	}
	if loc := w.Header().Get("Location"); loc != "/healthchecks/status-pages/"+strconv.FormatInt(p.ID, 10)+"/edit" || !e.audited("status_page.create") {
		t.Fatalf("redirect %q / audit %v", loc, e.audit)
	}
	hash := e.m.st.statusPasswordHash(ctx, p.ID)
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("not bcrypt: %q", hash)
	}
	edit := "/healthchecks/status-pages/" + strconv.FormatInt(p.ID, 10) + "/edit"

	// Bearbeiten ohne Passwort-Eingabe: Hash bleibt; Formular zeigt ihn nie
	if w := e.do("GET", edit, nil, ""); w.Code != 200 || e.formData().Page.Password != "" {
		t.Fatalf("edit form: %d", w.Code)
	}
	v = baseForm(p)
	v.Set("title", "Meine Dienste 2")
	if w := e.form(edit, v); w.Code != http.StatusSeeOther || e.m.st.statusPasswordHash(ctx, p.ID) != hash || !e.audited("status_page.update") {
		t.Fatalf("update: %d", w.Code)
	}
	// Feldfehler: Slug ungueltig, Passwort zu kurz
	v.Set("slug", "-x")
	if w := e.form(edit, v); w.Code != http.StatusUnprocessableEntity || e.formData().Errors["slug"] != "hc.status.err.slug" {
		t.Fatalf("bad slug: %d %+v", w.Code, e.formData().Errors)
	}
	v.Set("slug", "meine-dienste")
	v.Set("password", "abc")
	if w := e.form(edit, v); w.Code != http.StatusUnprocessableEntity || e.formData().Errors["password"] != "hc.status.err.password" {
		t.Fatalf("short password: %d", w.Code)
	}
	// Passwort entfernen
	v.Del("password")
	v.Set("password_remove", "on")
	if w := e.form(edit, v); w.Code != http.StatusSeeOther || e.m.st.statusPasswordHash(ctx, p.ID) != "" {
		t.Fatalf("remove password: %d", w.Code)
	}
	// Slug vergeben
	other := &StatusPage{Title: "Andere", Slug: "andere"}
	if err := e.m.saveStatusPage(ctx, other); err != nil {
		t.Fatal(err)
	}
	v = baseForm(p)
	v.Set("slug", "andere")
	if w := e.form(edit, v); w.Code != http.StatusUnprocessableEntity || e.formData().Errors["slug"] != "hc.status.err.slug_taken" {
		t.Fatalf("slug taken: %d", w.Code)
	}
	// Liste zaehlt Eintraege; Vorschau/Bearbeiten unbekannter Seiten 404; Loeschen
	e.do("GET", "/healthchecks/status-pages", nil, "")
	e.mu.Lock()
	ld := e.data.(statusPagesData)
	e.mu.Unlock()
	if len(ld.Pages) != 2 {
		t.Fatalf("list: %+v", ld.Pages)
	}
	for _, r := range ld.Pages {
		if r.ID == p.ID && (r.Items != 3 || r.URL != "") {
			t.Fatalf("row: %+v", r)
		}
	}
	if w := e.do("GET", "/healthchecks/status-pages/9999/edit", nil, ""); w.Code != 404 {
		t.Fatalf("missing: %d", w.Code)
	}
	if w := e.do("GET", "/healthchecks/status-pages/9999/preview", nil, ""); w.Code != 404 {
		t.Fatalf("missing preview: %d", w.Code)
	}
	if w := e.form("/healthchecks/status-pages/"+strconv.FormatInt(other.ID, 10)+"/delete", url.Values{}); w.Code != http.StatusSeeOther || !e.audited("status_page.delete") {
		t.Fatalf("delete: %d", w.Code)
	}
	if _, err := e.m.st.StatusPage(ctx, other.ID); err != ErrStatusPageNotFound {
		t.Fatalf("still there: %v", err)
	}
}

func TestStatusNoticesUI(t *testing.T) {
	e := newSPEnv(t)
	ctx := t.Context()
	p := &StatusPage{Title: "S", Slug: "s1"}
	if err := e.m.saveStatusPage(ctx, p); err != nil {
		t.Fatal(err)
	}
	base := "/healthchecks/status-pages/" + strconv.FormatInt(p.ID, 10) + "/notices"
	if w := e.form(base, url.Values{"title": {""}, "level": {"info"}}); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("empty title: %d", w.Code)
	}
	if w := e.form(base, url.Values{"title": {"Wartung Router"}, "level": {"warning"}, "text": {"heute 22 Uhr"}}); w.Code != http.StatusSeeOther || !e.audited("status_notice.create") {
		t.Fatalf("add: %d", w.Code)
	}
	list, _ := e.m.st.StatusNotices(ctx, p.ID, time.Time{})
	if len(list) != 1 || list[0].Level != "warning" || len(list[0].Updates) != 1 {
		t.Fatalf("notices: %+v", list)
	}
	nid := strconv.FormatInt(list[0].ID, 10)
	if w := e.form(base+"/"+nid+"/update", url.Values{"text": {"erledigt"}, "level": {"info"}, "resolve": {"on"}}); w.Code != http.StatusSeeOther || !e.audited("status_notice.resolve") {
		t.Fatalf("update: %d", w.Code)
	}
	if w := e.do("GET", base, nil, ""); w.Code != 200 {
		t.Fatalf("page: %d", w.Code)
	}
	e.mu.Lock()
	nd := e.data.(statusNoticesData)
	e.mu.Unlock()
	if len(nd.Open) != 0 || len(nd.Resolved) != 1 || len(nd.Resolved[0].Updates) != 2 || nd.Resolved[0].Level != "info" {
		t.Fatalf("after resolve: %+v", nd)
	}
	// Ankuendigung einer anderen Seite: 404
	q := &StatusPage{Title: "Q", Slug: "q1"}
	_ = e.m.saveStatusPage(ctx, q)
	if w := e.form("/healthchecks/status-pages/"+strconv.FormatInt(q.ID, 10)+"/notices/"+nid+"/delete", url.Values{}); w.Code != 404 {
		t.Fatalf("foreign notice: %d", w.Code)
	}
	if w := e.form(base+"/"+nid+"/delete", url.Values{}); w.Code != http.StatusSeeOther || !e.audited("status_notice.delete") {
		t.Fatalf("delete: %d", w.Code)
	}
	if list, _ := e.m.st.StatusNotices(ctx, p.ID, time.Time{}); len(list) != 0 {
		t.Fatalf("not deleted: %+v", list)
	}
}

func TestStatusPagesAPI(t *testing.T) {
	e := newSPEnv(t)
	a := e.check("Alpha", "")
	b := e.check("Beta", "")

	if code, body := e.api("GET", "/api/status-pages", nil); code != 200 || strings.TrimSpace(string(body)) != "[]" {
		t.Fatalf("empty list: %d %s", code, body)
	}
	// Feldfehler 422 mit Feld und Schluessel
	code, body := e.api("POST", "/api/status-pages", map[string]any{"title": "X", "slug": "Bad Slug!"})
	var fe statusAPIError
	_ = json.Unmarshal(body, &fe)
	if code != 422 || fe.Field != "slug" || fe.Key != "hc.status.err.slug" {
		t.Fatalf("422: %d %s", code, body)
	}
	if code, body = e.api("POST", "/api/status-pages", map[string]any{"slug": "abc"}); code != 422 || !strings.Contains(string(body), "hc.status.err.title") {
		t.Fatalf("no title: %d %s", code, body)
	}
	// Anlegen mit Gruppen und Passwort; Standardwerte wie im Formular
	code, body = e.api("POST", "/api/status-pages", map[string]any{"title": "Öffentlich", "enabled": true, "password": "sehrgeheim",
		"groups": []map[string]any{{"name": "Web", "items": []map[string]any{{"token": a, "label": "Shop"}, {"token": b}}}}})
	if code != 201 {
		t.Fatalf("create: %d %s", code, body)
	}
	if strings.Contains(string(body), "sehrgeheim") || strings.Contains(string(body), "$2a$") || strings.Contains(string(body), `"password"`) {
		t.Fatalf("password leaked: %s", body)
	}
	var p StatusPage
	_ = json.Unmarshal(body, &p)
	if p.ID == 0 || p.Slug != "oeffentlich" || !p.HasPassword || !p.NoIndex || !p.PoweredBy || p.Days != 90 || p.RefreshSec != 60 ||
		len(p.Groups) != 1 || len(p.Groups[0].Items) != 2 || p.Groups[0].Items[0].Label != "Shop" {
		t.Fatalf("created: %s", body)
	}
	id := strconv.FormatInt(p.ID, 10)
	// Slug vergeben: 409
	if !p.PublishNode || p.HCGroups {
		t.Fatalf("api defaults: %s", body)
	}
	code, body = e.api("POST", "/api/status-pages", map[string]any{"title": "Nur Proxy", "publish_node": false, "hc_groups": true})
	var q StatusPage
	_ = json.Unmarshal(body, &q)
	if code != 201 || q.PublishNode || !q.HCGroups {
		t.Fatalf("api publish_node false: %d %s", code, body)
	}
	if code, body = e.api("PUT", "/api/status-pages/"+strconv.FormatInt(q.ID, 10), map[string]any{"hc_groups": false}); code != 200 || !strings.Contains(string(body), `"hc_groups":false`) || !strings.Contains(string(body), `"publish_node":false`) {
		t.Fatalf("api put hc_groups: %d %s", code, body)
	}
	if code, body = e.api("POST", "/api/status-pages", map[string]any{"title": "Zwei", "slug": "oeffentlich"}); code != 409 || !strings.Contains(string(body), "slug_taken") {
		t.Fatalf("409: %d %s", code, body)
	}
	// Teil-Update: Gruppen bleiben, Passwort bleibt
	code, body = e.api("PUT", "/api/status-pages/"+id, map[string]any{"layout": "tiles", "accent": "#123456"})
	_ = json.Unmarshal(body, &p)
	if code != 200 || p.Layout != "tiles" || p.Accent != "#123456" || len(p.Groups) != 1 || len(p.Groups[0].Items) != 2 || !p.HasPassword || p.Title != "Öffentlich" {
		t.Fatalf("put: %d %s", code, body)
	}
	if code, body = e.api("PUT", "/api/status-pages/"+id, map[string]any{"accent": "red"}); code != 422 || !strings.Contains(string(body), `"field":"accent"`) {
		t.Fatalf("bad accent: %d %s", code, body)
	}
	// Gruppen ersetzen (ein Eintrag ohne Bezeichnung darf keine alte Bezeichnung erben), Passwort entfernen
	code, body = e.api("PUT", "/api/status-pages/"+id, map[string]any{"password": "-", "groups": []map[string]any{{"name": "Neu", "items": []map[string]any{{"token": b}}}}})
	p = StatusPage{}
	_ = json.Unmarshal(body, &p)
	if code != 200 || p.HasPassword || len(p.Groups) != 1 || p.Groups[0].Name != "Neu" || len(p.Groups[0].Items) != 1 || p.Groups[0].Items[0].Label != "" {
		t.Fatalf("replace groups: %d %s", code, body)
	}
	if code, _ = e.api("GET", "/api/status-pages/"+id, nil); code != 200 {
		t.Fatalf("get: %d", code)
	}
	if code, _ = e.api("GET", "/api/status-pages/999", nil); code != 404 {
		t.Fatalf("get 404: %d", code)
	}
	if code, _ = e.api("PUT", "/api/status-pages/999", map[string]any{"title": "x"}); code != 404 {
		t.Fatalf("put 404: %d", code)
	}
	if code, body = e.api("GET", "/api/status-pages", nil); code != 200 || !strings.Contains(string(body), `"groups":[{`) {
		t.Fatalf("list: %d %s", code, body)
	}

	// Ankuendigungen
	base := "/api/status-pages/" + id + "/notices"
	if code, body = e.api("POST", base, map[string]any{"title": "", "level": "info"}); code != 422 || !strings.Contains(string(body), "hc.status.err.notice") {
		t.Fatalf("notice 422: %d %s", code, body)
	}
	code, body = e.api("POST", base, map[string]any{"title": "Störung DSL", "level": "danger", "text": "Wir sind dran"})
	var n StatusNotice
	_ = json.Unmarshal(body, &n)
	if code != 201 || n.ID == 0 || n.Level != "danger" || len(n.Updates) != 1 {
		t.Fatalf("notice create: %d %s", code, body)
	}
	nid := strconv.FormatInt(n.ID, 10)
	if code, _ = e.api("PUT", base+"/"+nid, map[string]any{"level": "boom"}); code != 422 {
		t.Fatalf("bad level: %d", code)
	}
	code, body = e.api("PUT", base+"/"+nid, map[string]any{"level": "warning", "text": "behoben", "resolve": true})
	n = StatusNotice{}
	_ = json.Unmarshal(body, &n)
	if code != 200 || n.Level != "warning" || n.ResolvedAt.IsZero() || len(n.Updates) != 2 {
		t.Fatalf("notice update: %d %s", code, body)
	}
	if code, body = e.api("GET", base, nil); code != 200 || !strings.Contains(string(body), "Störung DSL") {
		t.Fatalf("notice list: %d %s", code, body)
	}
	if code, _ = e.api("PUT", "/api/status-pages/999/notices/"+nid, map[string]any{"text": "x"}); code != 404 {
		t.Fatalf("notice wrong page: %d", code)
	}
	if code, _ = e.api("DELETE", base+"/"+nid, nil); code != 204 {
		t.Fatalf("notice delete: %d", code)
	}
	if code, _ = e.api("DELETE", base+"/"+nid, nil); code != 404 {
		t.Fatalf("notice delete twice: %d", code)
	}
	if code, _ = e.api("DELETE", "/api/status-pages/"+id, nil); code != 204 || !e.audited("status_page.delete") {
		t.Fatalf("delete: %d", code)
	}
	if code, _ = e.api("DELETE", "/api/status-pages/"+id, nil); code != 404 {
		t.Fatalf("delete twice: %d", code)
	}
}

// fakeView bildet die Methoden der Oberflaeche nach, die die Templates nutzen.
type fakeView struct {
	Data    any
	CSRF    string
	Version string
}

func (fakeView) T(key string, args ...any) string { return key }
func (fakeView) Doc(ref string) template.HTML     { return "" }
func (fakeView) Time(t time.Time) string          { return t.Format(time.RFC3339) }

// Die Templates der Verwaltung lassen sich mit Beispieldaten ausfuehren (Tippfehler fallen sonst erst im Betrieb auf).
func TestStatusPagesTemplates(t *testing.T) {
	funcs := template.FuncMap{"add": func(a, b int) int { return a + b }, "split": strings.Fields}
	p := &StatusPage{ID: 3, Slug: "s", Title: "T", Enabled: true, PublishNode: true, HCGroups: true, Layout: "list", Theme: "auto", Days: 90, RefreshSec: 60, HasPassword: true, HasLogo: true, LogoUpdated: time.Now(),
		Groups: []StatusGroup{{Name: "A", Items: []StatusItem{{Token: "t1"}, {Token: "t2", Label: "L"}}}, {Name: "", Items: []StatusItem{}}}}
	now := time.Now()
	cases := map[string]any{
		"status_pages": statusPagesData{Pages: []statusPageRow{{StatusPage: p, Items: 2, Open: 1, URL: "/status/s", Preview: "/x"}}},
		"status_page_form": statusFormData{Page: p, Edit: true, Dirty: true, Errors: map[string]string{"slug": "x", "groups": "y"}, Error: "e", Names: map[string]string{"t1": "Check 1"}, Checks: []statusCheckOpt{{Token: "t1", Name: "Check 1", Tags: "a,b", Group: "G", OnPage: true, Paused: true}}, Tags: []string{"a"}, HCGroups: []string{"G"}, Layouts: []string{"list", "tiles", "compact"}, Themes: []string{"auto"}, DaysOpts: []int{30, 90}, Items: 2,
			ResCards: []statusResCard{{Kind: "pve", Title: "nav.proxmox", Icon: "bi-hdd-stack", Hint: "h", Systems: []statusResSys{{Name: "lab", Items: []statusResOpt{{ID: "1-0", Value: "1|qemu/100", Name: "vm", Type: "pve.type.qemu"}, {ID: "1-1", Value: "1|node/pve", Name: "pve", Type: "pve.type.node", Token: "t1", OnPage: true}}}, {Name: "leer"}}}}},
		"status_page_notices": statusNoticesData{Page: p, Form: map[string]string{"level": "info"}, Open: []StatusNotice{{ID: 1, Title: "N", Level: "warning", CreatedAt: now, Updates: []StatusNoticeUpdate{{Time: now, Text: "x"}}}}, Resolved: []StatusNotice{{ID: 2, Title: "R", Level: "info", CreatedAt: now, ResolvedAt: now}}},
	}
	for name, data := range cases {
		tpl, err := template.New("root").Funcs(funcs).Parse(`{{template "content" .}}{{block "scripts" .}}{{end}}`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tpl.ParseFS(templateFS, "templates/pages/"+name+".html"); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var buf bytes.Buffer
		if err := tpl.Execute(&buf, fakeView{Data: data, CSRF: "c", Version: "v"}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "status_page_form" && (!strings.Contains(buf.String(), `name="it_tok" value="t1"`) || !strings.Contains(buf.String(), "statuspages.js") || !strings.Contains(buf.String(), "hc.status.hc_groups_active") ||
			!strings.Contains(buf.String(), "/preview/logo?v=") || !strings.Contains(buf.String(), `enctype="multipart/form-data"`) ||
			!strings.Contains(buf.String(), `id="sp-add-pve"`) || !strings.Contains(buf.String(), `name="add_res" value="1|qemu/100"`) || !strings.Contains(buf.String(), "hc.status.res_new") || !strings.Contains(buf.String(), "hc.status.res_none")) {
			t.Fatalf("form output: %s", buf.String())
		}
	}
	// leere Liste und neues Formular
	for name, data := range map[string]any{"status_pages": statusPagesData{}, "status_page_form": statusFormData{Page: newStatusPage()}} {
		tpl := template.Must(template.New("root").Funcs(funcs).Parse(`{{template "content" .}}`))
		template.Must(tpl.ParseFS(templateFS, "templates/pages/"+name+".html"))
		if err := tpl.Execute(io.Discard, fakeView{Data: data}); err != nil {
			t.Fatalf("%s empty: %v", name, err)
		}
	}
}

// multipartForm baut ein Formular mit optionaler Datei im Feld "logo".
func multipartForm(v url.Values, file []byte, name string) (io.Reader, string) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, vals := range v {
		for _, x := range vals {
			_ = mw.WriteField(k, x)
		}
	}
	if name != "" {
		fw, _ := mw.CreateFormFile("logo", name)
		_, _ = fw.Write(file)
	}
	_ = mw.Close()
	return &buf, mw.FormDataContentType()
}

func testPNG() []byte {
	var buf bytes.Buffer
	_ = png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 2, 2)))
	return buf.Bytes()
}

func TestStatusLogoType(t *testing.T) {
	for in, want := range map[string]string{
		string(testPNG()):                           "image/png",
		"\xff\xd8\xff\xe0\x00\x10JFIF\x00":          "image/jpeg",
		"RIFF\x10\x00\x00\x00WEBPVP8 ":              "image/webp",
		`<svg xmlns="http://www.w3.org/2000/svg"/>`: "image/svg+xml",
		"\xef\xbb\xbf \n<?xml version=\"1.0\"?>\n<!-- Logo -->\n<!DOCTYPE svg>\n<svg>": "image/svg+xml",
		"<svgx>":         "",
		"<html><svg>":    "",
		"GIF89a\x01\x00": "",
		"hallo":          "",
		"":               "",
	} {
		got, ok := statusLogoType([]byte(in))
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v, want %q", in[:min(len(in), 20)], got, ok, want)
		}
	}
}

func TestStatusPageLogo(t *testing.T) {
	e := newSPEnv(t)
	ctx := t.Context()
	pngData := testPNG()
	// neue Seite mit Logo
	body, ct := multipartForm(baseForm(&StatusPage{Title: "Logo", Slug: "logo-test"}), pngData, "logo.png")
	if w := e.do("POST", "/healthchecks/status-pages/new", body, ct); w.Code != http.StatusSeeOther || !e.audited("status_page.logo") {
		t.Fatalf("create with logo: %d %s", w.Code, w.Body)
	}
	p, err := e.m.st.StatusPageBySlug(ctx, "logo-test")
	if err != nil || !p.HasLogo || p.LogoUpdated.IsZero() {
		t.Fatalf("logo missing: %+v %v", p, err)
	}
	if data, ctype, _, _ := e.m.st.StatusLogo(ctx, p.ID); ctype != "image/png" || !bytes.Equal(data, pngData) {
		t.Fatalf("stored: %s %d", ctype, len(data))
	}
	edit := "/healthchecks/status-pages/" + strconv.FormatInt(p.ID, 10) + "/edit"
	// falscher Inhalt (Name egal): Fehler am Feld, Logo bleibt
	body, ct = multipartForm(baseForm(p), []byte("kein bild"), "logo.png")
	if w := e.do("POST", edit, body, ct); w.Code != http.StatusUnprocessableEntity || e.formData().Errors["logo"] != "hc.status.err.logo" {
		t.Fatalf("bad logo: %d", w.Code)
	}
	// zu gross
	body, ct = multipartForm(baseForm(p), append([]byte("<svg>"), make([]byte, StatusLogoMax)...), "big.svg")
	if w := e.do("POST", edit, body, ct); w.Code != http.StatusUnprocessableEntity || e.formData().Errors["logo"] != "hc.status.err.logo" {
		t.Fatalf("big logo: %d", w.Code)
	}
	// ohne Datei speichern: Logo bleibt; SVG ersetzt es
	body, ct = multipartForm(baseForm(p), nil, "")
	if w := e.do("POST", edit, body, ct); w.Code != http.StatusSeeOther {
		t.Fatalf("save without file: %d", w.Code)
	}
	if _, ctype, _, _ := e.m.st.StatusLogo(ctx, p.ID); ctype != "image/png" {
		t.Fatalf("logo lost: %q", ctype)
	}
	body, ct = multipartForm(baseForm(p), []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>`), "l.svg")
	if w := e.do("POST", edit, body, ct); w.Code != http.StatusSeeOther {
		t.Fatalf("svg: %d", w.Code)
	}
	if _, ctype, _, _ := e.m.st.StatusLogo(ctx, p.ID); ctype != "image/svg+xml" {
		t.Fatalf("svg type: %q", ctype)
	}
	// Formular zeigt Vorschau und Entfernen
	e.do("GET", edit, nil, "")
	if !e.formData().Page.HasLogo {
		t.Fatal("form without logo")
	}
	// entfernen
	if w := e.form("/healthchecks/status-pages/"+strconv.FormatInt(p.ID, 10)+"/logo/delete", url.Values{}); w.Code != http.StatusSeeOther || !e.audited("status_page.logo_remove") {
		t.Fatalf("remove: %d", w.Code)
	}
	if data, _, _, _ := e.m.st.StatusLogo(ctx, p.ID); data != nil {
		t.Fatal("logo not removed")
	}

	// API
	id := strconv.FormatInt(p.ID, 10)
	put := func(data []byte, ctype string) (int, []byte) {
		w := e.do("PUT", "/api/status-pages/"+id+"/logo", bytes.NewReader(data), ctype)
		return w.Code, w.Body.Bytes()
	}
	if code, b := put(pngData, "image/png"); code != 200 || !strings.Contains(string(b), `"has_logo":true`) || !strings.Contains(string(b), `"logo_updated"`) {
		t.Fatalf("api put: %d %s", code, b)
	}
	if code, _ := put(pngData, ""); code != 200 {
		t.Fatalf("api put without type: %d", code)
	}
	if code, b := put([]byte("text"), "image/png"); code != http.StatusUnsupportedMediaType || !strings.Contains(string(b), "hc.status.err.logo") {
		t.Fatalf("api 415: %d %s", code, b)
	}
	if code, _ := put(pngData, "image/jpeg"); code != http.StatusUnsupportedMediaType {
		t.Fatalf("api type mismatch: %d", code)
	}
	if code, _ := put(append(pngData, make([]byte, StatusLogoMax)...), "image/png"); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("api 413: %d", code)
	}
	if w := e.do("PUT", "/api/status-pages/999/logo", bytes.NewReader(pngData), "image/png"); w.Code != 404 {
		t.Fatalf("api 404: %d", w.Code)
	}
	if code, _ := e.api("DELETE", "/api/status-pages/"+id+"/logo", nil); code != 204 {
		t.Fatalf("api delete: %d", code)
	}
	if code, b := e.api("GET", "/api/status-pages/"+id, nil); code != 200 || !strings.Contains(string(b), `"has_logo":false`) {
		t.Fatalf("api after delete: %d %s", code, b)
	}
}
