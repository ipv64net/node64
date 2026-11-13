package web

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

// Design-Umschalter: ohne Cookie das neue Design (Seitenleiste mit Gruppen), mit node64_design=classic das
// klassische; unbekannte Werte = Standard. Beide laden ihr Stylesheet vor dem gemeinsamen node64.css.
func TestDesignSwitch(t *testing.T) {
	a := newTestApp(t)
	loginAs(t, a, "admin", "sehr geheimes passwort")
	u, _ := url.Parse(a.srv.URL)
	get := func(path string, design *string) string {
		t.Helper()
		if design == nil { // Cookie entfernen
			a.client.Jar.SetCookies(u, []*http.Cookie{{Name: designCookie, Value: "", Path: "/", MaxAge: -1}})
		} else {
			a.client.Jar.SetCookies(u, []*http.Cookie{{Name: designCookie, Value: *design, Path: "/"}})
		}
		resp, body := a.get(t, path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		return body
	}
	str := func(s string) *string { return &s }
	isNew := func(body string) bool {
		return strings.Contains(body, `class="app-shell"`) && strings.Contains(body, `data-design="new"`) &&
			strings.Contains(body, `/static/css/design-new.css?v=test">`+"\n\t"+`<link rel="stylesheet" href="/static/css/node64.css?v=test">`) &&
			!strings.Contains(body, "design-classic.css") && strings.Contains(body, `class="nav-head"`)
	}

	for _, p := range []string{"/settings", "/", "/audit", "/api/docs"} {
		if body := get(p, nil); !isNew(body) {
			t.Fatalf("%s without cookie must render the new design", p)
		}
	}
	neu := get("/settings", str(""))
	if !isNew(neu) {
		t.Fatal("empty cookie must render the new design")
	}
	// Einstellungen: ein Knopf je Design aus der Liste, das aktive ausgewaehlt
	for _, d := range designs {
		if !strings.Contains(neu, `id="ui-design-`+d.Name+`" value="`+d.Key+`"`) || !strings.Contains(neu, `<i class="bi `+d.Icon+`"></i>`) {
			t.Fatalf("design choice %q missing on the settings page", d.Name)
		}
	}
	if !strings.Contains(neu, `id="ui-design-new" value="" checked`) || strings.Contains(neu, `id="ui-design-classic" value="classic" checked`) {
		t.Fatal("new design must be selected")
	}

	alt := get("/settings", str("classic"))
	if strings.Contains(alt, `class="app-shell"`) || !strings.Contains(alt, `class="d-flex app-body"`) || !strings.Contains(alt, `data-design="classic"`) ||
		!strings.Contains(alt, "/static/css/design-classic.css?v=test") || strings.Contains(alt, "design-new.css") ||
		!strings.Contains(alt, "/static/css/node64.css?v=test") || !strings.Contains(alt, `id="ui-design-classic" value="classic" checked`) {
		t.Fatal("classic design not rendered")
	}
	if strings.Count(alt, `class="nav flex-column flex-grow-1 sidebar-nav"`) != 2 {
		t.Fatal("classic design must use the shared navigation (sidebar and offcanvas)")
	}
	for _, p := range []string{"/", "/audit", "/api/docs", "/plans"} {
		if body := get(p, str("classic")); !strings.Contains(body, `class="d-flex app-body"`) {
			t.Fatalf("%s: classic frame missing", p)
		}
	}
	for _, v := range []string{"bogus", "Classic", "new"} {
		if body := get("/settings", str(v)); !isNew(body) {
			t.Fatalf("unknown value %q must fall back to the new design", v)
		}
	}

	// Anmeldeseite: gemeinsames Geruest, Stylesheet je Design
	jar, _ := cookiejar.New(nil)
	anon := &http.Client{Jar: jar}
	for _, d := range designs {
		jar.SetCookies(u, []*http.Cookie{{Name: designCookie, Value: d.Key, Path: "/"}})
		resp, err := anon.Get(a.srv.URL + "/login")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body := string(b)
		if !strings.Contains(body, `class="auth-card card shadow-sm"`) || !strings.Contains(body, "/static/css/"+d.CSS+"?v=test") || strings.Contains(body, "sidebar-nav") {
			t.Fatalf("login page for design %q", d.Name)
		}
	}
}

func TestDesignFor(t *testing.T) {
	if designFor("").Name != "new" || designFor("classic").Name != "classic" || designFor("x").Key != designs[0].Key {
		t.Fatal("designFor")
	}
	seen := map[string]bool{}
	for _, d := range designs {
		if seen["k:"+d.Key] || seen["n:"+d.Name] || d.CSS == "" || d.Label == "" || d.Frame == "" {
			t.Fatalf("design list entry %+v", d)
		}
		seen["k:"+d.Key], seen["n:"+d.Name] = true, true
	}
}
