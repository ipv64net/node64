package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Eingeklappte Seitenleiste: Cookie node64_nav=mini liefert die Seite gleich eingeklappt aus (ohne Flackern).
func TestNavMiniCookie(t *testing.T) {
	a := newTestApp(t)
	loginAs(t, a, "admin", "sehr geheimes passwort")
	_, body := a.get(t, "/settings")
	if strings.Contains(body, `class="nav-mini"`) || !strings.Contains(body, `id="navToggle"`) || !strings.Contains(body, `<span class="nav-label">`) {
		t.Fatal("default: not expanded or toggle missing")
	}
	u, _ := url.Parse(a.srv.URL)
	a.client.Jar.SetCookies(u, []*http.Cookie{{Name: navCookie, Value: "mini", Path: "/"}})
	if _, body = a.get(t, "/settings"); !strings.Contains(body, `class="nav-mini"`) {
		t.Fatal("cookie mini: page not collapsed")
	}
}
