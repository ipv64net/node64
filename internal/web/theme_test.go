package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Farbschema "System": theme.js steht im head (vor dem ersten Zeichnen, CSP erlaubt nur eigene Dateien); mit Cookie
// setzt der Server data-bs-theme und laedt es nicht (#124).
func TestThemeEarlyInHead(t *testing.T) {
	a := newTestApp(t)
	resp, body := a.get(t, "/setup")
	head, _, _ := strings.Cut(body, "</head>")
	if resp.StatusCode != http.StatusOK || !strings.Contains(head, `<script src="/static/js/theme.js?v=test"></script>`) || strings.Contains(head, "data-bs-theme") {
		t.Fatalf("auto: %d\n%s", resp.StatusCode, head)
	}
	if resp, js := a.get(t, "/static/js/theme.js"); resp.StatusCode != http.StatusOK || !strings.Contains(js, "prefers-color-scheme") {
		t.Fatalf("theme.js: %d", resp.StatusCode)
	}
	u, _ := url.Parse(a.srv.URL)
	a.client.Jar.SetCookies(u, []*http.Cookie{{Name: themeCookie, Value: "dark", Path: "/"}})
	_, body = a.get(t, "/setup")
	head, _, _ = strings.Cut(body, "</head>")
	if !strings.Contains(head, `data-bs-theme="dark"`) || strings.Contains(head, "theme.js") {
		t.Fatalf("dark:\n%s", head)
	}
}
