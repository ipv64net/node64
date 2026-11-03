package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Links mit Schraegstrich am Ende (z. B. aus einer Benachrichtigung) fuehren auf die Seite ohne Schraegstrich;
// unbekannte Adressen bleiben 404, "//host/" wird nie zu einem fremden Host, /static/ bleibt wie registriert.
func TestTrailingSlashRedirect(t *testing.T) {
	a := newTestApp(t)
	for _, c := range []struct{ path, want string }{
		{"/login/", "/login"},
		{"/audit/", "/audit"},
		{"/settings/?tab=x", "/settings?tab=x"},
	} {
		rec := httptest.NewRecorder()
		a.s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", c.path, nil))
		if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != c.want {
			t.Fatalf("%s: %d %q, want 301 %q", c.path, rec.Code, rec.Header().Get("Location"), c.want)
		}
	}
	for _, p := range []string{"/gibtsnicht/", "//evil.example/", "/login/"} {
		method := "GET"
		if p == "/login/" {
			method = "POST" // nur GET/HEAD werden umgeleitet
		}
		rec := httptest.NewRecorder()
		a.s.Handler().ServeHTTP(rec, httptest.NewRequest(method, p, nil))
		if rec.Code == http.StatusMovedPermanently {
			t.Fatalf("%s %s: unexpected redirect to %q", method, p, rec.Header().Get("Location"))
		}
	}
}
