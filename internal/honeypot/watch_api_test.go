package honeypot

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/ipv64api"
)

func (e *watchEnv) doJSON(mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Test-Auth", "1")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// Fruehwarnung ueber die lokale API: wie die Seite (Liste live, normalisiert eintragen, Fehler von ipv64 mit Code,
// loeschen, sofort abrufen), ohne Key 409.
func TestWatchAPI(t *testing.T) {
	e := watchTest(t, true)
	mux := e.mux()
	e.api.networks = []ipv64api.ThreatWatchNetwork{{ID: 1, CIDR: "203.0.113.0/24", Label: "Buero", CreatedAt: "2026-10-19T08:00:00Z"}}

	r := httptest.NewRequest(http.MethodGet, "/api/honeypot/watch", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("guard: %d", w.Code)
	}
	if w := e.doJSON(mux, http.MethodGet, "/api/honeypot/watch", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"cidr":"203.0.113.0/24"`) ||
		!strings.Contains(w.Body.String(), `"limits"`) || !strings.Contains(w.Body.String(), `"state"`) {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if w := e.doJSON(mux, http.MethodPost, "/api/honeypot/watch", `{"cidr":"198.51.100.77/24","label":"Lager"}`); w.Code != 201 || len(e.api.added) != 1 || e.api.added[0] != "198.51.100.0/24|Lager" {
		t.Fatalf("add: %d %s %v", w.Code, w.Body, e.api.added)
	}
	if e.audit[len(e.audit)-1].action != "honeypot.watch.add" {
		t.Fatalf("audit: %+v", e.audit)
	}
	for in, code := range map[string]string{`{"cidr":"192.168.1.0/24"}`: "not_public", `{"cidr":"x"}`: "invalid_cidr", `{"cidr":"192.0.2.0/24","label":"` + strings.Repeat("a", 65) + `"}`: "label"} {
		if w := e.doJSON(mux, http.MethodPost, "/api/honeypot/watch", in); w.Code != 422 || !strings.Contains(w.Body.String(), `"error":"`+code+`"`) {
			t.Fatalf("%s: %d %s", in, w.Code, w.Body)
		}
	}
	if w := e.doJSON(mux, http.MethodPost, "/api/honeypot/watch", `{"cidr":"192.0.2.0/24","x":1}`); w.Code != 400 {
		t.Fatalf("unknown field: %d", w.Code)
	}
	e.api.addStatus, e.api.addCode = http.StatusForbidden, "limit_reached"
	if w := e.doJSON(mux, http.MethodPost, "/api/honeypot/watch", `{"cidr":"192.0.2.0/24"}`); w.Code != 403 || !strings.Contains(w.Body.String(), `"error":"limit_reached"`) {
		t.Fatalf("limit: %d %s", w.Code, w.Body)
	}
	e.api.addStatus = 0
	if w := e.doJSON(mux, http.MethodDelete, "/api/honeypot/watch/1", ""); w.Code != 204 || len(e.api.deleted) != 1 {
		t.Fatalf("delete: %d %v", w.Code, e.api.deleted)
	}
	if w := e.doJSON(mux, http.MethodDelete, "/api/honeypot/watch/1", ""); w.Code != 404 {
		t.Fatalf("delete again: %d", w.Code)
	}
	if w := e.doJSON(mux, http.MethodDelete, "/api/honeypot/watch/abc", ""); w.Code != 400 {
		t.Fatalf("bad id: %d", w.Code)
	}
	if w := e.doJSON(mux, http.MethodPost, "/api/honeypot/watch/check", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"new_hits"`) {
		t.Fatalf("check: %d %s", w.Code, w.Body)
	}

	n := watchTest(t, false)
	nm := n.mux()
	for _, c := range [][3]string{{http.MethodGet, "/api/honeypot/watch", ""}, {http.MethodPost, "/api/honeypot/watch", `{"cidr":"192.0.2.0/24"}`},
		{http.MethodDelete, "/api/honeypot/watch/1", ""}, {http.MethodPost, "/api/honeypot/watch/check", ""}} {
		if w := n.doJSON(nm, c[0], c[1], c[2]); w.Code != 409 || !strings.Contains(w.Body.String(), "no_key") {
			t.Fatalf("%s %s without key: %d %s", c[0], c[1], w.Code, w.Body)
		}
	}
}
