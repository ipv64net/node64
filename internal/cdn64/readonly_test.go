package cdn64

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Rolle „Nur lesen“: Werte der Request-Header (Host und Locations) werden ***, Namen und Antwort-Header bleiben, der
// Host selbst bleibt unveraendert.
func TestRedactSecrets(t *testing.T) {
	h := newHost()
	h.Advanced.RequestHeaders = []Header{{Name: "Authorization", Value: "Bearer geheim"}}
	h.Advanced.ResponseHeaders = []Header{{Name: "X-Frame-Options", Value: "DENY"}}
	h.Locations = []Location{{Path: "/api", Advanced: &LocationAdvanced{RequestHeaders: []Header{{Name: "X-Token", Value: "t0ken"}}}}, {Path: "/x"}}
	r := h.redactSecrets()
	if got := r.Advanced.RequestHeaders; len(got) != 1 || got[0].Name != "Authorization" || got[0].Value != redactedValue {
		t.Fatalf("host headers: %+v", got)
	}
	if got := r.Locations[0].Advanced.RequestHeaders; len(got) != 1 || got[0].Name != "X-Token" || got[0].Value != redactedValue {
		t.Fatalf("location headers: %+v", got)
	}
	if r.Advanced.ResponseHeaders[0].Value != "DENY" || r.Locations[1].Advanced != nil || r.Locations[1].Path != "/x" {
		t.Fatalf("rest changed: %+v", r)
	}
	if h.Advanced.RequestHeaders[0].Value != "Bearer geheim" || h.Locations[0].Advanced.RequestHeaders[0].Value != "t0ken" {
		t.Fatal("original host changed")
	}
}

// API und Formular: „Nur lesen“ sieht die Namen der Request-Header ohne Werte, Administratoren sehen alles.
func TestReadOnlyHostHeaders(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"ro.test"}, "127.0.0.1", 9, CertNone
	h.Advanced.RequestHeaders = []Header{{Name: "Authorization", Value: "Bearer geheim"}}
	h.Locations = []Location{{Path: "/api", TargetHost: "127.0.0.1", TargetPort: 9,
		Advanced: &LocationAdvanced{RequestHeaders: []Header{{Name: "X-Token", Value: "t0ken"}}}}}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	e.m.g.ReadOnly = func(r *http.Request) bool { return r.Header.Get("X-Test-Role") == "read" }
	var data any
	e.m.g.Render = func(w http.ResponseWriter, _ *http.Request, st int, _, _ string, d any) {
		data = d
		w.WriteHeader(st)
	}
	get := func(path, role string) string {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("X-Test-Role", role)
		rec := httptest.NewRecorder()
		e.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
		return rec.Body.String()
	}
	id := strconv.FormatInt(h.ID, 10)
	for _, p := range []string{"/api/cdn64/hosts", "/api/cdn64/hosts/" + id} {
		body := get(p, "read")
		if strings.Contains(body, "geheim") || strings.Contains(body, "t0ken") || !strings.Contains(body, `"name":"Authorization","value":"***"`) ||
			!strings.Contains(body, `"name":"X-Token","value":"***"`) {
			t.Fatalf("read-only %s: %s", p, body)
		}
		if body := get(p, "admin"); !strings.Contains(body, "Bearer geheim") || !strings.Contains(body, "t0ken") {
			t.Fatalf("admin %s: %s", p, body)
		}
	}
	get("/cdn64/hosts/"+id, "read")
	form := aiRender(t, "host_form.html", data)
	if strings.Contains(form, "geheim") || strings.Contains(form, "t0ken") || !strings.Contains(form, "Authorization: ***") || !strings.Contains(form, "X-Token: ***") {
		t.Fatal("read-only form shows header values")
	}
	get("/cdn64/hosts/"+id, "admin")
	if form := aiRender(t, "host_form.html", data); !strings.Contains(form, "Authorization: Bearer geheim") {
		t.Fatal("admin form misses header values")
	}
	if got, _ := e.m.host(ctx, h.ID); got.Advanced.RequestHeaders[0].Value != "Bearer geheim" {
		t.Fatal("stored host changed")
	}
}
