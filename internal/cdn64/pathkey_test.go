package cdn64

import (
	"context"
	"errors"
	"testing"
)

// Location-Pfade gelten auch fuer Schreibvarianten, die das Ziel wie den Pfad behandeln koennte (Sicherheits-Review
// 2026-11-10): /SECURE, "/secure ", /secure., /secure;x, /secure\x.
func TestPathInVariants(t *testing.T) {
	for _, p := range []string{"/secure", "/SECURE", "/Secure/x", "/secure ", "/secure.", "/secure\t", "/secure;jsessionid=1",
		"/secure::$DATA", `/secure\x`, "/secure./x", "/SeCuRe /x"} {
		if !pathIn(p, "/secure") {
			t.Errorf("%q not under /secure", p)
		}
	}
	for _, p := range []string{"/securex", "/secur", "/other/secure", "/sec.ure"} {
		if pathIn(p, "/secure") {
			t.Errorf("%q under /secure", p)
		}
	}
	if !pathIn("/Admin/Panel", "/admin/panel") || pathIn("/admin", "/admin/panel") {
		t.Fatal("nested prefix")
	}
}

// Ende zu Ende: Sperr-Location greift fuer die Varianten, das Ziel bekommt den Pfad unveraendert.
func TestLocationPathVariants(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	port, _ := pathBackend(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"var.test"}, "127.0.0.1", port, CertNone
	h.Locations = []Location{{Path: "/secure", Action: LocBlock}, {Path: "/api", TargetHost: "127.0.0.1", TargetPort: port}}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)
	for _, p := range []string{"/secure", "/SECURE", "/Secure/x", "/secure%20", "/secure.", "/secure%09", "/secure;x=1", "/secure%5cx", "/%5Csecure/", "/%5csecure", "/;x/secure"} {
		if code, _, _ := do(t, c, "GET", "http://var.test"+p); code != 403 {
			t.Errorf("%s: %d, want 403", p, code)
		}
	}
	for _, p := range []string{"/securex", "/app/;jsessionid=ABC", "/;jsessionid=ABC"} { // reine Parameter-Abschnitte: kein 400
		if code, _, _ := do(t, c, "GET", "http://var.test"+p); code != 200 {
			t.Errorf("%s: %d, want 200", p, code)
		}
	}
	if code, _, _ := do(t, c, "GET", "http://var.test/securex"); code != 200 {
		t.Errorf("/securex: %d, want 200", code)
	}
	if _, got, _ := getJSON(t, c, "http://var.test/API/v1"); got["path"] != "/API/v1" {
		t.Fatalf("location target must get the path unchanged: %v", got)
	}
}

// /API und /api sind dieselbe Location: doppelt wird beim Speichern abgelehnt.
func TestLocationDupByKey(t *testing.T) {
	list := []Location{{Path: "/api", TargetHost: "nas", TargetPort: 80}, {Path: "/API", TargetHost: "nas", TargetPort: 81}}
	var fe *FieldError
	if err := normalizeLocations(list); !errors.As(err, &fe) || fe.Key != "cdn64.err.location_dup" {
		t.Fatalf("dup by key: %v", err)
	}
}

// Location mit Pfad beim Ziel: der Rest hinter der Location kommt auch bei Schreibvarianten richtig an, und Formen von
// ".." (..;, ".. ", ...) werden abgewiesen statt aus dem Pfad beim Ziel heraus zu fuehren (Review b3f1c000).
func TestLocationForwardVariants(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	port, _ := pathBackend(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"fw.test"}, "127.0.0.1", port, CertNone
	h.Locations = []Location{{Path: "/api", TargetHost: "127.0.0.1", TargetPort: port, ForwardPath: "/v1"}}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)
	for in, want := range map[string]string{"/api/x": "/v1/x", "/API/x": "/v1/x", "/api./x": "/v1/x", "/api%5cx": "/v1/x", "/Api/a/b/": "/v1/a/b/", "/api../x": "/v1/x", "/%5Capi/x": "/v1/x", "/;s=1/api/x": "/v1/x"} {
		if _, got, _ := getJSON(t, c, "http://fw.test"+in); got["path"] != want {
			t.Errorf("%s: %v, want %s", in, got["path"], want)
		}
	}
	for _, in := range []string{"/api/..;/x", "/api/..%20/x", "/api/.../x"} {
		if code, _, _ := do(t, c, "GET", "http://fw.test"+in); code != 400 {
			t.Errorf("%s: %d, want 400", in, code)
		}
	}
}

// Altbestand mit /admin und /Admin (gleicher key): buchstabengenau gewinnt, sonst die strengere Route.
func TestPickRouteSameKey(t *testing.T) {
	routes := []route{{prefix: "/Admin", key: "/admin"}, {prefix: "/admin", key: "/admin", strict: true}, {prefix: ""}}
	if r := pickRoute(routes, "/admin/x"); r.prefix != "/admin" {
		t.Fatalf("exact: %s", r.prefix)
	}
	if r := pickRoute(routes, "/Admin"); r.prefix != "/Admin" {
		t.Fatalf("exact other: %s", r.prefix)
	}
	if r := pickRoute(routes, "/ADMIN"); r.prefix != "/admin" {
		t.Fatalf("variant must take the strict route: %s", r.prefix)
	}
	if !pathIn("/ſecure", "/secure") {
		t.Fatal("U+017F folds to s")
	}
}
