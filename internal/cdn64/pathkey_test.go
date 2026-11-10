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
	for _, p := range []string{"/secure", "/SECURE", "/Secure/x", "/secure%20", "/secure.", "/secure%09", "/secure;x=1", "/secure%5cx"} {
		if code, _, _ := do(t, c, "GET", "http://var.test"+p); code != 403 {
			t.Errorf("%s: %d, want 403", p, code)
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
