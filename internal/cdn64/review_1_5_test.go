package cdn64

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// 1xx (100 Continue, 103 Early Hints) ist nicht der Status der Antwort: Log, Statistik und 5xx-Zaehler sehen den echten.
func TestStatusWriterSkips1xx(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec}
	sw.WriteHeader(http.StatusEarlyHints)
	sw.WriteHeader(http.StatusContinue)
	sw.WriteHeader(http.StatusBadGateway)
	if sw.status != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", sw.status)
	}
}

// Punkt-Segmente (auch "..;", ".. ", "...") abweisen, reine Parameter-Abschnitte (;jsessionid=) nicht.
func TestDotSeg(t *testing.T) {
	for s, want := range map[string]bool{"..": true, ".": true, "..;x": true, ".. ": true, "...": true, "..::$DATA": true,
		";jsessionid=ABC": false, "::x": false, "a.": false, "admin": false, "": false} {
		if dotSeg(s) != want {
			t.Errorf("%q: %v", s, !want)
		}
	}
}

// Leere Abschnitte zaehlen nicht: /\admin und /;x/admin sind beim Ziel /admin (Location-Zugriffsliste nicht umgehbar).
func TestPathKeyEmptySegments(t *testing.T) {
	for in, want := range map[string]string{"/\\admin/": "/admin", "//admin": "/admin", "/;x/admin": "/admin", "/": "/", "/ADMIN/x": "/admin/x"} {
		if got := pathKey(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if !pathIn("/\\admin/", "/admin") || !pathIn("/app/%5C", "/app") || pathIn("/adminx", "/admin") {
		t.Fatal("pathIn")
	}
	for in, want := range map[string]string{"/\\api/x": "x", "/;s=1/api/x": "x", "/api": "", "/api/": "", "/x": "x"} {
		n := 1
		if in == "/x" {
			n = 0
		}
		if got := stripSegs(in, n); got != want {
			t.Errorf("stripSegs(%q): %q, want %q", in, got, want)
		}
	}
}

// Erreichbarkeit abgeschaltet: der Host hat trotzdem ein Ziel (Healthcheck anlegen, verknuepfte Checks zeigen).
func TestHasTargetWithoutProbe(t *testing.T) {
	h := newHost()
	h.Advanced.NoProbe = true
	if !h.hasTarget() || h.probed() {
		t.Fatal("no_probe must keep the target for healthchecks")
	}
}

// Pruefsumme der Label-Kopfzeilen: leer ohne Kopfzeilen, sonst stabil und abhaengig vom Inhalt.
func TestHeaderSum(t *testing.T) {
	if headerSum(nil, nil) != "" {
		t.Fatal("empty")
	}
	a := headerSum([]Header{{Name: "Access-Control-Allow-Origin", Value: "*"}}, nil)
	b := headerSum([]Header{{Name: "Access-Control-Allow-Origin", Value: "https://x"}}, nil)
	if a == "" || a == b || a != headerSum([]Header{{Name: "Access-Control-Allow-Origin", Value: "*"}}, nil) {
		t.Fatalf("sum %q %q", a, b)
	}
}
