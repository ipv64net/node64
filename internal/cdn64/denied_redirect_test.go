package cdn64

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Weiterleitung bei verweigertem Zugriff (#55): abgewiesen -> 302 (nie ans Ziel), erlaubt -> Ziel, Anmeldung noetig ->
// keine Weiterleitung, ohne Ziel -> Fehlerseite wie bisher.
func TestLocationDeniedRedirect(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin") { // nicht die Erreichbarkeitspruefung des Ziels
			hits.Add(1)
		}
		_, _ = io.WriteString(w, "ziel "+r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	lan := &AccessList{Name: "nur lan", Rules: []AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}} // Test-Client ist 127.0.0.1
	local := &AccessList{Name: "lokal", Rules: []AccessRule{{Action: "allow", CIDR: "127.0.0.0/8"}}}
	login := &AccessList{Name: "Login", LoginPage: true}
	basic := &AccessList{Name: "Basic"}
	for _, a := range []*AccessList{lan, local} {
		if err := e.m.saveAccessList(ctx, a, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []*AccessList{login, basic} {
		if err := e.m.saveAccessList(ctx, a, []UserInput{{Username: "anna", Password: "geheim123"}}); err != nil {
			t.Fatal(err)
		}
	}
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"vault.test"}, "127.0.0.1", port, CertNone
	loc := func(p string, acl int64, to string) Location {
		return Location{Path: p, TargetHost: "127.0.0.1", TargetPort: port, AccessListID: acl, DeniedRedirect: to}
	}
	h.Locations = []Location{loc("/admin", lan.ID, " https://vault.test/ "), loc("/lan", local.ID, "/"), loc("/login", login.ID, "/"),
		loc("/basic", basic.ID, "/"), loc("/plain", lan.ID, ""), {Path: "/fest", Action: LocRespond, Body: "ok", AccessListID: lan.ID, DeniedRedirect: "/?von=fest"}}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.m.host(ctx, h.ID); got.Locations[0].DeniedRedirect != "https://vault.test/" {
		t.Fatalf("stored: %q", got.Locations[0].DeniedRedirect)
	}
	c := e.client(false)
	code, _, hd := do(t, c, "GET", "http://vault.test/admin/diagnostics")
	if code != http.StatusFound || hd.Get("Location") != "https://vault.test/" || hd.Get("Cache-Control") != "no-store" {
		t.Fatalf("denied: %d %v", code, hd)
	}
	if code, _, hd = do(t, c, "GET", "http://vault.test/fest"); code != http.StatusFound || hd.Get("Location") != "/?von=fest" {
		t.Fatalf("denied fixed response: %d %v", code, hd)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("denied request reached the target %d times", n)
	}
	if code, body, _ := do(t, c, "GET", "http://vault.test/lan/x"); code != 200 || body != "ziel /lan/x" {
		t.Fatalf("allowed: %d %q", code, body)
	}
	if code, body, hd := do(t, c, "GET", "http://vault.test/login/x"); code != http.StatusUnauthorized || hd.Get("Location") != "" ||
		!strings.Contains(body, `name="list"`) {
		t.Fatalf("login page must stay: %d %v %.100s", code, hd, body)
	}
	if code, _, hd = do(t, c, "GET", "http://vault.test/basic/x"); code != http.StatusUnauthorized || hd.Get("WWW-Authenticate") == "" || hd.Get("Location") != "" {
		t.Fatalf("basic auth must stay: %d %v", code, hd)
	}
	if code, _, hd = do(t, c, "GET", "http://vault.test/basic/x", "Authorization", "Basic YW5uYTpnZWhlaW0xMjM="); code != 200 {
		t.Fatalf("basic auth ok: %d %v", code, hd)
	}
	if code, _, hd = do(t, c, "GET", "http://vault.test/plain/x"); code != http.StatusForbidden || hd.Get("Location") != "" {
		t.Fatalf("without redirect: %d %v", code, hd)
	}

	// Grund im Zugriffs-Log
	got, _ := e.m.host(ctx, h.ID)
	reject := new(string)
	req := httptest.NewRequest(http.MethodGet, "http://vault.test/admin", nil)
	req = req.WithContext(context.WithValue(context.WithValue(req.Context(), ctxClientKey{}, netipMust("203.0.113.5")), ctxRejectKey{}, reject))
	rec := httptest.NewRecorder()
	if e.m.allowedOr(rec, req, got, lan.ID, "/") || rec.Code != http.StatusFound || *reject != rejACLRedirect {
		t.Fatalf("reason: %d %q", rec.Code, *reject)
	}
}

func TestDeniedRedirectTargets(t *testing.T) {
	for _, s := range []string{"", "/", "/x?y=1#z", "https://vault.example.com/", "HTTP://vault.example.com:8443/a?b=c", "http://[2001:db8::1]/"} {
		if _, ok := cleanDeniedRedirect(s); !ok {
			t.Errorf("valid %q rejected", s)
		}
	}
	for _, s := range []string{"//evil.example", "/\\evil.example", "admin", "javascript:alert(1)", "ftp://x.example/", "https://",
		"https://user@evil.example/", "/a b", "/a\nb", "/a\x00", "/a\tb", "https:/x", "mailto:a@b.example", "/" + strings.Repeat("a", 500)} {
		if _, ok := cleanDeniedRedirect(s); ok {
			t.Errorf("invalid %q accepted", s)
		}
	}
	// Schleifen werden beim Speichern abgelehnt
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	for i, locs := range [][]Location{
		{{Path: "/admin", Action: LocBlock, AccessListID: 0, DeniedRedirect: "/admin/x"}},
		{{Path: "/admin", Action: LocBlock, DeniedRedirect: "https://VAULT.test/admin"}},
		{{Path: "/a", Action: LocBlock, DeniedRedirect: "/b/c"}, {Path: "/b", Action: LocBlock, DeniedRedirect: "/a"}},
		{{Path: "/a", Action: LocBlock, DeniedRedirect: "bad"}},
	} {
		h := newHost()
		h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"vault.test"}, "127.0.0.1", 9, CertNone
		h.Locations = locs
		var fe *FieldError
		if err := e.m.saveHost(ctx, h); !errors.As(err, &fe) || fe.Field != "locations" {
			t.Errorf("case %d: %v", i, err)
		}
	}
	for i, locs := range [][]Location{
		{{Path: "/admin", Action: LocBlock, DeniedRedirect: "/"}},
		{{Path: "/admin", Action: LocBlock, DeniedRedirect: "/administrator"}},
		{{Path: "/admin", Action: LocBlock, DeniedRedirect: "https://other.test/admin"}},
		{{Path: "/a", Action: LocBlock, DeniedRedirect: "/b"}, {Path: "/b", Action: LocBlock}},
	} {
		h := newHost()
		h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"vault.test"}, "127.0.0.1", 9, CertNone
		h.Names[0] = strings.Replace(h.Names[0], "vault", "ok"+string(rune('a'+i)), 1)
		h.Locations = locs
		if err := e.m.saveHost(ctx, h); err != nil {
			t.Errorf("ok case %d: %v", i, err)
		}
	}
}
