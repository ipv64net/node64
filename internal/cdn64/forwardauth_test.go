package cdn64

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// fakeAuthentik spielt den Anmeldedienst: /outpost.goauthentik.io/auth/traefik prueft das Cookie, ohne Anmeldung
// Weiterleitung zum Start auf dem Host des Besuchers; der Rueckweg antwortet mit dem Host, unter dem er ankam.
func fakeAuthentik(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/outpost.goauthentik.io/auth/traefik":
			if c, err := r.Cookie("ak"); err == nil && c.Value == "ok" {
				w.Header().Set("X-authentik-username", "alice")
				w.Header().Set("X-authentik-email", "alice@example.com")
				w.Header().Set("X-authentik-groups", "admins|users")
				return
			}
			rd := r.Header.Get("X-Forwarded-Proto") + "://" + r.Header.Get("X-Forwarded-Host") + r.Header.Get("X-Forwarded-Uri")
			http.Redirect(w, r, "/outpost.goauthentik.io/start?rd="+url.QueryEscape(rd), http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/outpost.goauthentik.io/"):
			_, _ = w.Write([]byte("callback " + r.Host))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// headerBackend antwortet mit allen Headern, die beim Ziel ankommen.
func headerBackend(t *testing.T) int {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := map[string]string{}
		for k := range r.Header {
			out[k] = r.Header.Get(k)
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	p, _ := strconv.Atoi(u.Port())
	return p
}

func TestForwardAuthAuthentik(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	ak := fakeAuthentik(t)
	port := headerBackend(t)
	key, plain := newAccessKey("Handy-App")
	a := &AccessList{Name: "SSO", Auth: AuthAuthentik, PassUser: true, Keys: []AccessKey{key},
		Forward: ForwardAuth{Address: ak.URL + "/outpost.goauthentik.io/auth/traefik"}}
	if err := e.m.saveAccessList(ctx, a, nil); err != nil {
		t.Fatal(err)
	}
	if a.Forward.Callback != "/outpost.goauthentik.io/" || len(a.Forward.Headers) == 0 || a.Forward.Headers[0] != "X-authentik-username" {
		t.Fatalf("authentik preset not applied: %+v", a.Forward)
	}
	if strings.Contains(mustJSON(a.public()), key.Hash) {
		t.Fatal("public view must not contain key hashes")
	}
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID, h.AccessListID = []string{"sso.test"}, "127.0.0.1", port, CertNone, a.ID
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)

	// nicht angemeldet: Weiterleitung des Dienstes geht an den Besucher, mit der Adresse des Hosts
	code, _, hdr := do(t, c, "GET", "http://sso.test/app?x=1")
	if code != http.StatusFound || !strings.Contains(hdr.Get("Location"), url.QueryEscape("http://sso.test/app?x=1")) {
		t.Fatalf("not signed in: %d %q", code, hdr.Get("Location"))
	}
	// Rueckweg geht ohne Pruefung an den Dienst, mit dem Namen des Hosts
	if code, body, _ := do(t, c, "GET", "http://sso.test/outpost.goauthentik.io/callback?code=1"); code != 200 || body != "callback sso.test" {
		t.Fatalf("callback: %d %q", code, body)
	}
	// angemeldet: Header des Dienstes und Remote-User ans Ziel; vom Besucher gefaelschte Header sind weg
	code, got, _ := getJSON(t, c, "http://sso.test/", "Cookie", "ak=ok", "Remote-User", "admin")
	if code != 200 || got["Remote-User"] != "alice" || got["X-Authentik-Username"] != "alice" || got["Remote-Groups"] != "admins|users" ||
		got["Remote-Email"] != "alice@example.com" {
		t.Fatalf("signed in: %d %v", code, got)
	}
	code, got, _ = getJSON(t, c, "http://sso.test/", "X-Authentik-Username", "admin", "Remote-User", "admin")
	if code != http.StatusFound || got["Remote-User"] != "" {
		t.Fatalf("forged headers must not pass: %d %v", code, got)
	}
	// API-Key: ohne Anmeldung durch, als Name des Keys; der Key geht nicht ans Ziel
	for _, hd := range [][]string{{"Authorization", "Bearer " + plain}, {"X-API-Key", plain}, {"Authorization", basic("app", plain)}} {
		code, got, _ = getJSON(t, c, "http://sso.test/", hd...)
		if code != 200 || got["Remote-User"] != "Handy-App" || got["Authorization"] != "" || got["X-Api-Key"] != "" {
			t.Fatalf("api key %s: %d %v", hd[0], code, got)
		}
	}
	// falscher Key: 401 (zaehlt als Fehlversuch); fremdes Token des Ziels geht zum Anmeldedienst
	if code, _, _ := do(t, c, "GET", "http://sso.test/", "Authorization", "Bearer "+keyPrefix+"falsch"); code != http.StatusUnauthorized {
		t.Fatalf("wrong key: %d", code)
	}
	if code, _, _ := do(t, c, "GET", "http://sso.test/", "Authorization", "Bearer eigenes-token"); code != http.StatusFound {
		t.Fatalf("foreign token: %d", code)
	}
	// Dienst nicht erreichbar: 502
	ak.Close()
	if code, _, _ := do(t, c, "GET", "http://sso.test/", "Cookie", "ak=ok"); code != http.StatusBadGateway {
		t.Fatalf("service down: %d", code)
	}
}

func TestForwardAuthNormalize(t *testing.T) {
	var fe *FieldError
	f := ForwardAuth{Address: "authelia:9091"}
	if err := f.normalize(AuthAuthelia); !errors.As(err, &fe) || fe.Field != "fwd_address" {
		t.Fatalf("address without scheme: %v", err)
	}
	f = ForwardAuth{Address: "http://authelia:9091/api/authz/forward-auth"}
	if err := f.normalize(AuthAuthelia); err != nil || f.Callback != "" || f.Headers[0] != "Remote-User" {
		t.Fatalf("authelia preset: %v %+v", err, f)
	}
	f = ForwardAuth{Address: "http://x/auth", Headers: []string{"Content-Length"}}
	if err := f.normalize(AuthCustom); !errors.As(err, &fe) || fe.Field != "fwd_headers" {
		t.Fatalf("fixed header: %v", err)
	}
	f = ForwardAuth{Address: "http://x/auth", Callback: "auth"}
	if err := f.normalize(AuthCustom); !errors.As(err, &fe) || fe.Field != "fwd_callback" {
		t.Fatalf("callback without slash: %v", err)
	}
	if err := (&ForwardAuth{Address: "http://x/"}).normalize("keycloak"); !errors.As(err, &fe) || fe.Field != "auth" {
		t.Fatalf("unknown kind: %v", err)
	}
}

// Liste nur mit API-Key: ohne Key 401 (Basic Auth als Weg fuer Programme), mit Key durch.
func TestAccessListKeysOnly(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	port := headerBackend(t)
	key, plain := newAccessKey("Skript")
	a := &AccessList{Name: "Keys", Keys: []AccessKey{key}}
	if err := e.m.saveAccessList(ctx, a, nil); err != nil {
		t.Fatal(err)
	}
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID, h.AccessListID = []string{"keys.test"}, "127.0.0.1", port, CertNone, a.ID
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)
	if code, _, _ := do(t, c, "GET", "http://keys.test/"); code != http.StatusUnauthorized {
		t.Fatalf("without key: %d", code)
	}
	if code, got, _ := getJSON(t, c, "http://keys.test/", "X-API-Key", plain); code != 200 || got["Remote-User"] != "" {
		t.Fatalf("with key (no pass_user): %d %v", code, got)
	}
	// geloeschter Key gilt sofort nicht mehr
	a.Keys = nil
	a.Rules = []AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}
	if err := e.m.saveAccessList(ctx, a, nil); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := do(t, c, "GET", "http://keys.test/", "X-API-Key", plain); code != http.StatusForbidden {
		t.Fatalf("removed key: %d", code)
	}
}

// Formular der Zugriffsliste: Anmeldedienst mit Beispiel-Adresse, Bereich des Dienstes sichtbar, Login-Seite verborgen,
// API-Keys nur mit Anfang.
func TestAccessFormForwardAuthRender(t *testing.T) {
	key, _ := newAccessKey("Handy-App")
	a := &AccessList{ID: 3, Name: "SSO", Auth: AuthAuthentik, PassUser: true, Keys: []AccessKey{key},
		Forward: ForwardAuth{Address: "http://authentik-server:9000/outpost.goauthentik.io/auth/traefik", Callback: "/outpost.goauthentik.io/"}}
	body := renderPage(t, "access_form.html", (&Module{}).aclFormData(nil, a.public(), false, ""))
	for _, want := range []string{`name="auth" data-acl-auth`, `value="authentik" data-example="` + fwdPresets[AuthAuthentik].Example + `" selected`,
		`value="http://authentik-server:9000/outpost.goauthentik.io/auth/traefik"`, `name="new_key"`, `value="` + key.Hint + `"`,
		`name="pass_user" id="pass_user" checked`, `d-none" data-login-box`} {
		if !strings.Contains(body, want) {
			t.Fatalf("access form misses %s", want)
		}
	}
	if strings.Contains(body, key.Hash) || strings.Contains(body, `d-none" data-fwd-box`) {
		t.Fatal("access form shows the key hash or hides the service box")
	}
}
