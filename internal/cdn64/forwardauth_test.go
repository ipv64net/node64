package cdn64

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
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

// Traefik-Labels: Middleware mit forwardAuth wird zur Zugriffsliste "Traefik: <name>" (Vorlage nach der Adresse), der
// Router fuer den Rueckweg von authentik wird uebergangen; name@file verweist auf eine Liste mit diesem Namen.
func TestDockerTraefikForwardAuth(t *testing.T) {
	ctx := context.Background()
	e, f := dockerEnv(t)
	_ = e.st.SetSetting(ctx, setDockerCert, "http")
	app := &fakeC{id: "c1", name: "app", state: "running", created: 1, nets: map[string]string{"proxy": "172.20.0.5"}, labels: map[string]string{
		"traefik.enable":                                                     "true",
		"traefik.http.routers.app.rule":                                      "Host(`app.example.test`)",
		"traefik.http.routers.app.middlewares":                               "authentik@docker",
		"traefik.http.routers.app-outpost.rule":                              "Host(`app.example.test`) && PathPrefix(`/outpost.goauthentik.io/`)",
		"traefik.http.middlewares.authentik.forwardauth.address":             "http://authentik-server:9000/outpost.goauthentik.io/auth/traefik",
		"traefik.http.middlewares.authentik.forwardauth.authResponseHeaders": "X-authentik-username, X-authentik-groups",
		"traefik.http.services.app.loadbalancer.server.port":                 "8080"}}
	wiki := &fakeC{id: "c2", name: "wiki", state: "running", created: 2, nets: map[string]string{"proxy": "172.20.0.6"}, labels: map[string]string{
		"traefik.http.routers.wiki.rule":                      "Host(`wiki.example.test`)",
		"traefik.http.routers.wiki.middlewares":               "secure-headers@file, sso@file",
		"traefik.http.services.wiki.loadbalancer.server.port": "3000"}}
	f.set(app, wiki)
	dockerOnce(t, e.m)
	if v := viewOf(e.m, "app"); v.HostID == 0 || v.Problem != "" {
		t.Fatalf("app: %+v", v)
	}
	lists, _ := e.m.accessLists(ctx)
	if len(lists) != 1 || lists[0].Name != "Traefik: authentik" || lists[0].Auth != AuthAuthentik || lists[0].Forward.Callback != "/outpost.goauthentik.io/" ||
		!slices.Equal(lists[0].Forward.Headers, []string{"X-authentik-username", "X-authentik-groups"}) {
		t.Fatalf("lists: %+v", lists)
	}
	h, _ := e.m.host(ctx, viewOf(e.m, "app").HostID)
	if h.AccessListID != lists[0].ID {
		t.Fatalf("app host without list: %+v", h)
	}
	// Liste aus dem Label: Auswahl im Formular gesperrt, Speichern in Oberflaeche und API aendert sie nicht
	if e.m.dockerACLFrom(ctx, h) != "Traefik: authentik" {
		t.Fatalf("acl from label: %q", e.m.dockerACLFrom(ctx, h))
	}
	if form := aiRender(t, "host_form.html", e.m.form(ctx, h, false)); !strings.Contains(form, `name="access_list_id" disabled data-docker-acl`) ||
		!strings.Contains(form, "cdn64.docker.form_access") {
		t.Fatal("host form does not lock the access list from the label")
	}
	e.m.g.Flash = func(http.ResponseWriter, *http.Request, string, string) {}
	e.m.g.T = func(_ *http.Request, key string, _ ...any) string { return key }
	e.m.g.Render = func(w http.ResponseWriter, _ *http.Request, st int, _, _ string, _ any) { w.WriteHeader(st) }
	req := httptest.NewRequest("POST", "/cdn64/hosts/x", strings.NewReader(url.Values{"access_list_id": {"0"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", strconv.FormatInt(h.ID, 10))
	rec := httptest.NewRecorder()
	e.m.pageUpdate(rec, req)
	if got, _ := e.m.host(ctx, h.ID); rec.Code != http.StatusSeeOther || got.AccessListID != lists[0].ID {
		t.Fatalf("form changed the label's list: %d %+v", rec.Code, got)
	}
	req = httptest.NewRequest("PUT", "/api/cdn64/hosts/x", strings.NewReader(`{"access_list_id":0}`))
	req.SetPathValue("id", strconv.FormatInt(h.ID, 10))
	rec = httptest.NewRecorder()
	e.m.apiUpdate(rec, req)
	if got, _ := e.m.host(ctx, h.ID); got.AccessListID != lists[0].ID {
		t.Fatalf("api changed the label's list: %d %s %+v", rec.Code, rec.Body.String(), got)
	}
	// sso@file: Liste fehlt -> Host trotzdem, mit Hinweis; mit Liste "sso" wird sie zugewiesen
	if v := viewOf(e.m, "wiki"); v.HostID == 0 || v.Problem != dockerErrAccess || v.ProblemName != "sso" {
		t.Fatalf("wiki: %+v", v)
	}
	sso := &AccessList{Name: "SSO", Auth: AuthAuthelia, Forward: ForwardAuth{Address: "http://authelia:9091/api/authz/forward-auth"}}
	if err := e.m.saveAccessList(ctx, sso, nil); err != nil {
		t.Fatal(err)
	}
	dockerOnce(t, e.m)
	if v := viewOf(e.m, "wiki"); v.Problem != "" {
		t.Fatalf("wiki after list: %+v", v)
	}
	if w, _ := e.m.host(ctx, viewOf(e.m, "wiki").HostID); w.AccessListID != sso.ID {
		t.Fatalf("wiki host without list: %+v", w)
	}
	for addr, want := range map[string]string{"http://a:9091/api/verify?rd=x": AuthAuthelia, "http://p:4180/oauth2/auth": AuthOAuth2, "http://x/check": AuthCustom} {
		if got := fwdKindOf(addr); got != want {
			t.Fatalf("kind of %s: %s", addr, got)
		}
	}
}
