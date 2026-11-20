package web

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/environment"
	"github.com/ipv64net/node64/internal/store"
)

// jarClient: Browser mit Cookies, ohne Weiterleitungen.
func jarClient(t *testing.T) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// hostRewrite schickt jede Anfrage mit einem anderen Host-Kopf (wie ein Client, der die Node direkt anspricht).
type hostRewrite struct{ host string }

func (h hostRewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Host = h.host
	return http.DefaultTransport.RoundTrip(r)
}

var envStepRe = regexp.MustCompile(`name="step" value="([^"]+)"`)

// envBrowser schickt das Formular der oeffnenden Node (req, cross-site) wie ein Browser an B: ohne die Cookies von B
// (SameSite=Lax), Set-Cookie der Antwort landet aber im Cookie-Jar; die selbst absendende Seite von B (zweiter
// Schritt) geht danach same-site mit Cookies an B. Liefert die letzte Antwort mit Seite.
func envBrowser(t *testing.T, c *http.Client, req *http.Request) (*http.Response, string) {
	t.Helper()
	bare := *c
	bare.Jar = nil
	resp, err := bare.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if c.Jar != nil {
		c.Jar.SetCookies(req.URL, resp.Cookies())
	}
	m := envStepRe.FindStringSubmatch(body)
	if resp.StatusCode != http.StatusOK || m == nil {
		return resp, body
	}
	base := req.URL.Scheme + "://" + req.URL.Host
	req2, _ := http.NewRequest(http.MethodPost, base+envEnterPath, strings.NewReader(url.Values{"step": {m[1]}}.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Origin", base)
	if resp, err = c.Do(req2); err != nil {
		t.Fatal(err)
	}
	return resp, readBody(t, resp)
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// „Nur lesen“ auf A wird auf B nie Administrator – auch nicht ueber Zugangsdaten, die in der begrenzten Sitzung
// angelegt wuerden (API-Key, MCP-Key, Passkey, 2FA, SSO-Verknuepfung, Passwort). Gesperrt gilt auch fuer eine
// Environment-Sitzung mit Administrator-Rolle; Lesen und eigene Einstellungen bleiben.
func TestEnvironmentSessionNoCredentials(t *testing.T) {
	ctx := context.Background()
	a, b := newEnvNode(t, "node-a", "Node A"), newEnvNode(t, "node-b", "Node B")
	a.other, b.other = b, a
	me := loginAs(t, a.app, "admin", "sehr geheimes passwort")
	bu, err := b.app.store.CreateUserWith(ctx, store.NewUser{UID: me.UID, Username: "dennis", PasswordHash: "x", Lang: "de", Timezone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{store.RoleRead, store.RoleAdmin} {
		_ = a.app.store.UpdateUserAdmin(ctx, me.ID, store.UserAdmin{Role: role})
		_, _, tok := openB(t, a, b)
		c := jarClient(t)
		if resp := enter(t, c, b, tok, a.app.srv.URL); resp.Header.Get("Location") != "/" {
			t.Fatalf("%s: enter %d %s", role, resp.StatusCode, resp.Header.Get("Location"))
		}
		resp, _ := c.Get(b.app.srv.URL + "/settings")
		page := readBody(t, resp)
		csrf := csrfOf(t, page)
		for _, p := range []string{"/settings/api-keys", "/settings/mcp/keys", "/settings/2fa/enable", "/settings/2fa/disable", "/settings/password",
			"/settings/login/passkeys/begin", "/settings/login/passkeys/finish", "/settings/login/oidc/link", "/login/password"} {
			resp, err := c.PostForm(b.app.srv.URL+p, url.Values{"_csrf": {csrf}, "name": {"x"}, "code": {"123456"}, "password": {"ein neues langes passwort"}, "password2": {"ein neues langes passwort"}})
			if err != nil {
				t.Fatal(err)
			}
			if body := readBody(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "über Environment geöffneten Sitzung") {
				t.Errorf("%s: POST %s = %d", role, p, resp.StatusCode)
			}
		}
		for _, p := range []string{"/api/keys", "/api/mcp/keys"} {
			req, _ := http.NewRequest(http.MethodPost, b.app.srv.URL+p, strings.NewReader(`{"name":"x"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-CSRF-Token", csrf)
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if body := readBody(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "opened via environment") {
				t.Errorf("%s: POST %s = %d %s", role, p, resp.StatusCode, body)
			}
		}
		if role == store.RoleAdmin { // auch keine Zugangsdaten fuer andere Benutzer und keine Zugaenge fuer andere Nodes
			for _, p := range []string{userAdminPath, userAdminPath + "/" + itoa(bu.ID) + "/password", userAdminPath + "/" + itoa(bu.ID) + "/2fa-reset", "/environment/access"} {
				resp, err := c.PostForm(b.app.srv.URL+p, url.Values{"_csrf": {csrf}, "username": {"neu"}, "name": {"x"}, "user": {bu.UID}, "role": {"admin"},
					"password": {"ein neues langes passwort"}, "password2": {"ein neues langes passwort"}})
				if err != nil {
					t.Fatal(err)
				}
				if body := readBody(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "über Environment geöffneten Sitzung") {
					t.Errorf("admin: POST %s = %d", p, resp.StatusCode)
				}
			}
			for _, p := range []string{"/api/users", "/api/users/" + itoa(bu.ID) + "/password", "/api/environment/access"} {
				req, _ := http.NewRequest(http.MethodPost, b.app.srv.URL+p, strings.NewReader(`{"username":"neu","name":"x","role":"admin","password":"ein neues langes passwort"}`))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-CSRF-Token", csrf)
				resp, err := c.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				if body := readBody(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "opened via environment") {
					t.Errorf("admin: POST %s = %d %s", p, resp.StatusCode, body)
				}
			}
			if u, _ := b.app.store.UserByName(ctx, "neu"); u != nil {
				t.Fatal("admin: user created in environment session")
			}
			if acc, _ := b.env.Accesses(ctx); len(acc) != 0 {
				t.Fatal("admin: access created in environment session")
			}
		}
		if keys, _ := b.app.store.APIKeys(ctx, bu.ID); len(keys) != 0 {
			t.Fatalf("%s: api key created", role)
		}
		if keys, _ := b.app.store.MCPKeys(ctx, bu.ID); len(keys) != 0 {
			t.Fatalf("%s: mcp key created", role)
		}
		// Lesen geht, die Seite mit den Keys auch
		if resp, _ := c.Get(b.app.srv.URL + "/settings/api-keys"); resp.StatusCode == http.StatusForbidden {
			t.Fatalf("%s: reading denied", role)
		}
	}
	// normale Anmeldung auf B: Key anlegen geht weiterhin
	hash, _ := HashPassword("noch ein geheimes passwort")
	_ = b.app.store.UpdateUserPassword(ctx, bu.ID, hash)
	c := jarClient(t)
	resp, _ := c.Get(b.app.srv.URL + "/login")
	page := readBody(t, resp)
	if resp, _ := c.PostForm(b.app.srv.URL+"/login", url.Values{"_csrf": {csrfOf(t, page)}, "username": {"dennis"}, "password": {"noch ein geheimes passwort"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	resp, _ = c.Get(b.app.srv.URL + "/settings")
	page = readBody(t, resp)
	if resp, _ := c.PostForm(b.app.srv.URL+"/settings/api-keys", url.Values{"_csrf": {csrfOf(t, page)}, "name": {"x"}}); resp.StatusCode == http.StatusForbidden {
		t.Fatal("normal session may not create keys")
	}
	if keys, _ := b.app.store.APIKeys(ctx, bu.ID); len(keys) != 1 {
		t.Fatal("key in normal session")
	}

	// Pflichten auf B offen (Passwort beim ersten Anmelden): keine Environment-Anmeldung, sondern Anmeldeseite
	_ = b.app.store.SetUserMustChange(ctx, bu.ID, true)
	_, _, tok := openB(t, a, b)
	if resp := enter(t, jarClient(t), b, tok, a.app.srv.URL); resp.Header.Get("Location") != "/login?env=1" {
		t.Fatalf("must change: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// Login-CSRF ueber den Host-Header: Ein Konto auf A schickt "Open" mit frei gewaehltem Host; der Rueckweg im Ticket
// ist dann nicht die bekannte Adresse von A, B legt ohne Bestaetigung (eigenes CSRF-Token) keine Sitzung an.
func TestEnvironmentHostHeader(t *testing.T) {
	ctx := context.Background()
	a, b := newEnvNode(t, "node-a", "Node A"), newEnvNode(t, "node-b", "Node B")
	a.other, b.other = b, a
	me := loginAs(t, a.app, "admin", "sehr geheimes passwort")
	if _, err := b.app.store.CreateUserWith(ctx, store.NewUser{UID: me.UID, Username: "dennis", PasswordHash: "x", Lang: "de", Timezone: "UTC"}); err != nil {
		t.Fatal(err)
	}
	// der Angreifer spricht A direkt mit Host: evil.example an (Anmeldung, Liste, Oeffnen)
	evil := jarClient(t)
	evil.Transport = hostRewrite{"evil.example"}
	resp, _ := evil.Get(a.app.srv.URL + "/login")
	page := readBody(t, resp)
	if resp, _ := evil.PostForm(a.app.srv.URL+"/login", url.Values{"_csrf": {csrfOf(t, page)}, "username": {"admin"}, "password": {"sehr geheimes passwort"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login with foreign host: %d", resp.StatusCode)
	}
	resp, _ = evil.Get(a.app.srv.URL + "/environment")
	page = readBody(t, resp)
	resp, err := evil.PostForm(a.app.srv.URL+"/environment/open/node-b", url.Values{"_csrf": {csrfOf(t, page)}})
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	m := envTicketRe.FindStringSubmatch(body)
	if m == nil || !strings.Contains(resp.Header.Get("Content-Security-Policy"), b.app.srv.URL) {
		t.Fatalf("no ticket (%d)", resp.StatusCode)
	}
	// das Opfer schickt das Ticket von evil.example aus an B: nur die Bestaetigungsseite, keine Sitzung
	victim := jarClient(t)
	req, _ := http.NewRequest(http.MethodPost, b.app.srv.URL+envEnterPath, strings.NewReader(url.Values{"ticket": {m[1]}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://evil.example")
	if resp, body := envBrowser(t, victim, req); resp.StatusCode != http.StatusOK || !strings.Contains(body, `id="env-confirm"`) || !strings.Contains(body, "dennis") {
		t.Fatalf("no confirmation: %d", resp.StatusCode)
	}
	if resp, _ := victim.Get(b.app.srv.URL + "/settings"); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Fatalf("session without confirmation: %d", resp.StatusCode)
	}
	// Bestaetigen von fremder Seite (ohne CSRF-Token von B) geht nicht
	if resp, _ := victim.PostForm(b.app.srv.URL+"/environment/confirm", url.Values{}); resp.StatusCode == http.StatusSeeOther && resp.Header.Get("Location") == "/" {
		t.Fatal("confirmed without csrf token")
	}
	if resp, _ := victim.Get(b.app.srv.URL + "/settings"); resp.StatusCode != http.StatusSeeOther {
		t.Fatal("session after forged confirmation")
	}
	// ueber die bekannte Adresse von A: ohne Bestaetigung
	_, _, tok := openB(t, a, b)
	if resp := enter(t, jarClient(t), b, tok, a.app.srv.URL); resp.Header.Get("Location") != "/" {
		t.Fatalf("trusted back: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// Ein widerrufener Schluessel zaehlt nicht bei jedem Seitenaufruf als Fehlversuch (A merkt sich die Ablehnung), und
// Fehlversuche eines Schluessels bremsen keinen anderen, gueltigen Schluessel derselben Node.
func TestEnvironmentRevokedKeyQuiet(t *testing.T) {
	ctx := context.Background()
	a, b := newKeyNode(t, "node-a-000001", "Node A", 0), newKeyNode(t, "node-b-000001", "Node B", 0)
	me := loginAs(t, a.app, "admin", "sehr geheimes passwort")
	bu, _ := b.app.store.CreateUserWith(ctx, store.NewUser{Username: "dennis", PasswordHash: "x", Lang: "de", Timezone: "UTC"})
	_, key1, err := b.env.CreateAccess(ctx, "eins", bu.UID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_, key2, _ := b.env.CreateAccess(ctx, "zwei", bu.UID, "admin")
	n1, _ := a.env.AddNode(ctx, environment.NodeInput{URL: b.tls.URL, Key: key1, Name: "Eins"}, me.UID)
	n2, _ := a.env.AddNode(ctx, environment.NodeInput{URL: b.tls.URL, Key: key2, Name: "Zwei"}, me.UID)
	if _, page := a.app.get(t, "/environment"); strings.Count(page, "mit meinem Benutzer") != 2 {
		t.Fatal("both keys valid")
	}
	acc, _ := b.env.Accesses(ctx)
	for _, x := range acc {
		if x.Name == "eins" {
			_, _ = b.env.RevokeAccess(ctx, x.ID)
		}
	}
	// Oeffnen merkt die Ablehnung; danach fragt die Liste B nicht bei jedem Aufruf neu
	if _, err := a.env.RequestRemoteTicket(ctx, n1, me.UID, store.RoleAdmin, a.app.srv.URL+"/environment"); err == nil {
		t.Fatal("ticket with revoked key")
	}
	for range 8 {
		if _, page := a.app.get(t, "/environment"); !strings.Contains(page, "Zugangsschlüssel abgelehnt") {
			t.Fatal("denial not shown")
		}
	}
	entries, _ := b.app.store.AuditList(ctx, 100, 0)
	denied := 0
	for _, e := range entries {
		if e.Action == "environment.ticket_denied" {
			denied++
		}
	}
	if denied != 1 {
		t.Fatalf("failed attempts on B: %d", denied)
	}
	// viele Fehlversuche mit dem widerrufenen Schluessel: der gueltige geht weiter
	for range 7 {
		a.env.Status(ctx, n1)
	}
	if st := a.env.Status(ctx, n1); !strings.Contains(st.KeyErr, "too many") {
		t.Fatalf("revoked key not limited: %+v", st)
	}
	if st := a.env.Status(ctx, n2); !st.KeyOK {
		t.Fatalf("valid key limited by another key: %+v", st)
	}
	if _, err := a.env.RequestRemoteTicket(ctx, n2, me.UID, store.RoleAdmin, a.app.srv.URL+"/environment"); err != nil {
		t.Fatalf("valid key: %v", err)
	}
}
