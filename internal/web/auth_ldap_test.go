package web

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/authcfg"
	"github.com/ipv64net/node64/internal/ldapauth/ldaptest"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

const (
	tMaxDN    = "CN=Max Muster,OU=Users,DC=example,DC=org"
	tGUID     = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
	tGUIDHex  = "0102030405060708090a0b0c0d0e0f10"
	tAdminsDN = "CN=Node64 Admins,OU=Groups,DC=example,DC=org"
	tStaffDN  = "CN=Staff,OU=Groups,DC=example,DC=org"
	tOtherDN  = "CN=Other,OU=Groups,DC=example,DC=org"
)

type ldapEnv struct {
	a            *testApp
	dir          *ldaptest.Server
	box          *secrets.Box
	admins, read *store.Group
}

// newLDAPEnv: Node mit lokalem Administrator, zwei Gruppen mit LDAP-Zuordnung und eingeschaltetem AD.
func newLDAPEnv(t *testing.T) *ldapEnv {
	t.Helper()
	ctx := context.Background()
	box, _ := secrets.Load(filepath.Join(t.TempDir(), "secret.key"))
	a := newTestAppDeps(t, func(d *Deps) { d.Box = box })
	hash, _ := HashPassword("sehr geheimes passwort")
	if _, err := a.store.CreateUser(ctx, "admin", hash, "de", "UTC"); err != nil {
		t.Fatal(err)
	}
	f := ldaptest.New(t, false)
	f.Add(tMaxDN, map[string][]string{"objectClass": {"user"}, "sAMAccountName": {"MMuster"}, "userPrincipalName": {"max@example.org"},
		"mail": {"max@example.org"}, "memberOf": {tStaffDN}, "objectGUID": {tGUID}, "userAccountControl": {"512"}, "userPassword": {"ad-passwort-1"}})
	f.Add("CN=Bert,OU=Users,DC=example,DC=org", map[string][]string{"objectClass": {"user"}, "sAMAccountName": {"bert"},
		"memberOf": {tOtherDN}, "objectGUID": {"\xbb\xbb"}, "userPassword": {"ad-passwort-2"}})
	f.Add("CN=Kollege,OU=Users,DC=example,DC=org", map[string][]string{"objectClass": {"user"}, "sAMAccountName": {"kollege"},
		"userPrincipalName": {"kollege@example.org"}, "memberOf": {tStaffDN}, "objectGUID": {"\xcc\xcc"}, "userPassword": {"ad-passwort-3"}})
	f.Add(tStaffDN, map[string][]string{"objectClass": {"group"}, "member": {tMaxDN, "CN=Kollege,OU=Users,DC=example,DC=org"}})
	f.Add(tAdminsDN, map[string][]string{"objectClass": {"group"}, "member": {"CN=Jemand,DC=example,DC=org"}})
	f.Add(tOtherDN, map[string][]string{"objectClass": {"group"}, "member": {"CN=Bert,OU=Users,DC=example,DC=org"}})
	e := &ldapEnv{a: a, dir: f, box: box,
		admins: &store.Group{Name: "Admins", Role: store.RoleAdmin, LDAPGroups: []string{tAdminsDN}},
		read:   &store.Group{Name: "Staff", Role: store.RoleRead, LDAPGroups: []string{"staff"}}} // nur der Name
	for _, g := range []*store.Group{e.admins, e.read} {
		if err := a.store.SaveGroup(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	e.setLDAP(t, true)
	return e
}

func (e *ldapEnv) setLDAP(t *testing.T, on bool) {
	t.Helper()
	cfg := authcfg.LDAPConfig{Enabled: on, URLs: []string{e.dir.URL("ldap")}, AllowPlain: true, Profile: authcfg.ProfileAD,
		BindDN: ldaptest.Service, BindPasswordEnc: e.box.Encrypt(ldaptest.ServicePassword), BaseDN: "dc=example,dc=org", Nested: true, TimeoutSec: 5}
	if err := authcfg.SaveLDAP(context.Background(), e.a.store, cfg); err != nil {
		t.Fatal(err)
	}
}

func (e *ldapEnv) login(t *testing.T, name, pw string) *http.Response {
	t.Helper()
	_, body := e.a.get(t, "/login")
	resp, _ := e.a.post(t, "/login", url.Values{"_csrf": {csrfOf(t, body)}, "username": {name}, "password": {pw}, "next": {"/settings"}})
	return resp
}

// unthrottle leert die Fehlversuche (viele Anmeldungen von derselben Adresse im Test).
func (e *ldapEnv) unthrottle() {
	l := e.a.s.limiter
	l.mu.Lock()
	clear(l.buckets)
	l.mu.Unlock()
}

func (e *ldapEnv) logout(t *testing.T) {
	t.Helper()
	_, body := e.a.get(t, "/settings")
	_, _ = e.a.post(t, "/logout", url.Values{"_csrf": {csrfOf(t, body)}})
}

func (e *ldapEnv) lastAudit(t *testing.T, action string) *store.AuditEntry {
	t.Helper()
	list, _ := e.a.store.AuditList(context.Background(), 200, 0)
	for i := range list {
		if list[i].Action == action {
			return &list[i]
		}
	}
	return nil
}

func TestLDAPLoginCreatesAndUpdatesUser(t *testing.T) {
	e := newLDAPEnv(t)
	ctx := context.Background()
	resp := e.login(t, "MMuster", "ad-passwort-1")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings" {
		t.Fatalf("ldap login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	u, _ := e.a.store.UserByUID(ctx, store.ExternalUID("ldap", tGUIDHex))
	if u == nil || u.Username != "mmuster" || u.Source != store.SourceLDAP || u.Role != store.RoleRead || u.PasswordHash != "" ||
		u.Email != "max@example.org" || !slices.Equal(u.ExtGroupUIDs, []string{e.read.UID}) {
		t.Fatalf("created user: %+v", u)
	}
	if e.a.store.EffectiveRole(ctx, u) != store.RoleRead {
		t.Fatal("role must come from the groups")
	}
	if a := e.lastAudit(t, "login.ldap"); a == nil || a.Actor != "mmuster" || !strings.Contains(a.Details, "created") {
		t.Fatalf("audit: %+v", a)
	}
	// angemeldet; Passwort aendern gibt es fuer LDAP-Benutzer nicht
	resp, body := e.a.get(t, "/settings")
	if resp.StatusCode != 200 || strings.Contains(body, `action="/settings/password"`) {
		t.Fatalf("settings: %d, password form shown", resp.StatusCode)
	}
	resp, _ = e.a.post(t, "/settings/password", url.Values{"_csrf": {csrfOf(t, body)}, "current": {""}, "password": {"neues-passwort-1"}, "password2": {"neues-passwort-1"}})
	if nu, _ := e.a.store.UserByID(ctx, u.ID); resp.StatusCode != http.StatusSeeOther || nu.PasswordHash != "" {
		t.Fatalf("password change for ldap user: %d", resp.StatusCode)
	}
	e.logout(t)

	// zweite Anmeldung: jetzt auch in der Admin-Gruppe (verschachtelt nicht noetig), Benutzer bleibt derselbe
	e.dir.Set(tAdminsDN, "member", tMaxDN)
	e.dir.Set(tMaxDN, "mail", "max.neu@example.org")
	if resp := e.login(t, "max@example.org", "ad-passwort-1"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("second login: %d", resp.StatusCode)
	}
	u2, _ := e.a.store.UserByUID(ctx, u.UID)
	want := []string{e.admins.UID, e.read.UID}
	slices.Sort(want)
	if u2.ID != u.ID || !slices.Equal(u2.ExtGroupUIDs, want) || u2.Email != "max.neu@example.org" || e.a.store.EffectiveRole(ctx, u2) != store.RoleAdmin {
		t.Fatalf("updated user: %+v", u2)
	}
	if n, _ := e.a.store.UserCount(ctx); n != 2 {
		t.Fatalf("users: %d", n)
	}
}

func TestLDAPLoginDenied(t *testing.T) {
	e := newLDAPEnv(t)
	ctx := context.Background()
	// falsches und leeres Passwort
	for _, pw := range []string{"falsch", ""} {
		if resp := e.login(t, "mmuster", pw); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("password %q: %d", pw, resp.StatusCode)
		}
	}
	// keine passende Gruppe
	if resp := e.login(t, "bert", "ad-passwort-2"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no group: %d", resp.StatusCode)
	}
	if a := e.lastAudit(t, "login.ldap_denied"); a == nil || !strings.Contains(a.Details, "group") {
		t.Fatalf("audit: %+v", a)
	}
	// lokaler Benutzer gleichen Namens: nie uebernommen (lokales Passwort gilt, AD-Name wird abgelehnt)
	hash, _ := HashPassword("lokales passwort")
	local, _ := e.a.store.CreateUser(ctx, "kollege", hash, "de", "UTC")
	if resp := e.login(t, "kollege", "ad-passwort-3"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("local name with ad password: %d", resp.StatusCode)
	}
	if resp := e.login(t, "kollege@example.org", "ad-passwort-3"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ad user with local name: %d", resp.StatusCode)
	}
	if a := e.lastAudit(t, "login.ldap_denied"); a == nil || !strings.Contains(a.Details, "taken") {
		t.Fatalf("audit collision: %+v", a)
	}
	if u, _ := e.a.store.UserByName(ctx, "kollege"); u.ID != local.ID || u.Source != store.SourceLocal || u.PasswordHash != hash {
		t.Fatal("local user changed")
	}
	if n, _ := e.a.store.UserCount(ctx); n != 2 {
		t.Fatalf("users: %d", n)
	}
	// in Node64 gesperrt
	e.unthrottle()
	if resp := e.login(t, "mmuster", "ad-passwort-1"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	e.logout(t)
	u, _ := e.a.store.UserByName(ctx, "mmuster")
	_ = e.a.store.UpdateUserAdmin(ctx, u.ID, store.UserAdmin{Role: u.Role, Disabled: true})
	if resp := e.login(t, "mmuster", "ad-passwort-1"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled: %d", resp.StatusCode)
	}
}

func TestLDAPOffLoginUnchanged(t *testing.T) {
	e := newLDAPEnv(t)
	e.setLDAP(t, false)
	_, _, before := e.dir.Stats()
	if resp := e.login(t, "mmuster", "ad-passwort-1"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ldap off: %d", resp.StatusCode)
	}
	if _, _, after := e.dir.Stats(); after != before {
		t.Fatal("directory asked although ldap is off")
	}
	if resp := e.login(t, "admin", "sehr geheimes passwort"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("local login: %d", resp.StatusCode)
	}
	// LDAP an: lokaler Benutzer geht weiter ohne Verzeichnis
	e.logout(t)
	e.setLDAP(t, true)
	_, _, before = e.dir.Stats()
	if resp := e.login(t, "admin", "sehr geheimes passwort"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("local login with ldap on: %d", resp.StatusCode)
	}
	e.logout(t)
	if resp := e.login(t, "admin", "falsch"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("local wrong password: %d", resp.StatusCode)
	}
	if _, _, after := e.dir.Stats(); after != before {
		t.Fatal("directory asked for a local user")
	}
}

func TestOIDCGroupsJIT(t *testing.T) {
	idp := newFakeIdP(t)
	e := newLDAPEnv(t)
	a, ctx := e.a, context.Background()
	if err := a.s.oidcSave(ctx, oidcSettings{Issuer: idp.srv.URL, ClientID: "node64", Secret: "s3cret"}, false); err != nil {
		t.Fatal(err)
	}
	g := &store.Group{Name: "SSO Admins", Role: store.RoleAdmin, OIDCGroups: []string{"node64-admins"}}
	_ = a.store.SaveGroup(ctx, g)
	sso := func(sub string, extra map[string]any) *http.Response {
		idp.mu.Lock()
		idp.extra = extra
		idp.mu.Unlock()
		resp, _ := a.get(t, "/login/oidc?next=/settings")
		resp, _ = a.get(t, idp.authorize(t, resp.Header.Get("Location"), sub))
		return resp
	}
	carol := map[string]any{"preferred_username": "carol", "groups": []string{"x", "Node64-Admins"}}
	// Schalter aus: wie bisher nur verknuepfte Konten
	if resp := sso("carol", carol); resp.Header.Get("Location") != "/login" {
		t.Fatalf("jit off: %s", resp.Header.Get("Location"))
	}
	if n, _ := a.store.UserCount(ctx); n != 1 {
		t.Fatal("user created with jit off")
	}
	// an: Anlage ueber die Gruppe
	if err := a.s.oidcGroupsSet(ctx, true, "groups"); err != nil {
		t.Fatal(err)
	}
	if resp := sso("carol", carol); resp.Header.Get("Location") != "/settings" {
		t.Fatalf("jit on: %s", resp.Header.Get("Location"))
	}
	uid := store.ExternalUID("oidc", idp.srv.URL+"\x00carol")
	u, _ := a.store.UserByUID(ctx, uid)
	if u == nil || u.Username != "carol" || u.Source != store.SourceOIDC || u.Role != store.RoleRead || !slices.Equal(u.ExtGroupUIDs, []string{g.UID}) || u.Email != "carol@example.com" {
		t.Fatalf("created: %+v", u)
	}
	if ids, _ := a.store.Identities(ctx, u.ID); len(ids) != 1 || ids[0].Subject != "carol" {
		t.Fatalf("identity: %+v", ids)
	}
	if e.lastAudit(t, "login.oidc_created") == nil {
		t.Fatal("audit login.oidc_created")
	}
	e.logout(t)
	// Gruppen-Claim als String, Name aus der E-Mail
	if resp := sso("dave", map[string]any{"groups": "node64-admins"}); resp.Header.Get("Location") != "/settings" {
		t.Fatalf("string claim: %s", resp.Header.Get("Location"))
	}
	if u, _ := a.store.UserByName(ctx, "dave"); u == nil || u.Source != store.SourceOIDC {
		t.Fatal("name from email")
	}
	e.logout(t)
	// Name eines lokalen Benutzers: nie uebernommen
	if resp := sso("evil", map[string]any{"preferred_username": "admin", "groups": []string{"node64-admins"}}); resp.Header.Get("Location") != "/login" {
		t.Fatalf("collision: %s", resp.Header.Get("Location"))
	}
	if ids, _ := a.store.Identities(ctx, 1); len(ids) != 0 {
		t.Fatal("identity linked to the local admin")
	}
	// Name klein geschrieben; unzulaessige Zeichen abgelehnt statt ersetzt
	if resp := sso("erin", map[string]any{"preferred_username": "Erin.M", "groups": []string{"node64-admins"}}); resp.Header.Get("Location") != "/settings" {
		t.Fatalf("lowercase: %s", resp.Header.Get("Location"))
	}
	if u, _ := a.store.UserByUID(ctx, store.ExternalUID("oidc", idp.srv.URL+"\x00erin")); u == nil || u.Username != "erin.m" {
		t.Fatalf("name must be lowercased: %+v", u)
	}
	e.logout(t)
	if resp := sso("gina", map[string]any{"preferred_username": "Gina Meier", "groups": []string{"node64-admins"}}); resp.Header.Get("Location") != "/login" {
		t.Fatal("name with space must be rejected")
	}
	// ohne passende Gruppe: nicht angelegt; ueber Gruppen angelegter Benutzer ohne Gruppe: abgelehnt
	if resp := sso("frank", map[string]any{"groups": []string{"x"}}); resp.Header.Get("Location") != "/login" {
		t.Fatal("no group")
	}
	if resp := sso("carol", map[string]any{"preferred_username": "carol", "groups": []string{}}); resp.Header.Get("Location") != "/login" {
		t.Fatal("carol without groups must be denied")
	}
	if u, _ := a.store.UserByUID(ctx, uid); len(u.ExtGroupUIDs) != 0 { // abgelehnt: Rolle aus SSO-Gruppen entfaellt
		t.Fatalf("denied sso login must clear the groups: %v", u.ExtGroupUIDs)
	}
}

func TestLDAPCardAndForms(t *testing.T) {
	e := newLDAPEnv(t)
	a := e.a
	// Karte rendert ohne Passwort (ueber eine vorhandene Seite, partials sind ueberall geparst)
	v := a.s.view(httptest.NewRequest("GET", "/settings/users", nil), "ldap.title")
	var buf bytes.Buffer
	if err := a.s.pages["settings"].ExecuteTemplate(&buf, "ldap_card", v); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	enc := authcfg.LoadLDAP(context.Background(), a.store).BindPasswordEnc
	for _, want := range []string{`action="/settings/users/ldap"`, `formaction="/settings/users/ldap/test"`, `action="/settings/users/oidc-groups"`,
		ldaptest.Service, "sAMAccountName=%s", e.dir.URL("ldap")} {
		if !strings.Contains(html, want) {
			t.Fatalf("card without %q", want)
		}
	}
	if strings.Contains(html, enc) || strings.Contains(html, ldaptest.ServicePassword) {
		t.Fatal("card shows the bind password")
	}

	// Formulare: Speichern (Passwort leer = unveraendert), Test, SSO-Gruppen
	loginAs(t, a, "chef", "sehr geheimes passwort")
	_, body := a.get(t, "/settings")
	csrf := csrfOf(t, body)
	form := url.Values{"_csrf": {csrf}, "enabled": {"1"}, "urls": {e.dir.URL("ldap")}, "allow_plain": {"1"}, "profile": {"ad"},
		"bind_dn": {ldaptest.Service}, "base_dn": {"dc=example,dc=org"}, "nested": {"1"}, "timeout_sec": {"7"}}
	resp, _ := a.post(t, "/settings/users/ldap", form)
	c := authcfg.LoadLDAP(context.Background(), a.store)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != ldapBack || c.TimeoutSec != 7 || c.BindPasswordEnc != enc {
		t.Fatalf("save: %d %s %+v", resp.StatusCode, resp.Header.Get("Location"), c)
	}
	// Test: ungespeicherte Eingaben und Testname bleiben im Formular, gespeichert wird nichts; Enter speichert
	form.Set("probe", "mmuster")
	form.Set("timeout_sec", "9")
	resp, body = a.post(t, "/settings/users/ldap/test", form)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `name="timeout_sec" value="9"`) || !strings.Contains(body, `name="probe" value="mmuster"`) {
		t.Fatalf("test must keep the inputs: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "alert-success") || authcfg.LoadLDAP(context.Background(), a.store).TimeoutSec != 7 {
		t.Fatal("test result or saved state")
	}
	if i, j := strings.Index(body, `action="/settings/users/ldap"`), strings.Index(body, `formaction="/settings/users/ldap/test"`); i < 0 ||
		!strings.Contains(body[i:j], `type="submit"`) {
		t.Fatal("first submit button of the ldap form must save (Enter)")
	}
	form.Set("timeout_sec", "7")
	if x := e.lastAudit(t, "auth.ldap.test"); x == nil || !strings.Contains(x.Details, "found=true") {
		t.Fatalf("test audit: %+v", x)
	}
	form.Set("user_filter", "(uid=x")
	resp, _ = a.post(t, "/settings/users/ldap", form)
	if c2 := authcfg.LoadLDAP(context.Background(), a.store); resp.StatusCode != http.StatusSeeOther || c2.UserFilter != "" {
		t.Fatal("invalid filter must not be saved")
	}
	if resp, _ = a.post(t, "/settings/users/oidc-groups", url.Values{"_csrf": {csrf}, "jit": {"1"}, "claim": {"roles"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("oidc groups: %d", resp.StatusCode)
	}
	if on, claim := authcfg.OIDCJIT(context.Background(), a.store); !on || claim != "roles" || e.lastAudit(t, "auth.oidc.groups") == nil {
		t.Fatal("oidc groups not saved")
	}
}

func TestLDAPAPI(t *testing.T) {
	e := newLDAPEnv(t)
	a, ctx := e.a, context.Background()
	u, _ := a.store.UserByName(ctx, "admin")
	key, _, _ := a.store.NewAPIKey(ctx, u.ID, "script")
	in := map[string]any{"enabled": true, "urls": []string{e.dir.URL("ldap")}, "allow_plain": true, "profile": "ad", "bind_dn": ldaptest.Service,
		"bind_password": "neues-bind-pw", "base_dn": "dc=example,dc=org", "nested": true}
	code, out := apiCall(t, a, key, "PUT", "/api/auth/ldap", in)
	m, _ := out.(map[string]any)
	if code != 200 || m["bind_password_set"] != true || m["bind_password"] != nil || m["bind_password_enc"] != nil {
		t.Fatalf("put: %d %v", code, out)
	}
	c := authcfg.LoadLDAP(ctx, a.store)
	if pw, _ := e.box.Decrypt(c.BindPasswordEnc); pw != "neues-bind-pw" || strings.Contains(c.BindPasswordEnc, "neues-bind-pw") {
		t.Fatal("bind password must be stored encrypted")
	}
	// ohne Passwort: bleibt; GET ohne Passwort
	in["bind_password"] = ""
	if code, _ = apiCall(t, a, key, "PUT", "/api/auth/ldap", in); code != 200 || authcfg.LoadLDAP(ctx, a.store).BindPasswordEnc != c.BindPasswordEnc {
		t.Fatal("empty password must keep the stored one")
	}
	code, out = apiCall(t, a, key, "GET", "/api/auth/ldap", nil)
	m, _ = out.(map[string]any)
	if code != 200 || m["bind_password_set"] != true || m["default_filter"] == "" || strings.Contains(fmt.Sprint(out), "neues-bind-pw") || strings.Contains(fmt.Sprint(out), c.BindPasswordEnc) {
		t.Fatalf("get: %d %v", code, out)
	}
	in["user_filter"] = "(&(uid=x)"
	if code, out = apiCall(t, a, key, "PUT", "/api/auth/ldap", in); code != http.StatusUnprocessableEntity || out.(map[string]any)["field"] != "user_filter" {
		t.Fatalf("invalid filter: %d %v", code, out)
	}
	// Test mit gespeicherter Einstellung (das gespeicherte Bind-Passwort ist falsch) und mit eigener
	if code, out = apiCall(t, a, key, "POST", "/api/auth/ldap/test", map[string]any{"username": "mmuster"}); code != 200 || out.(map[string]any)["ok"] != false {
		t.Fatalf("test with wrong bind password: %d %v", code, out)
	}
	delete(in, "user_filter")
	in["bind_password"] = ldaptest.ServicePassword
	code, out = apiCall(t, a, key, "POST", "/api/auth/ldap/test", map[string]any{"username": "mmuster", "config": in})
	m, _ = out.(map[string]any)
	res, _ := m["result"].(map[string]any)
	if code != 200 || m["ok"] != true || res["found"] != true || res["dn"] != tMaxDN || len(m["matching_groups"].([]any)) != 1 {
		t.Fatalf("test: %d %v", code, out)
	}
	// SSO-Anlage ueber Gruppen
	if code, out = apiCall(t, a, key, "PUT", "/api/auth/oidc-groups", map[string]any{"enabled": true, "claim": ""}); code != 200 || out.(map[string]any)["claim"] != "groups" {
		t.Fatalf("oidc groups put: %d %v", code, out)
	}
	if code, out = apiCall(t, a, key, "GET", "/api/auth/oidc-groups", nil); code != 200 || out.(map[string]any)["enabled"] != true {
		t.Fatalf("oidc groups get: %d %v", code, out)
	}
	if code, _ = apiCall(t, a, key, "PUT", "/api/auth/oidc-groups", map[string]any{"enabled": true, "claim": "a b"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid claim: %d", code)
	}
}
