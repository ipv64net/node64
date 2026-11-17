package web

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/authcfg"
	"github.com/ipv64net/node64/internal/store"
)

// Benutzerverwaltung: Oberflaeche, API, Schutz des letzten lokalen Administrators, Sperre, Passwort beim ersten
// Anmelden, 2FA-Pflicht, Hinweis „Nur lesen“.

// asClient: eigener Browser (Cookies) fuer einen weiteren Benutzer am selben Testserver.
func asClient(a *testApp) *testApp {
	b := *a
	jar, _ := cookiejar.New(nil)
	b.client = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &b
}

func TestUserAdminUI(t *testing.T) {
	a := newTestApp(t)
	admin := loginAs(t, a, "admin", "sehr geheimes passwort")
	ctx := context.Background()

	resp, body := a.get(t, "/settings/users")
	if resp.StatusCode != 200 || !strings.Contains(body, `id="users"`) || !strings.Contains(body, `id="groups"`) || !strings.Contains(body, `id="login"`) ||
		!strings.Contains(body, `action="/settings/auth/2fa-required"`) || strings.Contains(strings.ReplaceAll(body, "useradmin.js", ""), "useradmin.") {
		t.Fatalf("page: %d", resp.StatusCode)
	}
	if !strings.Contains(body, `href="/settings/users"`) {
		t.Fatal("nav entry for administrators missing")
	}
	csrf := csrfOf(t, body)

	// Gruppe anlegen
	resp, _ = a.post(t, "/settings/groups", url.Values{"_csrf": {csrf}, "name": {"Technik"}, "role": {"admin"}, "description": {"Admins"},
		"ldap_groups": {"CN=Admins,DC=example,DC=com\nCN=IT,DC=example,DC=com"}, "oidc_groups": {"node64-admins"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/settings/users?tab=groups") {
		t.Fatalf("group create: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	groups, _ := a.store.Groups(ctx)
	if len(groups) != 1 || groups[0].Role != "admin" || len(groups[0].LDAPGroups) != 2 || groups[0].OIDCGroups[0] != "node64-admins" {
		t.Fatalf("group: %+v", groups)
	}
	g := groups[0]

	// Benutzer mit Einmal-Passwort anlegen: Passwort einmal sichtbar
	resp, _ = a.post(t, "/settings/users", url.Values{"_csrf": {csrf}, "username": {"erika"}, "role": {"read"}, "email": {"erika@example.com"}, "must_change": {"1"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("user create: %d", resp.StatusCode)
	}
	_, body = a.get(t, "/settings/users")
	m := regexp.MustCompile(`value="([^"]+)" readonly id="ua-otp"`).FindStringSubmatch(body)
	if m == nil || !strings.Contains(body, "erika@example.com") {
		t.Fatal("one-time password not shown")
	}
	otp := m[1]
	if _, body = a.get(t, "/settings/users"); strings.Contains(body, otp) {
		t.Fatal("one-time password shown twice")
	}
	erika, _ := a.store.UserByName(ctx, "erika")
	if erika == nil || erika.Role != "read" || !erika.MustChange || !VerifyPassword(erika.PasswordHash, otp) {
		t.Fatalf("user: %+v", erika)
	}
	// Name vergeben
	a.post(t, "/settings/users", url.Values{"_csrf": {csrf}, "username": {"erika"}, "password": {"sehr geheimes passwort"}, "password2": {"sehr geheimes passwort"}})
	if all, _ := a.store.Users(ctx); len(all) != 2 {
		t.Fatalf("duplicate created: %d", len(all))
	}

	// Bearbeiten: Gruppe zuordnen (wirksam Administrator), dann sperren
	resp, _ = a.post(t, "/settings/users/"+itoa(erika.ID), url.Values{"_csrf": {csrf}, "role": {"read"}, "groups": {g.UID}, "email": {"e@example.com"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("update: %d", resp.StatusCode)
	}
	erika, _ = a.store.UserByID(ctx, erika.ID)
	if a.store.EffectiveRole(ctx, erika) != "admin" || erika.Email != "e@example.com" {
		t.Fatalf("after update: %+v", erika)
	}
	a.post(t, "/settings/users/"+itoa(erika.ID), url.Values{"_csrf": {csrf}, "role": {"read"}, "disabled": {"1"}})
	if erika, _ = a.store.UserByID(ctx, erika.ID); !erika.Disabled || len(erika.GroupUIDs) != 0 {
		t.Fatalf("disable: %+v", erika)
	}
	// sich selbst nicht sperren
	a.post(t, "/settings/users/"+itoa(admin.ID), url.Values{"_csrf": {csrf}, "role": {"admin"}, "disabled": {"1"}})
	if me, _ := a.store.UserByID(ctx, admin.ID); me.Disabled {
		t.Fatal("admin disabled himself")
	}
	// Passwort setzen, 2FA zuruecksetzen, Sitzungen beenden, loeschen
	a.post(t, "/settings/users/"+itoa(erika.ID)+"/password", url.Values{"_csrf": {csrf}, "password": {"ganz neues passwort"}})
	if erika, _ = a.store.UserByID(ctx, erika.ID); !VerifyPassword(erika.PasswordHash, "ganz neues passwort") || erika.MustChange {
		t.Fatal("password not set")
	}
	_ = a.store.SetUserTOTP(ctx, erika.ID, "JBSWY3DPEHPK3PXP", "")
	_ = a.store.AddPasskey(ctx, store.Passkey{UserID: erika.ID, Name: "Stick", RPID: "localhost", CredentialID: "c1", Data: "{}"})
	_ = a.store.AddPasskey(ctx, store.Passkey{UserID: admin.ID, Name: "Admin", RPID: "localhost", CredentialID: "c2", Data: "{}"})
	a.post(t, "/settings/users/"+itoa(erika.ID)+"/2fa-reset", url.Values{"_csrf": {csrf}})
	if erika, _ = a.store.UserByID(ctx, erika.ID); erika.TOTPSecret != "" {
		t.Fatal("2fa not reset")
	}
	if pks, _ := a.store.Passkeys(ctx, erika.ID, ""); len(pks) != 0 {
		t.Fatalf("2fa reset must remove passkeys: %d", len(pks))
	}
	if pks, _ := a.store.Passkeys(ctx, admin.ID, ""); len(pks) != 1 {
		t.Fatal("passkeys of other users must stay")
	}
	a.post(t, "/settings/users/"+itoa(erika.ID)+"/sessions-end", url.Values{"_csrf": {csrf}})
	a.post(t, "/settings/users/"+itoa(erika.ID)+"/delete", url.Values{"_csrf": {csrf}})
	if u, _ := a.store.UserByID(ctx, erika.ID); u != nil {
		t.Fatal("not deleted")
	}
	a.post(t, "/settings/groups/"+g.UID+"/delete", url.Values{"_csrf": {csrf}})
	if x, _ := a.store.GroupByUID(ctx, g.UID); x != nil {
		t.Fatal("group not deleted")
	}
	// alte Adresse leitet weiter
	if resp, _ = a.get(t, "/settings/login"); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/settings/users") {
		t.Fatalf("old url: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// 2FA-Pflicht
	a.post(t, "/settings/auth/2fa-required", url.Values{"_csrf": {csrf}, "required": {"1"}})
	if !authcfg.TwoFARequired(ctx, a.store) {
		t.Fatal("2fa required not saved")
	}
	entries, _ := a.store.AuditList(ctx, 100, 0)
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Action] = true
	}
	for _, act := range []string{"user.create", "user.update", "user.disable", "user.password", "user.2fa_reset", "user.sessions_end", "user.delete",
		"group.create", "group.delete", "auth.2fa_required"} {
		if !seen[act] {
			t.Errorf("audit %s missing", act)
		}
	}
}

func TestUserAdminAPI(t *testing.T) {
	a := newTestApp(t)
	_, key := apiKeyUser(t, a, "admin")
	ctx := context.Background()

	st, out := apiCall(t, a, key, "POST", "/api/groups", map[string]any{"name": "Leser", "role": "read", "oidc_groups": []string{"readers"}})
	g, _ := out.(map[string]any)
	if st != 201 || g["uid"] == "" || g["role"] != "read" {
		t.Fatalf("group create: %d %v", st, out)
	}
	gid := g["uid"].(string)
	st, out = apiCall(t, a, key, "POST", "/api/users", map[string]any{"username": "max", "must_change": true, "groups": []string{gid, "unbekannt"}})
	u, _ := out.(map[string]any)
	if st != 201 || u["role"] != "read" || u["source"] != "local" || u["must_change"] != true || u["password"] == nil || len(u["groups"].([]any)) != 1 {
		t.Fatalf("user create: %d %v", st, out)
	}
	id := itoa(int64(u["id"].(float64)))
	if st, _ = apiCall(t, a, key, "POST", "/api/users", map[string]any{"username": "kurz", "password": "kurz"}); st != 422 {
		t.Fatalf("weak password: %d", st)
	}
	st, out = apiCall(t, a, key, "PUT", "/api/users/"+id, map[string]any{"role": "admin", "email": "max@example.com"})
	if u, _ = out.(map[string]any); st != 200 || u["role"] != "admin" || u["own_role"] != "admin" || u["email"] != "max@example.com" {
		t.Fatalf("update: %d %v", st, out)
	}
	if st, out = apiCall(t, a, key, "GET", "/api/users/"+id, nil); st != 200 || out.(map[string]any)["username"] != "max" {
		t.Fatalf("get: %d", st)
	}
	if st, out = apiCall(t, a, key, "GET", "/api/groups/"+gid, nil); st != 200 || len(out.(map[string]any)["members"].([]any)) != 1 {
		t.Fatalf("group members: %d %v", st, out)
	}
	if st, _ = apiCall(t, a, key, "POST", "/api/users/"+id+"/password", map[string]any{"password": "neues langes passwort"}); st != 204 {
		t.Fatalf("password: %d", st)
	}
	if st, _ = apiCall(t, a, key, "POST", "/api/users/"+id+"/2fa-reset", nil); st != 204 {
		t.Fatalf("2fa reset: %d", st)
	}
	if st, _ = apiCall(t, a, key, "POST", "/api/users/"+id+"/sessions-end", nil); st != 204 {
		t.Fatalf("sessions end: %d", st)
	}
	if st, _ = apiCall(t, a, key, "PUT", "/api/groups/"+gid, map[string]any{"description": "nur lesen"}); st != 200 {
		t.Fatalf("group update: %d", st)
	}
	if st, out = apiCall(t, a, key, "PUT", "/api/auth/2fa-required", map[string]any{"required": true}); st != 200 || !authcfg.TwoFARequired(ctx, a.store) {
		t.Fatalf("2fa required: %d %v", st, out)
	}
	if st, out = apiCall(t, a, key, "GET", "/api/auth/2fa-required", nil); st != 200 || out.(map[string]any)["required"] != true {
		t.Fatalf("2fa required get: %d %v", st, out)
	}
	if st, out = apiCall(t, a, key, "GET", "/api/users/me", nil); st != 200 || out.(map[string]any)["role"] != "admin" || out.(map[string]any)["disabled"] != false {
		t.Fatalf("me: %d %v", st, out)
	}
	if st, _ = apiCall(t, a, key, "DELETE", "/api/groups/"+gid, nil); st != 204 {
		t.Fatalf("group delete: %d", st)
	}
	if st, _ = apiCall(t, a, key, "DELETE", "/api/users/"+id, nil); st != 204 {
		t.Fatalf("user delete: %d", st)
	}
	// Nur lesen: Benutzerverwaltung gesperrt, /api/users/me mit Rolle
	reader := createUser(t, a, "leser", store.RoleRead)
	rkey, _, _ := a.store.NewAPIKey(ctx, reader.ID, "lesen")
	if st, out = apiCall(t, a, rkey, "GET", "/api/users/me", nil); st != 200 || out.(map[string]any)["role"] != "read" {
		t.Fatalf("reader me: %d %v", st, out)
	}
	for _, c := range [][2]string{{"GET", "/api/users"}, {"GET", "/api/groups"}, {"POST", "/api/users"}, {"GET", "/api/auth/2fa-required"}, {"PUT", "/api/settings"}} {
		if st, out = apiCall(t, a, rkey, c[0], c[1], map[string]any{}); st != 403 || out.(map[string]any)["error"] != "read-only user" {
			t.Errorf("reader %s %s: %d %v", c[0], c[1], st, out)
		}
	}
	// eigener Key eines Nur-lesen-Benutzers: anlegen erlaubt, der neue Key liest ebenfalls nur
	st, out = apiCall(t, a, rkey, "POST", "/api/keys", map[string]any{"name": "zweiter"})
	if st != 201 {
		t.Fatalf("reader own key: %d", st)
	}
	if st, _ = apiCall(t, a, out.(map[string]any)["key"].(string), "PUT", "/api/settings", map[string]any{}); st != 403 {
		t.Fatalf("new key of reader not read-only: %d", st)
	}
}

// Nie den letzten aktiven lokalen Administrator sperren, herabstufen oder loeschen (auch nicht ueber eine Gruppe).
func TestLastLocalAdmin(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	admin := createUser(t, a, "admin", store.RoleAdmin)
	// zweiter Administrator, aber aus dem Verzeichnis: zaehlt nicht
	ldap, _ := a.store.CreateUserWith(ctx, store.NewUser{Username: "ad.admin", Role: store.RoleAdmin, Source: store.SourceLDAP})
	key, _, _ := a.store.NewAPIKey(ctx, ldap.ID, "ldap")
	for _, c := range []struct {
		method, path string
		body         map[string]any
	}{
		{"PUT", "/api/users/" + itoa(admin.ID), map[string]any{"role": "read"}},
		{"PUT", "/api/users/" + itoa(admin.ID), map[string]any{"disabled": true}},
		{"DELETE", "/api/users/" + itoa(admin.ID), nil},
	} {
		if st, out := apiCall(t, a, key, c.method, c.path, c.body); st != http.StatusConflict {
			t.Errorf("%s %v: %d %v", c.method, c.body, st, out)
		}
	}
	// Rolle ueber eine Gruppe: eigene Rolle read, Gruppe admin - die Gruppe herabstufen oder loeschen geht nicht
	g := &store.Group{Name: "Admins", Role: store.RoleAdmin}
	_ = a.store.SaveGroup(ctx, g)
	if st, _ := apiCall(t, a, key, "PUT", "/api/users/"+itoa(admin.ID), map[string]any{"groups": []string{g.UID}}); st != 200 {
		t.Fatalf("assign group: %d", st)
	}
	if st, _ := apiCall(t, a, key, "PUT", "/api/users/"+itoa(admin.ID), map[string]any{"role": "read"}); st != 200 {
		t.Fatalf("own role read with admin group: %d", st)
	}
	if st, _ := apiCall(t, a, key, "PUT", "/api/groups/"+g.UID, map[string]any{"role": "read"}); st != http.StatusConflict {
		t.Fatalf("group demote: %d", st)
	}
	if st, _ := apiCall(t, a, key, "DELETE", "/api/groups/"+g.UID, nil); st != http.StatusConflict {
		t.Fatalf("group delete: %d", st)
	}
	// mit einem weiteren lokalen Administrator geht es
	createUser(t, a, "admin2", store.RoleAdmin)
	if st, _ := apiCall(t, a, key, "PUT", "/api/users/"+itoa(admin.ID), map[string]any{"disabled": true}); st != 200 {
		t.Fatalf("disable with second admin: %d", st)
	}
}

// Sperre: Sitzungen enden, API-Keys gelten nicht, keine Anmeldung.
func TestDisabledUser(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	loginAs(t, a, "admin", "sehr geheimes passwort")
	reader := createUser(t, a, "leser", store.RoleRead)
	rkey, _, _ := a.store.NewAPIKey(ctx, reader.ID, "lesen")
	b := asClient(a)
	if resp := login(t, b, "leser", "sehr geheimes passwort"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	if resp, _ := b.get(t, "/settings"); resp.StatusCode != 200 {
		t.Fatalf("reader settings: %d", resp.StatusCode)
	}
	_, body := a.get(t, "/settings/users")
	a.post(t, "/settings/users/"+itoa(reader.ID), url.Values{"_csrf": {csrfOf(t, body)}, "role": {"read"}, "disabled": {"1"}})
	if resp, _ := b.get(t, "/settings"); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Fatalf("session after disable: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if st, _ := apiCall(t, a, rkey, "GET", "/api/users/me", nil); st != http.StatusUnauthorized {
		t.Fatalf("api key after disable: %d", st)
	}
	c := asClient(a)
	_, body = c.get(t, "/login")
	resp, body := c.post(t, "/login", url.Values{"_csrf": {csrfOf(t, body)}, "username": {"leser"}, "password": {"sehr geheimes passwort"}})
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "gesperrt") {
		t.Fatalf("login disabled: %d", resp.StatusCode)
	}
}

// Passwort beim ersten Anmelden setzen: bis dahin ist nur diese Seite erreichbar.
func TestMustChangePassword(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	_, key := apiKeyUser(t, a, "admin")
	_, out := apiCall(t, a, key, "POST", "/api/users", map[string]any{"username": "neu", "role": "read", "must_change": true})
	otp := out.(map[string]any)["password"].(string)
	b := asClient(a)
	resp := login(t, b, "neu", otp)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login/password") {
		t.Fatalf("login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, p := range []string{"/", "/settings", "/audit"} {
		if resp, _ := b.get(t, p); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login/password") {
			t.Fatalf("%s before change: %d %s", p, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	if resp, _ := b.get(t, "/api/status"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("api before change: %d", resp.StatusCode)
	}
	resp, body := b.get(t, "/login/password")
	if resp.StatusCode != 200 || !strings.Contains(body, `action="/login/password"`) {
		t.Fatalf("page: %d", resp.StatusCode)
	}
	csrf := csrfOf(t, body)
	if resp, _ = b.post(t, "/login/password", url.Values{"_csrf": {csrf}, "password": {otp}, "password2": {otp}}); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("same password: %d", resp.StatusCode)
	}
	if resp, _ = b.post(t, "/login/password", url.Values{"_csrf": {csrf}, "password": {"mein eigenes passwort"}, "password2": {"mein eigenes passwort"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("change: %d", resp.StatusCode)
	}
	u, _ := a.store.UserByName(ctx, "neu")
	if u.MustChange || !VerifyPassword(u.PasswordHash, "mein eigenes passwort") {
		t.Fatalf("after change: %+v", u)
	}
	if resp, _ := b.get(t, "/"); resp.StatusCode != 200 {
		t.Fatalf("after change: %d", resp.StatusCode)
	}
}

// 2FA-Pflicht: lokale Benutzer ohne App-2FA und ohne Passkey kommen nur zur Einrichtung; SSO-Benutzer nicht.
func TestTwoFARequired(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	loginAs(t, a, "admin", "sehr geheimes passwort")
	_ = authcfg.SetTwoFARequired(ctx, a.store, true)
	for _, p := range []string{"/", "/settings/users"} {
		if resp, _ := a.get(t, p); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings/2fa" {
			t.Fatalf("%s: %d %s", p, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	if resp, _ := a.get(t, "/api/status"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("api: %d", resp.StatusCode)
	}
	if resp, body := a.get(t, "/settings/2fa"); resp.StatusCode != 200 || !strings.Contains(body, "/settings/2fa/enable") {
		t.Fatalf("setup page: %d", resp.StatusCode)
	}
	// mit App-2FA wieder alles erreichbar
	u, _ := a.store.UserByName(ctx, "admin")
	_ = a.store.SetUserTOTP(ctx, u.ID, "JBSWY3DPEHPK3PXP", "")
	if resp, _ := a.get(t, "/"); resp.StatusCode != 200 {
		t.Fatalf("with totp: %d", resp.StatusCode)
	}
	// SSO-Benutzer ausgenommen
	sso, _ := a.store.CreateUserWith(ctx, store.NewUser{Username: "sso.user", Role: store.RoleRead, Source: store.SourceOIDC})
	if a.s.needs2FA(ctx, sso) {
		t.Fatal("sso user must not need local 2fa")
	}
	ldap, _ := a.store.CreateUserWith(ctx, store.NewUser{Username: "ldap.user", Role: store.RoleRead, Source: store.SourceLDAP})
	if !a.s.needs2FA(ctx, ldap) {
		t.Fatal("ldap user needs 2fa")
	}
}

// Oberflaeche fuer „Nur lesen“: Hinweis oben, kein Menuepunkt Benutzerverwaltung, Formulare ausgegraut, 403-Seite.
func TestReadOnlyUI(t *testing.T) {
	a := newTestApp(t)
	createUser(t, a, "admin", store.RoleAdmin)
	createUser(t, a, "leser", store.RoleRead)
	login(t, a, "leser", "sehr geheimes passwort")
	resp, body := a.get(t, "/settings")
	if resp.StatusCode != 200 || !strings.Contains(body, `data-readonly="1"`) || !strings.Contains(body, "readonly-badge") || !strings.Contains(body, "Nur lesen") {
		t.Fatalf("hint: %d", resp.StatusCode)
	}
	if strings.Contains(body, `href="/settings/users"`) {
		t.Fatal("user management visible for read-only")
	}
	if !strings.Contains(body, `<fieldset class="border-0 p-0 m-0" disabled>`) {
		t.Fatal("forms not disabled")
	}
	// eigene Karten (Sprache, Passwort, 2FA, Passkeys) auf Mein Konto - fuer "Nur lesen" bedienbar, nicht gesperrt
	if _, acc := a.get(t, "/settings/account"); !strings.Contains(acc, `id="passkeys"`) || !strings.Contains(acc, "/static/js/passkey.js") || !strings.Contains(acc, `id="twofa"`) || !strings.Contains(acc, `action="/settings/password"`) || strings.Contains(acc, " disabled>") {
		t.Fatal("personal cards missing on my account")
	}
	csrf := csrfOf(t, body)
	resp, body = a.post(t, "/settings/node", url.Values{"_csrf": {csrf}, "node_name": {"x"}})
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "Nur lesen") {
		t.Fatalf("post: %d", resp.StatusCode)
	}
	if resp, body = a.get(t, "/settings/users"); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "nur für Administratoren") {
		t.Fatalf("admin page: %d", resp.StatusCode)
	}
	// eigenes Profil geht
	if resp, _ = a.post(t, "/settings/user", url.Values{"_csrf": {csrf}, "lang": {"en"}, "timezone": {"UTC"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("own profile: %d", resp.StatusCode)
	}
	// Geheimnisse der Kanaele nicht
	if resp, _ = a.get(t, "/api/backup"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("backup: %d", resp.StatusCode)
	}
	// Administrator: kein Hinweis
	b := asClient(a)
	login(t, b, "admin", "sehr geheimes passwort")
	if _, body = b.get(t, "/settings"); strings.Contains(body, `data-readonly`) || !strings.Contains(body, `href="/settings/users"`) {
		t.Fatal("admin view")
	}
}
