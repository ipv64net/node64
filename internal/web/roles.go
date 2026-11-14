package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/ipv64net/node64/internal/authcfg"
	"github.com/ipv64net/node64/internal/store"
)

// Rollen der Benutzerverwaltung (docs/PLAN-NODE64-BENUTZER.md): Administrator darf alles, „Nur lesen“ sieht alle
// Seiten und GET-APIs, aendert aber nichts ausser dem eigenen Konto (selfService). Geprueft wird zentral in auth
// (damit auch in Guards.Auth der Module); GETs mit Geheimnissen schuetzt admin bzw. Guards.Admin.

const ctxRole ctxKey = 100 // wirksame Rolle des angemeldeten Benutzers (store.RoleAdmin/RoleRead)

// withUser setzt den angemeldeten Benutzer samt wirksamer Rolle (eigene Rolle und Gruppen) in den Kontext.
func (s *Server) withUser(ctx context.Context, u *store.User) context.Context {
	ctx = context.WithValue(ctx, ctxUser, u)
	return context.WithValue(ctx, ctxRole, s.Store.EffectiveRole(ctx, u))
}

// role: wirksame Rolle des angemeldeten Benutzers ("" = niemand angemeldet).
func (s *Server) role(r *http.Request) string {
	if v, ok := r.Context().Value(ctxRole).(string); ok && v != "" {
		return v
	}
	if u := currentUser(r); u != nil {
		return s.Store.EffectiveRole(r.Context(), u)
	}
	return ""
}

// isAdmin: angemeldet mit Rolle Administrator.
func (s *Server) isAdmin(r *http.Request) bool { return store.IsAdmin(s.role(r)) }

// readOnly: angemeldet mit Rolle „Nur lesen“.
func (s *Server) readOnly(r *http.Request) bool { return currentUser(r) != nil && !s.isAdmin(r) }

// selfService: aendernde Anfragen, die auch „Nur lesen“ darf, weil sie nur das eigene Konto betreffen (Profil,
// Passwort, 2FA, Passkeys, verknuepfte SSO-Konten, eigene API- und MCP-Keys, eigenes Dashboard). Login, Setup,
// Abmelden, Push, Statusseiten, /peer/ und /mcp laufen nicht ueber auth und brauchen hier keinen Eintrag.
var selfService = func() *http.ServeMux {
	m := http.NewServeMux()
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for _, p := range []string{
		"POST /settings/user",
		"POST /settings/password",
		"POST /login/password", // Passwort beim ersten Anmelden setzen
		"POST /settings/2fa/enable",
		"POST /settings/2fa/disable",
		"POST /settings/api-keys",
		"POST /settings/api-keys/{id}/delete",
		"POST /settings/login/passkeys/begin",
		"POST /settings/login/passkeys/finish",
		"POST /settings/login/passkeys/{id}/delete",
		"POST /settings/login/oidc/link",
		"POST /settings/login/identities/{id}/delete",
		"POST /settings/mcp/keys",
		"POST /settings/mcp/keys/{id}/delete",
		"PUT /api/users/me",
		"POST /api/keys",
		"DELETE /api/keys/{id}",
		"POST /api/mcp/keys",
		"DELETE /api/mcp/keys/{id}",
		"PUT /api/dashboard/layout",
		"DELETE /api/dashboard/layout",
		"POST /environment/open/{id}",        // andere Node oeffnen: Rolle dort nie groesser (environment.go)
		"POST /environment/nodes/{uid}/open", // hinzugefuegte Node oeffnen (environment_nodes.go), ebenso begrenzt
	} {
		m.Handle(p, ok)
	}
	return m
}()

// changes: Methode aendert etwas.
func changes(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// readOnlyAllowed: darf „Nur lesen“ diese Anfrage stellen?
func readOnlyAllowed(r *http.Request) bool {
	if !changes(r.Method) {
		return true
	}
	_, pat := selfService.Handler(r)
	return pat != ""
}

// adminPath: Bereich der Benutzerverwaltung (Seiten und API, auch Teil AD/LDAP und SSO-Gruppen) - nur
// Administratoren, auch beim Lesen; zusaetzlich zu admin an den Routen, damit neue Routen dort nicht durchrutschen.
func adminPath(p string) bool {
	for _, pre := range []string{userAdminPath, "/settings/groups", "/settings/auth/", "/api/auth/", "/api/groups", "/api/users"} {
		if p == pre || strings.HasPrefix(p, strings.TrimSuffix(pre, "/")+"/") {
			return p != "/api/users/me"
		}
	}
	return false
}

// forbidRole antwortet mit 403, weil die Rolle nicht reicht (Warnung im Log mit Benutzer und Pfad).
func (s *Server) forbidRole(w http.ResponseWriter, r *http.Request) {
	name := "-"
	if u := currentUser(r); u != nil {
		name = u.Username
	}
	s.log.Warn("forbidden by role", "user", name, "role", s.role(r), "method", r.Method, "path", r.URL.Path, "ip", s.clientIP(r))
	if strings.HasPrefix(r.URL.Path, "/api/") || viaAPIKey(r) {
		writeErr(w, http.StatusForbidden, "read-only user")
		return
	}
	key := "errors.read_only"
	if !changes(r.Method) {
		key = "errors.admin_only"
	}
	s.errorPage(w, r, http.StatusForbidden, key)
}

// admin: wie auth, dazu Rolle Administrator auch beim Lesen (Backup, Export, Schluessel, Benutzerverwaltung).
func (s *Server) admin(h http.HandlerFunc) http.Handler {
	return s.auth(func(w http.ResponseWriter, r *http.Request) {
		if !s.isAdmin(r) {
			s.forbidRole(w, r)
			return
		}
		h(w, r)
	})
}

// adminHandler ist admin fuer beliebige Handler (Guards.Admin der Module).
func (s *Server) adminHandler(next http.Handler) http.Handler { return s.admin(next.ServeHTTP) }

// ---------------------------------------------------------------- Pflichten nach der Anmeldung

// needs2FA: Schalter „2FA fuer alle Pflicht“ an, Benutzer lokal oder LDAP und ohne App-2FA und ohne Passkey
// (SSO-Benutzer erledigen 2FA beim Anbieter).
func (s *Server) needs2FA(ctx context.Context, u *store.User) bool {
	if u.Source == store.SourceOIDC || u.TOTPSecret != "" || !authcfg.TwoFARequired(ctx, s.Store) {
		return false
	}
	pks, _ := s.Store.Passkeys(ctx, u.ID, "")
	return len(pks) == 0
}

// gate prueft die Pflichten einer Sitzung: Passwort beim ersten Anmelden setzen, 2FA einrichten. Bis dahin ist nur
// die jeweilige Seite erreichbar (Abmelden und statische Dateien laufen nicht ueber auth). false = beantwortet.
func (s *Server) gate(w http.ResponseWriter, r *http.Request) bool {
	u := currentUser(r)
	if u == nil || currentSession(r) == nil || viaAPIKey(r) {
		return true // API-Keys, Forward-Auth und MCP: keine Sitzung, keine Seite zum Nachholen (Forward-Auth: Anmeldung und 2FA beim vorgeschalteten Dienst, in der Oberflaeche so beschrieben)
	}
	var to, msg string
	switch {
	case u.MustChange && u.Source == store.SourceLocal:
		if r.URL.Path == "/login/password" {
			return true
		}
		to, msg = "/login/password", "password change required"
	case s.needs2FA(r.Context(), u):
		switch r.URL.Path {
		case "/settings/2fa", "/settings/2fa/enable", "/settings/login/passkeys/begin", "/settings/login/passkeys/finish":
			return true
		}
		to, msg = "/settings/2fa", "two-factor setup required"
	default:
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeErr(w, http.StatusForbidden, msg)
		return false
	}
	if to == "/login/password" && r.Method == http.MethodGet {
		to += "?next=" + url.QueryEscape(r.URL.RequestURI())
	}
	if to == "/settings/2fa" {
		s.flash(w, r, "warning", s.tr(r, "useradmin.twofa_required_flash"))
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
	return false
}

// ---------------------------------------------------------------- Passwort beim ersten Anmelden setzen

func (s *Server) mustChangeForm(w http.ResponseWriter, r *http.Request) {
	if !currentUser(r).MustChange {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	v := s.mustChangeView(r)
	v.Form["next"] = safeNext(r.URL.Query().Get("next"))
	s.render(w, r, http.StatusOK, "password_new", v)
}

// mustChangeView: Seite ohne Menue (wie die Anmeldung), es geht ohnehin nur hierhin.
func (s *Server) mustChangeView(r *http.Request) *View {
	v := s.view(r, "useradmin.must_change_title")
	v.Data = map[string]string{"Username": currentUser(r).Username}
	v.User, v.Nav = nil, nil
	return v
}

func (s *Server) mustChangeSubmit(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if !u.MustChange {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	f := s.formValues(r, "password", "password2", "next")
	v := s.mustChangeView(r)
	v.Form["next"] = safeNext(f["next"])
	if err := checkPassword(f["password"]); err != nil {
		v.Errors["password"] = v.T("errors.password_short")
	} else if f["password"] != f["password2"] {
		v.Errors["password2"] = v.T("errors.password_mismatch")
	} else if VerifyPassword(u.PasswordHash, f["password"]) {
		v.Errors["password"] = v.T("useradmin.must_change_same")
	}
	if len(v.Errors) > 0 {
		s.render(w, r, http.StatusUnprocessableEntity, "password_new", v)
		return
	}
	hash, err := HashPassword(f["password"])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := r.Context()
	if err := s.Store.UpdateUserPassword(ctx, u.ID, hash); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.SetUserMustChange(ctx, u.ID, false); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.DeleteUserSessions(ctx, u.ID, sessionID(r))
	s.audit(r, "settings.password", u.Username, "first login")
	s.flash(w, r, "success", v.T("settings.password_changed"))
	http.Redirect(w, r, v.Form["next"], http.StatusSeeOther)
}
