package web

import (
	"errors"
	"net/http"

	"github.com/ipv64net/node64/internal/store"
)

// Anmeldung: Einrichtung von SSO (OIDC) und Forward-Auth im Reiter „Anmeldung“ der Benutzerverwaltung (frueher
// /settings/login, leitet weiter); eigene Passkeys und verknuepfte SSO-Konten auf /settings. Lokale Benutzer bleiben.

func (s *Server) ssoRoutes() {
	s.mux.HandleFunc("GET /login/oidc", s.loginOIDC)
	s.mux.HandleFunc("GET /login/oidc/callback", s.loginOIDCCallback)
	s.mux.Handle("GET /settings/login", s.auth(s.loginMethods))
	s.mux.Handle("POST /settings/login/oidc", s.admin(s.loginMethodsOIDC))
	s.mux.Handle("POST /settings/login/oidc/link", s.auth(s.oidcLink))
	s.mux.Handle("POST /settings/login/identities/{id}/delete", s.auth(s.ssoUnlink))
	s.mux.Handle("POST /settings/login/forward", s.admin(s.loginMethodsForward))
	s.mux.Handle("POST /settings/login/passkeys/begin", s.auth(s.passkeyRegisterBegin))
	s.mux.Handle("POST /settings/login/passkeys/finish", s.auth(s.passkeyRegisterFinish))
	s.mux.Handle("POST /settings/login/passkeys/{id}/delete", s.auth(s.passkeyDelete))
	s.mux.Handle("POST /settings/login/users/{id}/delete", s.admin(s.uaDeleteSubmit)) // frueher Liste „Benutzer dieser Node“
	s.mux.HandleFunc("POST /login/passkey/begin", s.passkeyLoginBegin)
	s.mux.HandleFunc("POST /login/passkey/finish", s.passkeyLoginFinish)
}

type loginMethodsData struct {
	OIDC       oidcSettings
	SecretSet  bool
	Callback   string
	Identities []store.Identity
	Fwd        fwdSettings
	FwdIP      string // Adresse dieser Anfrage (Hilfe beim Eintragen des Proxys)
	FwdHeader  string // Wert des Kopfs in dieser Anfrage
	FwdTrusted bool   // diese Anfrage kommt von einem eingetragenen Proxy
	Passkeys   []store.Passkey
	PKHost     string // Hostname dieser Anfrage (Passkeys gelten nur dafuer)
	PKOK       bool   // Passkeys sind unter dieser Adresse moeglich (Name statt IP, HTTPS)
}

// loginMethodsData: Einrichtung der Anmeldewege (Reiter „Anmeldung“) und die eigenen Passkeys/SSO-Konten (/settings).
func (s *Server) loginMethodsData(r *http.Request) loginMethodsData {
	ctx := r.Context()
	o := s.oidcSettings(ctx)
	d := loginMethodsData{OIDC: o, SecretSet: o.Secret != "", Callback: s.oidcCallbackURL(r, o)}
	d.OIDC.Secret = ""
	d.Identities, _ = s.Store.Identities(ctx, currentUser(r).ID)
	d.Fwd = s.fwdSettings(ctx)
	d.FwdIP = remoteIP(r).String()
	d.FwdHeader = truncate(r.Header.Get(d.Fwd.Header), 64)
	d.FwdTrusted = d.Fwd.trusts(remoteIP(r))
	d.Passkeys, _ = s.Store.Passkeys(ctx, currentUser(r).ID, "")
	_, host, pkErr := s.relyingParty(r)
	d.PKHost, d.PKOK = host, pkErr == nil
	return d
}

// loginMethodsView: Benutzerverwaltung mit Reiter „Anmeldung“ (fuer Fehlermeldungen beim Speichern).
func (s *Server) loginMethodsView(r *http.Request) *View { return s.userAdminView(r, "login") }

// loginMethods: alte Adresse /settings/login - Administratoren zum Reiter „Anmeldung“, sonst zu den eigenen Passkeys.
func (s *Server) loginMethods(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		http.Redirect(w, r, accountPath+"#passkeys", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, userAdminPath+"?tab=login#login", http.StatusSeeOther)
}

func (s *Server) loginMethodsOIDC(w http.ResponseWriter, r *http.Request) {
	f := s.formValues(r, "issuer", "client_id", "client_secret", "label", "scopes", "base_url", "clear")
	in := oidcSettings{Issuer: f["issuer"], ClientID: f["client_id"], Secret: f["client_secret"], Label: f["label"], Scopes: f["scopes"], BaseURL: f["base_url"]}
	if f["clear"] == "1" {
		in = oidcSettings{}
	}
	err := s.oidcSave(r.Context(), in, f["clear"] != "1")
	v := s.view(r, "sso.title")
	switch {
	case errors.Is(err, errOIDCIssuer), errors.Is(err, errOIDCBase):
		v = s.loginMethodsView(r)
		v.Flash = &Flash{Kind: "danger", Text: v.T("sso.invalid", "error", err.Error())}
		s.render(w, r, http.StatusUnprocessableEntity, "useradmin", v)
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	s.audit(r, "sso.config", in.Issuer, in.ClientID)
	s.flash(w, r, "success", v.T("sso.saved"))
	http.Redirect(w, r, userAdminPath+"?tab=login#login", http.StatusSeeOther)
}

// loginOptions ergaenzt die Login-Seite um die weiteren Anmeldearten.
func (s *Server) loginOptions(r *http.Request, v *View) {
	if o := s.oidcSettings(r.Context()); o.Enabled() {
		v.Form["sso"] = o.ButtonLabel()
	}
	if _, host, err := s.relyingParty(r); err == nil && s.Store.PasskeyCount(r.Context(), host) > 0 {
		v.Form["passkey"] = "1"
	}
}

func (s *Server) loginMethodsForward(w http.ResponseWriter, r *http.Request) {
	f := s.formValues(r, "enabled", "trusted", "header")
	err := s.fwdSave(r.Context(), f["enabled"] == "1", f["trusted"], f["header"])
	if err != nil {
		v := s.loginMethodsView(r)
		v.Flash = &Flash{Kind: "danger", Text: v.T("sso.invalid", "error", err.Error())}
		s.render(w, r, http.StatusUnprocessableEntity, "useradmin", v)
		return
	}
	s.audit(r, "sso.forward", f["trusted"], "enabled="+f["enabled"])
	v := s.view(r, "sso.title")
	s.flash(w, r, "success", v.T("sso.saved"))
	http.Redirect(w, r, userAdminPath+"?tab=login#login", http.StatusSeeOther)
}
