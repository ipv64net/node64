package web

import (
	"errors"
	"net/http"

	"github.com/ipv64net/node64/internal/store"
)

// Seite "Anmeldung" (/settings/login): SSO (OIDC), Forward-Auth und Passkeys. Lokale Benutzer bleiben immer.

func (s *Server) ssoRoutes() {
	s.mux.HandleFunc("GET /login/oidc", s.loginOIDC)
	s.mux.HandleFunc("GET /login/oidc/callback", s.loginOIDCCallback)
	s.mux.Handle("GET /settings/login", s.auth(s.loginMethods))
	s.mux.Handle("POST /settings/login/oidc", s.auth(s.loginMethodsOIDC))
	s.mux.Handle("POST /settings/login/oidc/link", s.auth(s.oidcLink))
	s.mux.Handle("POST /settings/login/identities/{id}/delete", s.auth(s.ssoUnlink))
}

type loginMethodsData struct {
	OIDC       oidcSettings
	SecretSet  bool
	Callback   string
	Identities []store.Identity
}

func (s *Server) loginMethodsView(r *http.Request) *View {
	ctx := r.Context()
	v := s.view(r, "sso.title")
	o := s.oidcSettings(ctx)
	d := loginMethodsData{OIDC: o, SecretSet: o.Secret != "", Callback: s.oidcCallbackURL(r, o)}
	d.OIDC.Secret = ""
	d.Identities, _ = s.Store.Identities(ctx, v.User.ID)
	v.Data = d
	return v
}

func (s *Server) loginMethods(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "login_methods", s.loginMethodsView(r))
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
		s.render(w, r, http.StatusUnprocessableEntity, "login_methods", v)
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	s.audit(r, "sso.config", in.Issuer, in.ClientID)
	s.flash(w, r, "success", v.T("sso.saved"))
	http.Redirect(w, r, "/settings/login", http.StatusSeeOther)
}

// loginOptions ergaenzt die Login-Seite um die weiteren Anmeldearten.
func (s *Server) loginOptions(r *http.Request, v *View) {
	if o := s.oidcSettings(r.Context()); o.Enabled() {
		v.Form["sso"] = o.ButtonLabel()
	}
}
