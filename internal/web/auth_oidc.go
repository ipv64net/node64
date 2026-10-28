package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/ipv64net/node64/internal/store"
	"github.com/ipv64net/node64/internal/usercluster"
)

// Anmeldung ueber SSO per OpenID Connect (Authelia, Authentik, Keycloak, Pocket ID, Zitadel, …). Lokale Konten
// bleiben die Grundlage: Anmelden kann sich nur, wer seine SSO-Identitaet vorher in den Einstellungen mit seinem
// lokalen Benutzer verknuepft hat (kein automatisches Anlegen). Den zweiten Faktor uebernimmt der SSO-Anbieter.
// Ablauf mit state (an ein Cookie gebunden), nonce und PKCE.

const (
	setOIDCIssuer   = "auth.oidc.issuer"
	setOIDCClient   = "auth.oidc.client_id"
	setOIDCSecret   = "auth.oidc.client_secret" // verschluesselt
	setOIDCLabel    = "auth.oidc.label"
	setOIDCScopes   = "auth.oidc.scopes"
	setOIDCBaseURL  = "auth.oidc.base_url" // feste externe Adresse fuer die Rueckleitung (leer = aus der Anfrage)
	oidcCookie      = "node64_oidc"
	oidcFlowTTL     = 10 * time.Minute
	oidcDefaultScop = "openid profile email"
)

// oidcSettings ist die Einrichtung des SSO-Anbieters.
type oidcSettings struct {
	Issuer, ClientID, Secret, Label, Scopes, BaseURL string
}

func (o oidcSettings) Enabled() bool { return o.Issuer != "" && o.ClientID != "" }

// ButtonLabel: Beschriftung des Knopfs auf der Login-Seite.
func (o oidcSettings) ButtonLabel() string {
	if o.Label != "" {
		return o.Label
	}
	if u, err := url.Parse(o.Issuer); err == nil && u.Host != "" {
		return u.Host
	}
	return "SSO"
}

func (s *Server) oidcSettings(ctx context.Context) oidcSettings {
	o := oidcSettings{
		Issuer: s.Store.SettingOr(ctx, setOIDCIssuer, ""), ClientID: s.Store.SettingOr(ctx, setOIDCClient, ""),
		Label: s.Store.SettingOr(ctx, setOIDCLabel, ""), Scopes: s.Store.SettingOr(ctx, setOIDCScopes, oidcDefaultScop),
		BaseURL: s.Store.SettingOr(ctx, setOIDCBaseURL, ""),
	}
	if enc := s.Store.SettingOr(ctx, setOIDCSecret, ""); enc != "" && s.Box != nil {
		o.Secret, _ = s.Box.Decrypt(enc)
	}
	return o
}

// oidcCallbackURL: Adresse, an die der Anbieter zurueckleitet (muss dort eingetragen sein).
func (s *Server) oidcCallbackURL(r *http.Request, o oidcSettings) string {
	base := strings.TrimRight(o.BaseURL, "/")
	if base == "" {
		scheme := "http"
		if r.TLS != nil || (s.Cfg.TrustProxyHeaders && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")) {
			scheme = "https"
		}
		host := r.Host
		if s.Cfg.TrustProxyHeaders && r.Header.Get("X-Forwarded-Host") != "" {
			host = r.Header.Get("X-Forwarded-Host")
		}
		base = scheme + "://" + host
	}
	return base + "/login/oidc/callback"
}

// ---------------------------------------------------------------- Anbieter (Discovery, 1 h zwischengespeichert)

var oidcCache struct {
	sync.Mutex
	issuer string
	p      *oidc.Provider
	at     time.Time
}

func oidcProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	oidcCache.Lock()
	defer oidcCache.Unlock()
	if oidcCache.p != nil && oidcCache.issuer == issuer && time.Since(oidcCache.at) < time.Hour {
		return oidcCache.p, nil
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(cctx, issuer)
	if err != nil {
		// Der Issuer muss Zeichen fuer Zeichen zum Discovery-Dokument (und zu "iss" im ID-Token) passen. Manche Anbieter
		// haben einen Schraegstrich am Ende (authentik), andere nicht (Authelia, Keycloak): die andere Schreibweise
		// versuchen, Discovery liegt bei beiden unter derselben Adresse.
		alt := issuer + "/"
		if strings.HasSuffix(issuer, "/") {
			alt = strings.TrimRight(issuer, "/")
		}
		p2, err2 := oidc.NewProvider(cctx, alt)
		if err2 != nil {
			return nil, err
		}
		p = p2
	}
	oidcCache.issuer, oidcCache.p, oidcCache.at = issuer, p, time.Now()
	return p, nil
}

// ---------------------------------------------------------------- laufende Anmeldungen

type oidcFlow struct {
	verifier, nonce, next, redirect string
	linkUser                        int64 // > 0: Verknuepfen statt Anmelden
	expires                         time.Time
}

var oidcFlows struct {
	sync.Mutex
	m map[string]oidcFlow
}

func oidcPut(state string, f oidcFlow) {
	oidcFlows.Lock()
	defer oidcFlows.Unlock()
	if oidcFlows.m == nil {
		oidcFlows.m = map[string]oidcFlow{}
	}
	now := time.Now()
	for k, v := range oidcFlows.m {
		if now.After(v.expires) {
			delete(oidcFlows.m, k)
		}
	}
	if len(oidcFlows.m) < 1000 {
		oidcFlows.m[state] = f
	}
}

// oidcTake liefert eine Anmeldung genau einmal.
func oidcTake(state string) (oidcFlow, bool) {
	oidcFlows.Lock()
	defer oidcFlows.Unlock()
	f, ok := oidcFlows.m[state]
	delete(oidcFlows.m, state)
	return f, ok && time.Now().Before(f.expires)
}

func (s *Server) oauthConfig(p *oidc.Provider, o oidcSettings, redirect string) *oauth2.Config {
	scopes := strings.Fields(o.Scopes)
	hasOpenID := false
	for _, sc := range scopes {
		hasOpenID = hasOpenID || sc == oidc.ScopeOpenID
	}
	if !hasOpenID {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}
	return &oauth2.Config{ClientID: o.ClientID, ClientSecret: o.Secret, Endpoint: p.Endpoint(), RedirectURL: redirect, Scopes: scopes}
}

// oidcStart leitet zum Anbieter (linkUser > 0: Verknuepfen des angemeldeten Benutzers).
func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request, linkUser int64, next string) {
	v := s.view(r, "login.title")
	o := s.oidcSettings(r.Context())
	if !o.Enabled() {
		s.flash(w, r, "warning", v.T("sso.not_configured"))
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	p, err := oidcProvider(r.Context(), o.Issuer)
	if err != nil {
		s.log.Warn("oidc discovery failed", "issuer", o.Issuer, "err", err)
		s.flash(w, r, "danger", v.T("sso.unreachable"))
		back := "/login"
		if linkUser > 0 {
			back = "/settings/login"
		}
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	state, nonce, verifier := randomToken(24), randomToken(24), oauth2.GenerateVerifier()
	redirect := s.oidcCallbackURL(r, o)
	oidcPut(state, oidcFlow{verifier: verifier, nonce: nonce, next: safeNext(next), redirect: redirect, linkUser: linkUser, expires: time.Now().Add(oidcFlowTTL)})
	s.setCookie(w, r, oidcCookie, state, int(oidcFlowTTL.Seconds()))
	http.Redirect(w, r, s.oauthConfig(p, o, redirect).AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (s *Server) loginOIDC(w http.ResponseWriter, r *http.Request) {
	s.oidcStart(w, r, 0, r.URL.Query().Get("next"))
}

// errSSONotLinked: die SSO-Identitaet gehoert zu keinem lokalen Benutzer.
var errSSONotLinked = errors.New("sso identity not linked")

// loginOIDCCallback nimmt die Rueckleitung des Anbieters an: Verknuepfen oder Anmelden.
func (s *Server) loginOIDCCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v := s.view(r, "login.title")
	q := r.URL.Query()
	ip := s.clientIP(r)
	fail := func(back, key string, args ...any) {
		s.flash(w, r, "danger", v.T(key, args...))
		http.Redirect(w, r, back, http.StatusSeeOther)
	}
	state := q.Get("state")
	c, err := r.Cookie(oidcCookie)
	s.clearCookie(w, r, oidcCookie)
	f, ok := oidcTake(state)
	if !ok || err != nil || c.Value != state {
		fail("/login", "sso.expired")
		return
	}
	back := "/login"
	if f.linkUser > 0 {
		back = "/settings/login"
	}
	if e := q.Get("error"); e != "" {
		s.log.Info("oidc denied", "error", e, "desc", q.Get("error_description"))
		fail(back, "sso.denied", "error", truncate(e+": "+q.Get("error_description"), 200))
		return
	}
	if wait := s.limiter.retryAfter("ip:" + ipKey(ip)); wait > 0 {
		fail("/login", "login.ratelimited", "seconds", int(wait.Seconds())+1)
		return
	}
	o := s.oidcSettings(ctx)
	p, err := oidcProvider(ctx, o.Issuer)
	if err != nil || !o.Enabled() {
		fail(back, "sso.unreachable")
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tok, err := s.oauthConfig(p, o, f.redirect).Exchange(cctx, q.Get("code"), oauth2.VerifierOption(f.verifier))
	if err != nil {
		s.log.Warn("oidc code exchange failed", "err", err)
		fail(back, "sso.failed")
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := p.Verifier(&oidc.Config{ClientID: o.ClientID}).Verify(cctx, raw)
	if err != nil || idt.Nonce != f.nonce {
		s.log.Warn("oidc id token rejected", "err", err)
		fail(back, "sso.failed")
		return
	}
	var cl struct {
		Email    string `json:"email"`
		Username string `json:"preferred_username"`
		Name     string `json:"name"`
	}
	_ = idt.Claims(&cl)
	label := cl.Email
	if label == "" {
		label = cl.Username
	}
	if label == "" {
		label = cl.Name
	}
	provider := "oidc:" + idt.Issuer
	if f.linkUser > 0 {
		u, _ := s.Store.UserByID(ctx, f.linkUser)
		if u == nil {
			fail("/login", "sso.expired")
			return
		}
		switch err := s.Store.LinkIdentity(ctx, u.ID, provider, idt.Subject, truncate(label, 200)); {
		case errors.Is(err, store.ErrIdentityTaken):
			fail(back, "sso.taken")
			return
		case err != nil:
			s.fail(w, r, err)
			return
		}
		s.auditEntry(ctx, store.AuditEntry{Actor: u.Username, Action: "sso.link", Target: truncate(label, 100), Details: o.ButtonLabel(), IP: ip})
		s.flash(w, r, "success", v.T("sso.linked", "name", label))
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	uid, err := s.Store.IdentityUser(ctx, provider, idt.Subject)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var u *store.User
	if uid > 0 {
		u, _ = s.Store.UserByID(ctx, uid)
	}
	if u == nil {
		s.limiter.fail("ip:" + ipKey(ip))
		s.loginFailed(r, ip)
		s.auditEntry(ctx, store.AuditEntry{Actor: truncate(label, 64), Action: "login.failed", Details: "sso: " + errSSONotLinked.Error(), IP: ip})
		s.log.Warn("sso login without linked user", "label", label, "ip", ip)
		fail("/login", "sso.not_linked", "name", label)
		return
	}
	s.finishLogin(w, r, u, "sso "+o.ButtonLabel(), f.next)
}

// finishLogin startet nach einer Anmeldung ohne Passwort (SSO, Passkey) die Sitzung; den zweiten Faktor hat der
// Anbieter bzw. der Passkey schon geprueft.
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, u *store.User, how, next string) {
	if err := s.completeLogin(w, r, u, how); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, safeNext(next), http.StatusSeeOther)
}

// completeLogin: Sitzung, Sprache, letzte Anmeldung und Audit nach einer Anmeldung ohne Passwort.
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, u *store.User, how string) error {
	ctx := r.Context()
	if err := s.startSession(w, r, u.ID, false); err != nil {
		return err
	}
	if s.I18n.Has(u.Lang) {
		s.setCookie(w, r, langCookie, u.Lang, 365*24*3600)
	}
	_ = s.Store.TouchUserLogin(ctx, u.ID)
	ip := s.clientIP(r)
	s.auditEntry(ctx, store.AuditEntry{Actor: u.Username, Action: "login", Details: how, IP: ip})
	s.log.Info("login", "user", u.Username, "ip", ip, "via", how)
	return nil
}

// ---------------------------------------------------------------- Einstellungen

// oidcSave speichert die Einrichtung; ein leeres Secret laesst das gespeicherte stehen.
func (s *Server) oidcSave(ctx context.Context, in oidcSettings, keepSecret bool) error {
	in.Issuer = strings.TrimSpace(in.Issuer) // wie eingegeben, auch mit "/" am Ende (authentik); s. oidcProvider
	if in.Issuer != "" {
		u, err := url.Parse(in.Issuer)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return errOIDCIssuer
		}
	}
	in.BaseURL = strings.TrimRight(strings.TrimSpace(in.BaseURL), "/")
	if in.BaseURL != "" {
		u, err := url.Parse(in.BaseURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || (u.Path != "" && u.Path != "/") {
			return errOIDCBase
		}
	}
	kv := map[string]string{setOIDCIssuer: in.Issuer, setOIDCClient: strings.TrimSpace(in.ClientID), setOIDCLabel: truncate(strings.TrimSpace(in.Label), 60),
		setOIDCScopes: truncate(strings.Join(strings.Fields(in.Scopes), " "), 300), setOIDCBaseURL: in.BaseURL}
	if kv[setOIDCScopes] == "" {
		kv[setOIDCScopes] = oidcDefaultScop
	}
	if !keepSecret || strings.TrimSpace(in.Secret) != "" {
		enc := ""
		if strings.TrimSpace(in.Secret) != "" && s.Box != nil {
			enc = s.Box.Encrypt(strings.TrimSpace(in.Secret))
		}
		kv[setOIDCSecret] = enc
	}
	for k, val := range kv {
		if err := s.Store.SetSetting(ctx, k, val); err != nil {
			return err
		}
	}
	oidcCache.Lock()
	oidcCache.p = nil // neu einlesen
	oidcCache.Unlock()
	usercluster.SSOChanged(ctx, s.Store) // an die anderen Nodes (Bereich users/sso; die Rueckleit-Adresse bleibt je Node)
	return nil
}

var (
	errOIDCIssuer = errors.New("issuer must be an http(s) URL")
	errOIDCBase   = errors.New("base URL must be an http(s) URL without path")
)

func (s *Server) oidcLink(w http.ResponseWriter, r *http.Request) {
	s.oidcStart(w, r, currentUser(r).ID, "/settings/login")
}

func (s *Server) ssoUnlink(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "sso.title")
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	ok, err := s.Store.UnlinkIdentity(r.Context(), currentUser(r).ID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if ok {
		s.audit(r, "sso.unlink", strconv.FormatInt(id, 10), "")
		s.flash(w, r, "success", v.T("sso.unlinked"))
	}
	http.Redirect(w, r, "/settings/login", http.StatusSeeOther)
}
