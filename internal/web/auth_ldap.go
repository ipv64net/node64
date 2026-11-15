package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-ldap/ldap/v3"

	"github.com/ipv64net/node64/internal/authcfg"
	"github.com/ipv64net/node64/internal/ldapauth"
	"github.com/ipv64net/node64/internal/store"
)

// AD/LDAP-Anmeldung und SSO-Anlage ueber Gruppen (docs/PLAN-NODE64-BENUTZER.md, Teil C). Lokale Benutzer bleiben
// immer zuerst: nur wenn kein lokaler Benutzer passt und LDAP an ist, fragt die Anmeldung das Verzeichnis. Benutzer
// aus LDAP/SSO werden beim ersten Anmelden angelegt, wenn sie in einer zugeordneten Node64-Gruppe sind (feste UID aus
// der Quelle, eigene Rolle "read", wirksame Rolle aus den Gruppen). Ein lokaler Benutzer mit gleichem Namen wird nie
// uebernommen. Nur lokal fuer Node64 (kein Bezug zu ipv64.net).

// ldapBack: Reiter „Anmeldung“ der Benutzerverwaltung.
const ldapBack = "/settings/users#login"

func (s *Server) ldapRoutes() {
	s.mux.Handle("POST /settings/users/ldap", s.auth(s.ldapSettingsSave))
	s.mux.Handle("POST /settings/users/ldap/test", s.auth(s.ldapSettingsTest))
	s.mux.Handle("POST /settings/users/oidc-groups", s.auth(s.oidcGroupsSave))
	s.mux.Handle("GET /api/auth/ldap", s.auth(s.apiLDAPGet))
	s.mux.Handle("PUT /api/auth/ldap", s.auth(s.apiLDAPPut))
	s.mux.Handle("POST /api/auth/ldap/test", s.auth(s.apiLDAPTest))
	s.mux.Handle("GET /api/auth/oidc-groups", s.auth(s.apiOIDCGroupsGet))
	s.mux.Handle("PUT /api/auth/oidc-groups", s.auth(s.apiOIDCGroupsPut))
}

// ---------------------------------------------------------------- Anmeldung mit Passwort

// ldapLogin uebernimmt die Passwort-Anmeldung, wenn kein lokaler Benutzer passt und AD/LDAP an ist. false = nicht
// zustaendig (dann weiter wie bisher). Der Versuch ist schon verbucht (keys), bei Erfolg kommt er zurueck. Als
// Fehlversuch (Honeypot64-Meldung) zaehlen nur falsches Passwort und unbekannter Name; ist das Verzeichnis nicht
// erreichbar oder falsch eingerichtet, kommt der Versuch zurueck. Abgelehnte Benutzer verlieren ihre Gruppen aus LDAP.
func (s *Server) ldapLogin(w http.ResponseWriter, r *http.Request, v *View, u *store.User, username, password string, keys []string, start time.Time) bool {
	if u != nil && u.Source == store.SourceLocal {
		return false
	}
	ctx := r.Context()
	cfg := authcfg.LoadLDAP(ctx, s.Store)
	if !cfg.Enabled {
		return false
	}
	ip := s.clientIP(r)
	deny := func(action, reason string, counts bool) {
		if counts {
			s.loginFailed(r, ip)
		}
		s.auditEntry(ctx, store.AuditEntry{Actor: truncate(username, 64), Action: action, Details: "ldap: " + truncate(reason, 300), IP: ip})
		s.log.Warn("ldap login denied", "user", truncate(username, 64), "ip", ip, "reason", reason)
		failDelay(ctx, start)
		v.Flash = &Flash{Kind: "danger", Text: v.T("login.failed")}
		s.render(w, r, http.StatusUnauthorized, "login", v)
	}
	id, err := ldapauth.Authenticate(s.ldapContext(ctx), cfg, s.ldapBindPassword(cfg), username, password)
	switch {
	case errors.Is(err, ldapauth.ErrInvalidCredentials):
		deny("login.failed", ldapReason(err), true)
		return true
	case errors.Is(err, ldapauth.ErrUnknownUser), errors.Is(err, ldapauth.ErrDisabled):
		if u != nil && u.Source == store.SourceLDAP { // im Verzeichnis geloescht bzw. deaktiviert: Rolle aus LDAP entfaellt
			_ = s.Store.SetUserExtGroups(ctx, u.ID, nil)
		}
		deny("login.failed", ldapReason(err), errors.Is(err, ldapauth.ErrUnknownUser))
		return true
	case errors.Is(err, ldapauth.ErrAmbiguous):
		deny("login.failed", ldapReason(err), false)
		return true
	case err != nil: // Verzeichnis nicht erreichbar, ausgelastet oder falsch eingerichtet: kein Fehlversuch des Benutzers
		s.limiter.refund(keys...)
		s.auditEntry(ctx, store.AuditEntry{Actor: truncate(username, 64), Action: "login.ldap_error", Details: "ldap: " + truncate(ldapReason(err), 300), IP: ip})
		s.log.Warn("ldap login: directory error", "user", truncate(username, 64), "ip", ip, "err", ldapReason(err))
		failDelay(ctx, start)
		v.Flash = &Flash{Kind: "warning", Text: v.T("login.ldap_unavailable")}
		s.render(w, r, http.StatusServiceUnavailable, "login", v)
		return true
	}
	groups := s.ldapGroupUIDs(ctx, id.GroupDNs)
	if len(groups) == 0 {
		if old, _ := s.Store.UserByUID(ctx, store.ExternalUID(store.SourceLDAP, id.StableKey)); old != nil && old.Source == store.SourceLDAP {
			_ = s.Store.SetUserExtGroups(ctx, old.ID, nil)
		}
		deny("login.ldap_denied", "no matching node64 group", false)
		return true
	}
	nu, created, reason, err := s.extUser(r, store.SourceLDAP, store.ExternalUID(store.SourceLDAP, id.StableKey), id.Username, id.Email, groups)
	if err != nil {
		s.fail(w, r, err)
		return true
	}
	if nu == nil {
		deny("login.ldap_denied", reason, false)
		return true
	}
	s.limiter.refund(keys...)
	pending := nu.TOTPSecret != ""
	if err := s.startSession(w, r, nu.ID, pending); err != nil {
		s.fail(w, r, err)
		return true
	}
	if s.I18n.Has(nu.Lang) {
		s.setCookie(w, r, langCookie, nu.Lang, 365*24*3600)
	}
	details := "ldap"
	if created {
		details += ", created"
	}
	if pending {
		details += ", 2fa pending"
	}
	s.auditEntry(ctx, store.AuditEntry{Actor: nu.Username, Action: "login.ldap", Target: truncate(id.DN, 200), Details: details, IP: ip})
	if pending {
		http.Redirect(w, r, "/login/totp?next="+url.QueryEscape(v.Form["next"]), http.StatusSeeOther)
		return true
	}
	_ = s.Store.TouchUserLogin(ctx, nu.ID)
	s.log.Info("login", "user", nu.Username, "ip", ip, "via", "ldap")
	http.Redirect(w, r, v.Form["next"], http.StatusSeeOther)
	return true
}

// ldapReason: Grund fuer Audit und Log (nie mit Passwort).
func ldapReason(err error) string {
	for _, e := range []error{ldapauth.ErrInvalidCredentials, ldapauth.ErrUnknownUser, ldapauth.ErrDisabled, ldapauth.ErrAmbiguous, ldapauth.ErrBusy} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return err.Error()
}

// extUser sucht einen Benutzer aus LDAP bzw. SSO ueber seine feste UID oder legt ihn an (gemeinsam fuer beide
// Quellen); nil mit Grund = abgelehnt. Namen werden klein geschrieben, ein vorhandenes Konto gleichen Namens wird nie
// uebernommen. Bei vorhandenem Benutzer aktualisiert es die Gruppen und (falls geliefert) die E-Mail.
func (s *Server) extUser(r *http.Request, source, uid, name, email string, groups []string) (u *store.User, created bool, reason string, err error) {
	ctx := r.Context()
	email = truncate(strings.TrimSpace(email), 254)
	if u, err = s.Store.UserByUID(ctx, uid); err != nil {
		return nil, false, "", err
	}
	if u == nil {
		name = strings.ToLower(strings.TrimSpace(name))
		if !extNameOK(name) {
			s.log.Warn(source+" login: user name with characters node64 does not allow, not created", "user", truncate(name, 64))
			return nil, false, "invalid user name", nil
		}
		other, err := s.Store.UserByName(ctx, name)
		if err != nil {
			return nil, false, "", err
		}
		if other != nil { // nie ein vorhandenes Konto uebernehmen
			s.log.Warn(source+" login: user name already used by another node64 user, not taken over", "user", name, "source", other.Source)
			return nil, false, "user name taken by another node64 user", nil
		}
		u, err = s.Store.CreateUserWith(ctx, store.NewUser{UID: uid, Username: name, Lang: s.lang(r), Role: store.RoleRead,
			Source: source, Email: email, ExtGroupUIDs: groups})
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return nil, false, "user name taken by another node64 user", nil
			}
			return nil, false, "", err
		}
		if err := s.Store.SetUserExtGroups(ctx, u.ID, groups); err != nil { // Zeitpunkt der Pruefung festhalten
			return nil, false, "", err
		}
		u, err = s.Store.UserByID(ctx, u.ID)
		return u, true, "", err
	}
	if u.Source != source {
		s.log.Warn(source+" login: uid belongs to a user of another source", "user", u.Username, "source", u.Source)
		return nil, false, "uid belongs to a user of another source", nil
	}
	if u.Disabled {
		return nil, false, "user disabled in node64", nil
	}
	if err := s.Store.SetUserExtGroups(ctx, u.ID, groups); err != nil {
		return nil, false, "", err
	}
	if email != "" {
		if err := s.Store.SetUserEmail(ctx, u.ID, email); err != nil {
			return nil, false, "", err
		}
	}
	u, err = s.Store.UserByID(ctx, u.ID)
	return u, false, "", err
}

// extNameRe: Benutzername aus LDAP/SSO (so verlangt ihn der Cluster); unzulaessige Zeichen werden abgelehnt, nicht
// ersetzt.
var extNameRe = regexp.MustCompile(`^[\p{L}\p{N}._@+-]{1,128}$`)

func extNameOK(n string) bool { return extNameRe.MatchString(n) }

// ldapGroupUIDs: Node64-Gruppen, deren LDAP-Zuordnung zu einer der Gruppen des Benutzers passt.
func (s *Server) ldapGroupUIDs(ctx context.Context, dns []string) []string {
	list, _ := s.Store.Groups(ctx)
	var out []string
	for _, g := range list {
		if ldapGroupMatches(g, dns) {
			out = append(out, g.UID)
		}
	}
	return out
}

func ldapGroupMatches(g *store.Group, dns []string) bool {
	for _, m := range g.LDAPGroups {
		for _, dn := range dns {
			if ldapauth.MatchGroup(m, dn) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------- Nachpruefen ohne Passwort

// ldapCheckedGroups: Node64-Gruppen eines Benutzers nach ldapauth.Lookup (id nil = nicht gefunden); Grund, wenn er
// abzulehnen ist (dann keine Gruppen).
func (s *Server) ldapCheckedGroups(ctx context.Context, u *store.User, id *ldapauth.Identity) ([]string, string) {
	switch {
	case id == nil:
		return nil, "not found in directory"
	case store.ExternalUID(store.SourceLDAP, id.StableKey) != u.UID:
		return nil, "directory entry belongs to another account"
	case id.Disabled:
		return nil, "account disabled in directory"
	}
	groups := s.ldapGroupUIDs(ctx, id.GroupDNs)
	if len(groups) == 0 {
		return nil, "no matching node64 group"
	}
	return groups, ""
}

// ldapRecheck prueft einen Benutzer aus LDAP mit dem Dienstkonto nach (Passkey-Anmeldung) und uebernimmt seine
// Gruppen; geloescht, deaktiviert oder in keiner zugeordneten Gruppe = abgelehnt (Gruppen weg). Ist AD/LDAP aus oder
// das Verzeichnis nicht erreichbar, bleibt der letzte Stand; der gilt nur begrenzt (store.ExtMaxAgeLDAP).
func (s *Server) ldapRecheck(ctx context.Context, u *store.User) (bool, string) {
	cfg := authcfg.LoadLDAP(ctx, s.Store)
	if !cfg.Enabled {
		return true, ""
	}
	found, err := ldapauth.Lookup(s.ldapContext(ctx), cfg, s.ldapBindPassword(cfg), []string{u.Username})
	if err != nil {
		s.log.Warn("ldap recheck: directory error, last state kept", "user", u.Username, "err", ldapReason(err))
		return true, ""
	}
	groups, reason := s.ldapCheckedGroups(ctx, u, found[u.Username])
	_ = s.Store.SetUserExtGroups(ctx, u.ID, groups)
	return reason == "", reason
}

// ldapSyncGroups gleicht die Gruppen aller Benutzer aus LDAP mit dem Verzeichnis ab (housekeeping, stuendlich). So
// enden Rollen aus Gruppen auch ohne neue Anmeldung (Passkey, API-/MCP-Keys, laufende Sitzungen). Bei einem Fehler
// bleibt alles, wie es ist; die Gruppen laufen dann nach store.ExtMaxAgeLDAP ab.
func (s *Server) ldapSyncGroups(ctx context.Context) {
	cfg := authcfg.LoadLDAP(ctx, s.Store)
	if !cfg.Enabled {
		return
	}
	users, err := s.Store.Users(ctx)
	if err != nil {
		return
	}
	var list []*store.User
	var names []string
	for _, u := range users {
		if u.Source == store.SourceLDAP && !u.Disabled {
			list, names = append(list, u), append(names, u.Username)
		}
	}
	if len(list) == 0 {
		return
	}
	found, err := ldapauth.Lookup(s.ldapContext(ctx), cfg, s.ldapBindPassword(cfg), names)
	if err != nil {
		s.log.Warn("ldap group sync failed, last state kept", "err", ldapReason(err))
		return
	}
	for _, u := range list {
		groups, reason := s.ldapCheckedGroups(ctx, u, found[u.Username])
		sorted := slices.Clone(groups)
		slices.Sort(sorted)
		if !slices.Equal(sorted, u.ExtGroupUIDs) && !(len(sorted) == 0 && len(u.ExtGroupUIDs) == 0) {
			s.log.Info("ldap group sync: groups changed", "user", u.Username, "groups", len(groups), "reason", reason)
		}
		_ = s.Store.SetUserExtGroups(ctx, u.ID, groups)
	}
}

// ldapContext: eigene CAs der Zertifikatsverwaltung zusaetzlich vertrauen (internes AD mit eigener CA).
func (s *Server) ldapContext(ctx context.Context) context.Context {
	if s.Certs == nil {
		return ctx
	}
	pool, _ := s.Certs.TrustPoolKey(ctx)
	return ldapauth.WithRootCAs(ctx, pool)
}

// ldapBindPassword entschluesselt das Bind-Passwort (leer, wenn keines oder nicht lesbar).
func (s *Server) ldapBindPassword(cfg authcfg.LDAPConfig) string {
	if cfg.BindPasswordEnc == "" || s.Box == nil {
		return ""
	}
	pw, err := s.Box.Decrypt(cfg.BindPasswordEnc)
	if err != nil {
		s.log.Warn("ldap bind password unreadable (secret.key changed?)")
		return ""
	}
	return pw
}

// ---------------------------------------------------------------- SSO: Benutzer ueber Gruppen anlegen

// oidcGroupUser: SSO-Anlage ueber Gruppen (Schalter, Standard aus). Ohne verknuepftes Konto legt sie den Benutzer an,
// wenn der Gruppen-Claim zu einer Node64-Gruppe passt, und verknuepft die SSO-Identitaet; bei jeder Anmeldung
// aktualisiert sie die Gruppen. Schalter aus: u unveraendert (nur verknuepfte Konten). nil = abgelehnt.
func (s *Server) oidcGroupUser(r *http.Request, idt *oidc.IDToken, provider, label string, u *store.User) *store.User {
	ctx := r.Context()
	on, claim := authcfg.OIDCJIT(ctx, s.Store)
	if !on {
		return u
	}
	var cl map[string]any
	_ = idt.Claims(&cl)
	groups := s.oidcGroupUIDs(ctx, claimStrings(cl[claim]))
	if u != nil {
		if len(groups) == 0 && u.Source == store.SourceOIDC { // ueber Gruppen angelegt, jetzt in keiner mehr
			_ = s.Store.SetUserExtGroups(ctx, u.ID, nil)
			s.log.Warn("sso login: no matching node64 group", "user", u.Username)
			return nil
		}
		_ = s.Store.SetUserExtGroups(ctx, u.ID, groups)
		nu, _ := s.Store.UserByID(ctx, u.ID)
		return nu
	}
	uid := store.ExternalUID(store.SourceOIDC, idt.Issuer+"\x00"+idt.Subject)
	if len(groups) == 0 {
		if old, _ := s.Store.UserByUID(ctx, uid); old != nil && old.Source == store.SourceOIDC { // abgelehnt: Gruppen weg
			_ = s.Store.SetUserExtGroups(ctx, old.ID, nil)
		}
		return nil
	}
	email, _ := cl["email"].(string)
	name, _ := cl["preferred_username"].(string)
	if name = strings.TrimSpace(name); name == "" {
		name, _, _ = strings.Cut(strings.TrimSpace(email), "@")
	}
	nu, created, reason, err := s.extUser(r, store.SourceOIDC, uid, name, email, groups)
	if err != nil || nu == nil {
		s.log.Warn("sso login: user not accepted", "user", truncate(name, 64), "label", truncate(label, 64), "reason", reason, "err", err)
		return nil
	}
	if created {
		s.auditEntry(ctx, store.AuditEntry{Actor: nu.Username, Action: "login.oidc_created", Target: truncate(label, 100), Details: provider, IP: s.clientIP(r)})
	}
	if err := s.Store.LinkIdentity(ctx, nu.ID, provider, idt.Subject, truncate(label, 200)); err != nil {
		s.log.Warn("sso login: identity not linked", "user", nu.Username, "err", err)
		return nil
	}
	nu, _ = s.Store.UserByID(ctx, nu.ID)
	return nu
}

// claimStrings: Gruppen-Claim als Liste (String-Array oder ein String).
func claimStrings(v any) []string {
	var out []string
	switch x := v.(type) {
	case string:
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	}
	return out
}

// oidcGroupUIDs: Node64-Gruppen, deren SSO-Zuordnung einen der Gruppennamen enthaelt (ohne Gross/klein).
func (s *Server) oidcGroupUIDs(ctx context.Context, names []string) []string {
	list, _ := s.Store.Groups(ctx)
	var out []string
	for _, g := range list {
	match:
		for _, m := range g.OIDCGroups {
			for _, n := range names {
				if strings.EqualFold(strings.TrimSpace(m), n) {
					out = append(out, g.UID)
					break match
				}
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- Einstellungen

// ldapInput: Einstellungen aus Formular bzw. API (Bind-Passwort leer = unveraendert).
type ldapInput struct {
	Enabled      bool     `json:"enabled"`
	URLs         []string `json:"urls"`
	StartTLS     bool     `json:"starttls"`
	AllowPlain   bool     `json:"allow_plain"`
	SkipVerify   bool     `json:"skip_verify"`
	Profile      string   `json:"profile"`
	BindDN       string   `json:"bind_dn"`
	BindPassword string   `json:"bind_password"`
	BaseDN       string   `json:"base_dn"`
	UserFilter   string   `json:"user_filter"`
	Nested       bool     `json:"nested"`
	TimeoutSec   int      `json:"timeout_sec"`
}

// ldapFieldErr: ungueltige Angabe (Feld fuer die Meldung, Text ohne Geheimnisse).
type ldapFieldErr struct{ Field, Msg string }

func (e *ldapFieldErr) Error() string { return e.Field + ": " + e.Msg }

// ldapBuild prueft die Angaben und baut die Einstellung; das Bind-Passwort wird verschluesselt (leer = das
// gespeicherte bleibt, ohne Bind-DN entfaellt es).
func (s *Server) ldapBuild(ctx context.Context, in ldapInput) (authcfg.LDAPConfig, error) {
	c := authcfg.LDAPConfig{Enabled: in.Enabled, StartTLS: in.StartTLS, AllowPlain: in.AllowPlain, SkipVerify: in.SkipVerify,
		Profile: in.Profile, BindDN: strings.TrimSpace(in.BindDN), BaseDN: strings.TrimSpace(in.BaseDN),
		UserFilter: strings.TrimSpace(in.UserFilter), Nested: in.Nested, TimeoutSec: in.TimeoutSec}
	if c.Profile != authcfg.ProfileLDAP {
		c.Profile = authcfg.ProfileAD
	}
	for _, u := range in.URLs {
		if u = strings.TrimSpace(u); u != "" {
			c.URLs = append(c.URLs, u)
		}
	}
	switch {
	case len(c.URLs) > 10:
		return c, &ldapFieldErr{"urls", "at most 10 servers"}
	case c.Enabled && len(c.URLs) == 0:
		return c, &ldapFieldErr{"urls", "at least one server required"}
	case c.Enabled && c.BaseDN == "":
		return c, &ldapFieldErr{"base_dn", "base dn required"}
	case len(c.BindDN) > 512 || len(c.BaseDN) > 512:
		return c, &ldapFieldErr{"base_dn", "too long"}
	case c.TimeoutSec < 0 || c.TimeoutSec > 60:
		return c, &ldapFieldErr{"timeout_sec", "0 to 60 seconds"}
	}
	for _, u := range c.URLs {
		if err := ldapauth.CheckURL(c, u); err != nil {
			return c, &ldapFieldErr{"urls", err.Error()}
		}
	}
	if c.BaseDN != "" {
		if _, err := ldap.ParseDN(c.BaseDN); err != nil {
			return c, &ldapFieldErr{"base_dn", "invalid base dn"}
		}
	}
	if c.UserFilter != "" {
		if _, err := ldap.CompileFilter(strings.ReplaceAll(c.UserFilter, "%s", "x")); err != nil || !strings.Contains(c.UserFilter, "%s") || len(c.UserFilter) > 1024 {
			return c, &ldapFieldErr{"user_filter", "invalid filter (needs %s for the user name)"}
		}
	}
	old := authcfg.LoadLDAP(ctx, s.Store)
	switch {
	case c.BindDN == "":
		c.BindPasswordEnc = ""
	case in.BindPassword != "":
		if s.Box == nil {
			return c, &ldapFieldErr{"bind_password", "no secret key to encrypt the password"}
		}
		c.BindPasswordEnc = s.Box.Encrypt(in.BindPassword)
	case old.BindPasswordEnc != "" && !sameBindTarget(old, c):
		// gespeichertes Passwort nie an einen anderen Server bzw. fuer ein anderes Konto schicken
		return c, &ldapFieldErr{"bind_password", "bind password required again (server, account or tls changed)"}
	default:
		c.BindPasswordEnc = old.BindPasswordEnc
	}
	if c.Enabled && c.BindDN != "" && c.BindPasswordEnc == "" {
		return c, &ldapFieldErr{"bind_password", "bind password required"}
	}
	return c, nil
}

// sameBindTarget: Server, Dienstkonto und TLS-Einstellungen unveraendert (dann darf das gespeicherte Bind-Passwort
// weiter benutzt werden).
func sameBindTarget(a, b authcfg.LDAPConfig) bool {
	return slices.Equal(a.URLs, b.URLs) && a.BindDN == b.BindDN && a.StartTLS == b.StartTLS && a.AllowPlain == b.AllowPlain &&
		a.SkipVerify == b.SkipVerify
}

// ldapAuditDetails: Zusammenfassung ohne Passwort.
func ldapAuditDetails(c authcfg.LDAPConfig, pwChanged bool) string {
	b := func(x bool) string {
		if x {
			return "1"
		}
		return "0"
	}
	d := "enabled=" + b(c.Enabled) + " profile=" + c.Profile + " servers=" + strconv.Itoa(len(c.URLs)) + " starttls=" + b(c.StartTLS) +
		" plain=" + b(c.AllowPlain) + " skip_verify=" + b(c.SkipVerify) + " nested=" + b(c.Nested)
	if pwChanged {
		d += " bind_password=changed"
	}
	return d
}

func (s *Server) ldapForm(r *http.Request) ldapInput {
	f := s.formValues(r, "enabled", "urls", "starttls", "allow_plain", "skip_verify", "profile", "bind_dn", "base_dn", "user_filter", "nested", "timeout_sec")
	t, _ := strconv.Atoi(f["timeout_sec"])
	return ldapInput{Enabled: f["enabled"] == "1", URLs: strings.Fields(f["urls"]), StartTLS: f["starttls"] == "1", AllowPlain: f["allow_plain"] == "1",
		SkipVerify: f["skip_verify"] == "1", Profile: f["profile"], BindDN: f["bind_dn"], BindPassword: r.PostFormValue("bind_password"),
		BaseDN: f["base_dn"], UserFilter: f["user_filter"], Nested: f["nested"] == "1", TimeoutSec: t}
}

func (s *Server) ldapFieldFlash(w http.ResponseWriter, r *http.Request, v *View, err error) {
	var fe *ldapFieldErr
	if errors.As(err, &fe) {
		s.flash(w, r, "danger", v.T("ldap.err_"+fe.Field)+" ("+fe.Msg+")")
	} else {
		s.flash(w, r, "danger", v.T("ldap.err_save"))
	}
	http.Redirect(w, r, ldapBack, http.StatusSeeOther)
}

// POST /settings/users/ldap
func (s *Server) ldapSettingsSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v := s.view(r, "ldap.title")
	in := s.ldapForm(r)
	c, err := s.ldapBuild(ctx, in)
	if err != nil {
		s.ldapFieldFlash(w, r, v, err)
		return
	}
	if err := authcfg.SaveLDAP(ctx, s.Store, c); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "auth.ldap.update", "", ldapAuditDetails(c, in.BindPassword != "" && c.BindDN != ""))
	s.flash(w, r, "success", v.T("ldap.saved"))
	http.Redirect(w, r, ldapBack, http.StatusSeeOther)
}

// ldapTestOut: Ergebnis von „Verbindung testen“ mit den passenden Node64-Gruppen.
type ldapTestOut struct {
	OK      bool                `json:"ok"`
	Error   string              `json:"error,omitempty"`
	Result  ldapauth.TestResult `json:"result"`
	Matches []map[string]string `json:"matching_groups"`
}

func (s *Server) ldapTestRun(r *http.Request, c authcfg.LDAPConfig, bindPassword, probe string) ldapTestOut {
	ctx := r.Context()
	res, err := ldapauth.Test(s.ldapContext(ctx), c, bindPassword, probe)
	out := ldapTestOut{OK: err == nil, Result: res, Matches: []map[string]string{}}
	if err != nil {
		out.Error = err.Error()
	}
	if res.Found {
		list, _ := s.Store.Groups(ctx)
		for _, g := range list {
			if ldapGroupMatches(g, res.Groups) {
				out.Matches = append(out.Matches, map[string]string{"uid": g.UID, "name": g.Name, "role": g.Role})
			}
		}
	}
	details := "ok"
	if err != nil {
		details = "error: " + truncate(out.Error, 300)
	} else if probe != "" {
		details = "ok, probe " + truncate(probe, 64) + " found=" + strconv.FormatBool(res.Found)
	}
	s.audit(r, "auth.ldap.test", res.URL, details)
	return out
}

// testPassword: Bind-Passwort fuer einen Test (eingegeben, sonst das gespeicherte).
func (s *Server) testPassword(c authcfg.LDAPConfig, typed string) string {
	if typed != "" {
		return typed
	}
	return s.ldapBindPassword(c)
}

// POST /settings/users/ldap/test: prueft die Angaben im Formular (ohne zu speichern), Ergebnis als Meldung.
func (s *Server) ldapSettingsTest(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "ldap.title")
	in := s.ldapForm(r)
	c, err := s.ldapBuild(r.Context(), in)
	if err != nil {
		s.ldapFieldFlash(w, r, v, err)
		return
	}
	probe := strings.TrimSpace(r.PostFormValue("probe"))
	out := s.ldapTestRun(r, c, s.testPassword(c, in.BindPassword), probe)
	kind, text := "success", ldapTestText(v, out)
	if !out.OK {
		kind = "danger"
	} else if probe != "" && (!out.Result.Found || len(out.Matches) == 0) {
		kind = "warning"
	}
	s.flash(w, r, kind, truncate(text, 1000))
	http.Redirect(w, r, ldapBack, http.StatusSeeOther)
}

// ldapTestText: Ergebnis in einer Zeile fuer die Meldung.
func ldapTestText(v *View, out ldapTestOut) string {
	if !out.OK {
		return v.T("ldap.test_failed", "error", out.Error)
	}
	res := out.Result
	tls := "ldap.test_tls"
	if !res.TLS {
		tls = "ldap.test_plain"
	}
	t := v.T("ldap.test_ok", "url", res.URL) + " " + v.T(tls)
	if res.Probe == "" {
		return t
	}
	if !res.Found {
		return t + " " + v.T("ldap.test_notfound", "name", res.Probe)
	}
	t += " " + v.T("ldap.test_found", "name", res.Username, "dn", res.DN)
	if res.Disabled {
		t += " " + v.T("ldap.test_disabled")
	}
	groups := res.Groups
	more := ""
	if len(groups) > 5 {
		more = " (+" + strconv.Itoa(len(groups)-5) + ")"
		groups = groups[:5]
	}
	if len(groups) == 0 {
		t += " " + v.T("ldap.test_nogroups")
	} else {
		t += " " + v.T("ldap.test_groups", "groups", strings.Join(groups, "; ")+more)
	}
	if len(out.Matches) == 0 {
		return t + " " + v.T("ldap.test_nomatch")
	}
	var names []string
	for _, m := range out.Matches {
		names = append(names, m["name"])
	}
	return t + " " + v.T("ldap.test_match", "groups", strings.Join(names, ", "))
}

// oidcClaimOK: Name des Gruppen-Claims (z. B. groups, roles, https://example.com/groups).
func oidcClaimOK(c string) bool {
	if c == "" || len(c) > 100 {
		return false
	}
	for _, r := range c {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// oidcGroupsSet speichert Schalter und Claim-Name und meldet sie an den Cluster (Bereich users/sso).
func (s *Server) oidcGroupsSet(ctx context.Context, on bool, claim string) error {
	return authcfg.SaveOIDCJIT(ctx, s.Store, on, claim)
}

// POST /settings/users/oidc-groups
func (s *Server) oidcGroupsSave(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "ldap.title")
	f := s.formValues(r, "jit", "claim")
	claim := f["claim"]
	if claim == "" {
		claim = "groups"
	}
	if !oidcClaimOK(claim) {
		s.flash(w, r, "danger", v.T("ldap.err_claim"))
		http.Redirect(w, r, ldapBack, http.StatusSeeOther)
		return
	}
	on := f["jit"] == "1"
	if err := s.oidcGroupsSet(r.Context(), on, claim); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "auth.oidc.groups", claim, "jit="+strconv.FormatBool(on))
	s.flash(w, r, "success", v.T("ldap.oidc_saved"))
	http.Redirect(w, r, ldapBack, http.StatusSeeOther)
}

// ---------------------------------------------------------------- Karte (Reiter „Anmeldung“)

// ldapCardData: Daten fuer das Template ldap_card (ohne Bind-Passwort).
type ldapCardData struct {
	Cfg           authcfg.LDAPConfig
	URLs          string // eine Adresse je Zeile
	PasswordSet   bool
	DefaultFilter string // Vorgabe des eingestellten Profils (Platzhalter)
	FilterAD      string
	FilterLDAP    string
	LDAPGroups    int // Node64-Gruppen mit LDAP-Zuordnung
	OIDCGroups    int // Node64-Gruppen mit SSO-Zuordnung
	OIDCJIT       bool
	OIDCClaim     string
	OIDCEnabled   bool // SSO eingerichtet
}

// LDAPCard liefert die Daten fuer {{template "ldap_card" .}} (unabhaengig von der Seite, die sie einbindet).
func (v *View) LDAPCard() ldapCardData {
	ctx := context.Background()
	st := v.s.Store
	c := authcfg.LoadLDAP(ctx, st)
	d := ldapCardData{Cfg: c, URLs: strings.Join(c.URLs, "\n"), PasswordSet: c.BindPasswordEnc != "", DefaultFilter: c.DefaultFilter(),
		FilterAD: authcfg.LDAPConfig{Profile: authcfg.ProfileAD}.DefaultFilter(), FilterLDAP: authcfg.LDAPConfig{Profile: authcfg.ProfileLDAP}.DefaultFilter()}
	d.Cfg.BindPasswordEnc = ""
	if list, err := st.Groups(ctx); err == nil {
		for _, g := range list {
			if len(g.LDAPGroups) > 0 {
				d.LDAPGroups++
			}
			if len(g.OIDCGroups) > 0 {
				d.OIDCGroups++
			}
		}
	}
	d.OIDCJIT, d.OIDCClaim = authcfg.OIDCJIT(ctx, st)
	d.OIDCEnabled = v.s.oidcSettings(ctx).Enabled()
	return d
}

// ---------------------------------------------------------------- API

func ldapJSON(c authcfg.LDAPConfig) map[string]any {
	urls := c.URLs
	if urls == nil {
		urls = []string{}
	}
	return map[string]any{"enabled": c.Enabled, "urls": urls, "starttls": c.StartTLS, "allow_plain": c.AllowPlain, "skip_verify": c.SkipVerify,
		"profile": c.Profile, "bind_dn": c.BindDN, "bind_password_set": c.BindPasswordEnc != "", "base_dn": c.BaseDN, "user_filter": c.UserFilter,
		"default_filter": c.DefaultFilter(), "nested": c.Nested, "timeout_sec": c.TimeoutSec}
}

// GET /api/auth/ldap: Einstellungen ohne Bind-Passwort.
func (s *Server) apiLDAPGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, ldapJSON(authcfg.LoadLDAP(r.Context(), s.Store)))
}

func writeLDAPErr(w http.ResponseWriter, err error) {
	var fe *ldapFieldErr
	if errors.As(err, &fe) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": fe.Msg, "field": fe.Field})
		return
	}
	writeErr(w, 500, "internal error")
}

// PUT /api/auth/ldap: ganze Einstellung; bind_password leer oder fehlend = unveraendert.
func (s *Server) apiLDAPPut(w http.ResponseWriter, r *http.Request) {
	var in ldapInput
	if !decodeJSON(w, r, &in) {
		return
	}
	c, err := s.ldapBuild(r.Context(), in)
	if err != nil {
		writeLDAPErr(w, err)
		return
	}
	if err := authcfg.SaveLDAP(r.Context(), s.Store, c); err != nil {
		writeErr(w, 500, "database error")
		return
	}
	s.audit(r, "auth.ldap.update", "", ldapAuditDetails(c, in.BindPassword != "" && c.BindDN != ""))
	writeJSON(w, 200, ldapJSON(c))
}

// POST /api/auth/ldap/test {username, config}: Verbindung testen (config fehlt = gespeicherte Einstellung).
func (s *Server) apiLDAPTest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string     `json:"username"`
		Config   *ldapInput `json:"config"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	c := authcfg.LoadLDAP(r.Context(), s.Store)
	typed := ""
	if in.Config != nil {
		var err error
		if c, err = s.ldapBuild(r.Context(), *in.Config); err != nil {
			writeLDAPErr(w, err)
			return
		}
		typed = in.Config.BindPassword
	}
	writeJSON(w, 200, s.ldapTestRun(r, c, s.testPassword(c, typed), strings.TrimSpace(in.Username)))
}

// GET /api/auth/oidc-groups: SSO-Anlage ueber Gruppen.
func (s *Server) apiOIDCGroupsGet(w http.ResponseWriter, r *http.Request) {
	on, claim := authcfg.OIDCJIT(r.Context(), s.Store)
	writeJSON(w, 200, map[string]any{"enabled": on, "claim": claim})
}

// PUT /api/auth/oidc-groups {enabled, claim}
func (s *Server) apiOIDCGroupsPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled bool   `json:"enabled"`
		Claim   string `json:"claim"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	claim := strings.TrimSpace(in.Claim)
	if claim == "" {
		claim = "groups"
	}
	if !oidcClaimOK(claim) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "invalid claim name", "field": "claim"})
		return
	}
	if err := s.oidcGroupsSet(r.Context(), in.Enabled, claim); err != nil {
		writeErr(w, 500, "database error")
		return
	}
	s.audit(r, "auth.oidc.groups", claim, "jit="+strconv.FormatBool(in.Enabled))
	writeJSON(w, 200, map[string]any{"enabled": in.Enabled, "claim": claim})
}
