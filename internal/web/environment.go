package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/environment"
	"github.com/ipv64net/node64/internal/store"
)

// Seite „Environment“ (internal/environment): diese Node und die Mitglieder des Clusters mit „Oeffnen“. Oeffnen holt
// bei der anderen Node ein Anmelde-Ticket und schickt es per Formular direkt an deren /environment/enter (der
// Browser spricht immer selbst mit der anderen Node, kein Ticket in URL oder Verlauf).

const (
	envEnterPath     = "/environment/enter" // ohne CSRF-Pruefung (middleware.go), das Ticket ist die Berechtigung
	envConfirmCookie = "n64_envconfirm"     // Ticket, das auf dieser Node noch bestaetigt werden muss
	ctxEnvOrigin     = ctxKey(110)          // Herkunft einer ueber Environment geoeffneten Sitzung (*environment.Origin)
)

type envData struct {
	SelfName    string
	SelfURL     string
	SelfVersion string
	Nodes       []environment.Node
	Added       []envAddedRow // E2: hinzugefuegte Nodes (environment_nodes.go)
	Admin       bool
}

type envOpenData struct {
	Name   string
	URL    string
	Ticket string // leer = Anmeldeseite der anderen Node
}

func (s *Server) environmentRoutes() {
	if s.Env == nil || s.Peer == nil {
		return
	}
	s.mux.Handle("GET /environment", s.auth(s.environmentPage))
	s.mux.Handle("POST /environment/open/{id}", s.auth(s.environmentOpen))
	s.mux.HandleFunc("POST "+envEnterPath, s.environmentEnter)
	s.mux.HandleFunc("POST /environment/confirm", s.environmentConfirm)
	s.environmentNodeRoutes()
}

func (s *Server) environmentPage(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "environment.title")
	d := envData{SelfName: s.Store.SettingOr(r.Context(), SettingNodeName, "Node64"), SelfURL: browserOrigin(r), SelfVersion: s.Version,
		Nodes: s.Env.Nodes(r.Context()), Admin: s.isAdmin(r)}
	d.Added = s.envAddedRows(r.Context(), currentUser(r), d.Nodes)
	v.Data = d
	s.render(w, r, http.StatusOK, "environment", v)
}

// browserOrigin: Adresse dieser Node, wie der Browser sie gerade aufruft.
func browserOrigin(r *http.Request) string {
	if r.TLS != nil {
		return "https://" + r.Host
	}
	return "http://" + r.Host
}

// formOrigin: Ursprung einer Node-Adresse fuer form-action ("" = ungueltig).
func formOrigin(raw string) string {
	p, err := url.Parse(raw)
	if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" || strings.ContainsAny(p.Host, " ;,'\"\r\n") {
		return ""
	}
	return p.Scheme + "://" + p.Host
}

// environmentOpen holt bei der anderen Node ein Ticket und liefert die Seite, die es dorthin schickt; ohne Ticket
// (Benutzer-Abgleich aus, Benutzer dort unbekannt oder gesperrt, Node ausgesetzt, aeltere Version) geht es zur
// Anmeldeseite der anderen Node.
func (s *Server) environmentOpen(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	n := s.Env.Member(ctx, r.PathValue("id"))
	origin := ""
	if n != nil {
		origin = formOrigin(n.URL)
	}
	if origin == "" {
		s.notFound(w, r)
		return
	}
	d := envOpenData{Name: n.Name, URL: origin}
	result := "login page"
	if u := currentUser(r); u != nil && u.UID != "" && n.Login {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		tok, err := s.Env.RequestTicket(cctx, n.ID, environment.TicketRequest{UID: u.UID, Role: s.role(r), Back: browserOrigin(r) + "/environment"})
		cancel()
		if err == nil {
			d.Ticket, result = tok, "ticket"
		} else {
			result += ": " + err.Error()
			s.log.Info("environment ticket not issued", "node", n.Name, "err", err)
		}
	}
	s.audit(r, "environment.open", n.Name, result)
	s.renderEnvOpen(w, r, d)
}

// renderEnvOpen liefert die Seite, die das Ticket an die andere Node schickt (bzw. zu deren Anmeldeseite fuehrt).
func (s *Server) renderEnvOpen(w http.ResponseWriter, r *http.Request, d envOpenData) {
	// das Formular geht an die andere Node: nur fuer diese Antwort dorthin erlauben
	h := w.Header()
	h.Set("Content-Security-Policy", strings.Replace(h.Get("Content-Security-Policy"), "form-action 'self'", "form-action 'self' "+d.URL, 1))
	h.Set("Referrer-Policy", "origin") // nur der Ursprung: /environment/enter prueft ihn (bei no-referrer kaeme Origin "null")
	v := s.view(r, "environment.title")
	v.Data = d
	s.render(w, r, http.StatusOK, "environment_open", v)
}

// environmentEnter loest ein Ticket ein (Browser kommt von der anderen Node) und legt eine Sitzung mit begrenzter
// Rolle an. Ungueltig, abgelaufen, schon benutzt, Benutzer inzwischen gesperrt oder geloescht: Anmeldeseite mit Hinweis.
func (s *Server) environmentEnter(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := s.clientIP(r)
	deny := func(actor, why string) {
		s.log.Warn("environment ticket rejected", "reason", why, "ip", ip)
		s.auditEntry(ctx, store.AuditEntry{Actor: actor, Action: "login.environment_failed", Details: why, IP: ip})
		http.Redirect(w, r, "/login?env=1", http.StatusSeeOther)
	}
	t, ok := s.Env.Redeem(r.PostFormValue("ticket"))
	if !ok {
		deny("-", "invalid, used or expired ticket")
		return
	}
	// Login-CSRF: das Formular muss von der oeffnenden Node kommen (Ursprung wie der Rueckweg im Ticket), sonst koennte
	// eine fremde Seite ein eigenes Ticket unterschieben und den Browser mit fremdem Benutzer anmelden
	if !environment.SameHost(sourceOrigin(r), t.Back) {
		deny("-", "ticket not sent from "+t.FromName)
		return
	}
	u := s.envUser(w, r, t, deny)
	if u == nil {
		return
	}
	// Login-CSRF: kommt der Rueckweg aus dem (frei waehlbaren) Host der Anfrage an die oeffnende Node statt aus einer
	// hier bekannten Adresse, erst auf dieser Node bestaetigen lassen (eigenes CSRF-Token, keine Einbettung moeglich)
	if !t.Trusted {
		tok, err := s.Env.Hold(t)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		s.setCookie(w, r, envConfirmCookie, tok, int(environment.TicketTTL.Seconds()))
		d := map[string]string{"Username": u.Username, "From": t.FromName}
		if !store.IsAdmin(environment.MinRole(t.Role, s.Store.EffectiveRole(ctx, u))) {
			d["ReadOnly"] = "1"
		}
		v := s.view(r, "environment.confirm_title")
		v.Data = d
		v.User, v.Nav = nil, nil
		w.Header().Set("Cache-Control", "no-store")
		s.render(w, r, http.StatusOK, "environment_confirm", v)
		return
	}
	s.envLogin(w, r, t, u)
}

// environmentConfirm: Anmeldung ueber Environment auf dieser Node bestaetigt (Formular dieser Node mit CSRF).
func (s *Server) environmentConfirm(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	deny := func(actor, why string) {
		s.log.Warn("environment ticket rejected", "reason", why, "ip", ip)
		s.auditEntry(r.Context(), store.AuditEntry{Actor: actor, Action: "login.environment_failed", Details: why, IP: ip})
		http.Redirect(w, r, "/login?env=1", http.StatusSeeOther)
	}
	tok := ""
	if c, err := cookie(r, envConfirmCookie); err == nil {
		tok = c.Value
	}
	s.clearCookie(w, r, envConfirmCookie)
	t, ok := s.Env.Redeem(tok)
	if !ok {
		deny("-", "confirmation expired")
		return
	}
	if u := s.envUser(w, r, t, deny); u != nil {
		s.envLogin(w, r, t, u)
	}
}

// envUser prueft den Benutzer eines Tickets (nil = beantwortet): unbekannt oder gesperrt, ein anderer Benutzer schon
// angemeldet, oder auf dieser Node stehen Pflichten aus (Passwort beim ersten Anmelden, 2FA einrichten) - die gehen
// nur mit eigener Anmeldung hier, denn in einer Environment-Sitzung lassen sich keine Zugangsdaten aendern.
func (s *Server) envUser(w http.ResponseWriter, r *http.Request, t *environment.Ticket, deny func(actor, why string)) *store.User {
	ctx := r.Context()
	u, err := s.Store.UserByUID(ctx, t.UID)
	if err != nil {
		s.fail(w, r, err)
		return nil
	}
	if u == nil || u.Disabled {
		deny("-", "user unknown or locked (from "+t.FromName+")")
		return nil
	}
	// eine bestehende Anmeldung eines anderen Benutzers nicht stillschweigend ersetzen
	if cur := currentUser(r); cur != nil && cur.ID != u.ID {
		s.log.Warn("environment ticket rejected", "reason", "other user signed in", "ip", s.clientIP(r))
		s.auditEntry(ctx, store.AuditEntry{Actor: cur.Username, Action: "login.environment_failed", Target: t.FromName,
			Details: "other user signed in (ticket for " + u.Username + ")", IP: s.clientIP(r)})
		s.flash(w, r, "warning", s.tr(r, "environment.other_user", "name", t.FromName))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return nil
	}
	if (u.MustChange && u.Source == store.SourceLocal) || s.needs2FA(ctx, u) {
		deny(u.Username, "sign-in duties open here (new password or 2FA setup)")
		return nil
	}
	return u
}

// envLogin legt die Sitzung mit begrenzter Rolle an.
func (s *Server) envLogin(w http.ResponseWriter, r *http.Request, t *environment.Ticket, u *store.User) {
	ctx := r.Context()
	ip := s.clientIP(r)
	role := environment.MinRole(t.Role, s.Store.EffectiveRole(ctx, u))
	id, err := s.newSession(w, r, u.ID, false) // zweiter Faktor ist auf der oeffnenden Node erledigt
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Env.SaveSession(ctx, id, environment.Origin{MaxRole: role, FromNode: t.FromNode, FromName: t.FromName, Back: t.Back}); err != nil {
		_ = s.Store.DeleteSession(ctx, id) // ohne Vermerk keine Sitzung (sonst ohne Begrenzung der Rolle)
		s.clearCookie(w, r, sessionCookie)
		s.fail(w, r, err)
		return
	}
	if s.I18n.Has(u.Lang) {
		s.setCookie(w, r, langCookie, u.Lang, 365*24*3600)
	}
	_ = s.Store.TouchUserLogin(ctx, u.ID)
	s.auditEntry(ctx, store.AuditEntry{Actor: u.Username, Action: "login.environment", Target: t.FromName, Details: "role " + role, IP: ip})
	s.log.Info("login via environment", "user", u.Username, "from", t.FromName, "role", role, "ip", ip)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// sourceOrigin: Ursprung der Seite, die das Formular geschickt hat (Origin, ersatzweise Referer; "" = unbekannt).
func sourceOrigin(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
		return o
	}
	return r.Header.Get("Referer")
}

// envCap begrenzt die Rolle einer Sitzung, die ueber Environment entstanden ist (env_sessions.max_role); die
// Rechtepruefung (roles.go) sieht so nur die begrenzte Rolle. Die Herkunft steht danach im Kontext (envOrigin, einmal
// je Anfrage gelesen). Bei einem Lesefehler „nur lesen“ und wie eine Environment-Sitzung behandelt.
func (s *Server) envCap(ctx context.Context, sessionID string) context.Context {
	if s.Env == nil {
		return ctx
	}
	o, err := s.Env.SessionOrigin(ctx, sessionID)
	if err != nil {
		o = &environment.Origin{MaxRole: store.RoleRead}
	}
	if o == nil {
		return ctx
	}
	role, _ := ctx.Value(ctxRole).(string)
	ctx = context.WithValue(ctx, ctxEnvOrigin, o)
	return context.WithValue(ctx, ctxRole, environment.MinRole(role, o.MaxRole))
}

// envOrigin: Herkunft der Sitzung, wenn sie ueber Environment geoeffnet wurde (nil = normale Anmeldung).
func envOrigin(r *http.Request) *environment.Origin {
	o, _ := r.Context().Value(ctxEnvOrigin).(*environment.Origin)
	return o
}

// envCredentials: Routen, die Zugangsdaten anlegen, aendern oder entfernen (Passwort, 2FA, Passkeys, SSO-Verknuepfung,
// API- und MCP-Keys). In einer ueber Environment geoeffneten Sitzung gesperrt: solche Zugangsdaten gaelten danach
// ohne die Begrenzung der Sitzung (z. B. ein API-Key mit der vollen Rolle des Benutzers hier).
var envCredentials = func() *http.ServeMux {
	m := http.NewServeMux()
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for _, p := range []string{
		"POST /settings/password",
		"POST /login/password",
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
		"POST /api/keys",
		"DELETE /api/keys/{id}",
		"POST /api/mcp/keys",
		"DELETE /api/mcp/keys/{id}",
	} {
		m.Handle(p, ok)
	}
	return m
}()

// envForbidden: Anfrage aendert Zugangsdaten in einer ueber Environment geoeffneten Sitzung (dann 403 geschickt).
func (s *Server) envForbidden(w http.ResponseWriter, r *http.Request) bool {
	if envOrigin(r) == nil {
		return false
	}
	if _, pat := envCredentials.Handler(r); pat == "" {
		return false
	}
	name := "-"
	if u := currentUser(r); u != nil {
		name = u.Username
	}
	s.log.Warn("credentials change denied in environment session", "user", name, "method", r.Method, "path", r.URL.Path, "ip", s.clientIP(r))
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeErr(w, http.StatusForbidden, "not allowed in a session opened via environment")
		return true
	}
	s.errorPage(w, r, http.StatusForbidden, "errors.env_credentials")
	return true
}
