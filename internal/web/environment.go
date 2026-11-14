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

const envEnterPath = "/environment/enter" // ohne CSRF-Pruefung (middleware.go), das Ticket ist die Berechtigung

type envData struct {
	SelfName    string
	SelfURL     string
	SelfVersion string
	Nodes       []environment.Node
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
}

func (s *Server) environmentPage(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "environment.title")
	v.Data = envData{SelfName: s.Store.SettingOr(r.Context(), SettingNodeName, "Node64"), SelfURL: browserOrigin(r), SelfVersion: s.Version,
		Nodes: s.Env.Nodes(r.Context())}
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
	// das Formular geht an die andere Node: nur fuer diese Antwort dorthin erlauben
	h := w.Header()
	h.Set("Content-Security-Policy", strings.Replace(h.Get("Content-Security-Policy"), "form-action 'self'", "form-action 'self' "+origin, 1))
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
	if !sameHost(sourceOrigin(r), t.Back) {
		deny("-", "ticket not sent from "+t.FromName)
		return
	}
	u, err := s.Store.UserByUID(ctx, t.UID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if u == nil || u.Disabled {
		deny("-", "user unknown or locked (from "+t.FromName+")")
		return
	}
	// eine bestehende Anmeldung eines anderen Benutzers nicht stillschweigend ersetzen
	if cur := currentUser(r); cur != nil && cur.ID != u.ID {
		s.log.Warn("environment ticket rejected", "reason", "other user signed in", "ip", ip)
		s.auditEntry(ctx, store.AuditEntry{Actor: cur.Username, Action: "login.environment_failed", Target: t.FromName,
			Details: "other user signed in (ticket for " + u.Username + ")", IP: ip})
		s.flash(w, r, "warning", s.tr(r, "environment.other_user", "name", t.FromName))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
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

// sameHost: gleicher Host samt Port. Das Schema zaehlt nicht, weil die oeffnende Node hinter einem Proxy mit TLS ihren
// Rueckweg mit http:// bildet, der Browser aber https:// schickt.
func sameHost(a, b string) bool {
	pa, err1 := url.Parse(a)
	pb, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && pa.Host != "" && strings.EqualFold(pa.Host, pb.Host)
}

// envCap begrenzt die Rolle einer Sitzung, die ueber Environment entstanden ist (env_sessions.max_role); die
// Rechtepruefung (roles.go) sieht so nur die begrenzte Rolle. Bei einem Lesefehler „nur lesen“.
func (s *Server) envCap(ctx context.Context, sessionID string) context.Context {
	if s.Env == nil {
		return ctx
	}
	o, err := s.Env.SessionOrigin(ctx, sessionID)
	if err != nil {
		return context.WithValue(ctx, ctxRole, store.RoleRead)
	}
	if o == nil {
		return ctx
	}
	role, _ := ctx.Value(ctxRole).(string)
	return context.WithValue(ctx, ctxRole, environment.MinRole(role, o.MaxRole))
}
