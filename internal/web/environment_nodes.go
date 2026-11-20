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

	"github.com/ipv64net/node64/internal/environment"
	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/store"
)

// Environment E2: hinzugefuegte Nodes (Adresse, optional Zugangsschluessel der anderen Node) und Zugaenge dieser Node
// fuer andere Nodes. Anlegen, Aendern und Zugaenge nur fuer Administratoren; Oeffnen duerfen alle (die Rolle wird auf
// der anderen Node begrenzt), angemeldet wird ueber einen Schluessel nur der Benutzer, der ihn eingetragen hat.

// envAddedRow ist eine hinzugefuegte Node in der Liste.
type envAddedRow struct {
	environment.AddedNode
	Status  environment.AddedStatus
	Display string // eigener Name, sonst gemeldeter Name, sonst Host
	Open    string // Adresse fuer den Browser
	Login   bool   // Oeffnen meldet mit dem eigenen Benutzer an
	Mine    bool   // Schluessel gehoert dem angemeldeten Benutzer
}

type envNodeData struct {
	Node    *environment.AddedNode // nil = neu
	Message string                 // Fehler beim Speichern
}

type envAccessData struct {
	Accesses []environment.Access
	Users    []*store.User
	Key      string // gerade erstellter Schluessel (nur einmal sichtbar)
	KeyName  string
	Message  string
}

func (s *Server) environmentNodeRoutes() {
	s.mux.Handle("GET /environment/nodes/new", s.admin(s.envNodeForm))
	s.mux.Handle("POST /environment/nodes", s.admin(s.envNodeCreate))
	s.mux.Handle("GET /environment/nodes/{uid}", s.admin(s.envNodeForm))
	s.mux.Handle("POST /environment/nodes/{uid}", s.admin(s.envNodeUpdate))
	s.mux.Handle("POST /environment/nodes/{uid}/delete", s.admin(s.envNodeDelete))
	s.mux.Handle("POST /environment/nodes/{uid}/open", s.auth(s.envNodeOpen))
	s.mux.Handle("GET /environment/access", s.admin(s.envAccessPage))
	s.mux.Handle("POST /environment/access", s.admin(s.envAccessCreate))
	s.mux.Handle("POST /environment/access/{id}/delete", s.admin(s.envAccessRevoke))
	// gebundene Endpunkte fuer andere Nodes (ohne Sitzung, Antwort mit dem Node-Schluessel signiert; Pfade wie
	// environment.PathStatus/PathTicket)
	s.mux.Handle("POST /peer/v2/env/status", s.Peer.HandleBound(s.envRemote(environment.PathStatus)))
	s.mux.Handle("POST /peer/v2/env/ticket", s.Peer.HandleBound(s.envRemote(environment.PathTicket)))
	// API
	s.mux.Handle("GET /api/environment", s.auth(s.apiEnvironment))
	s.mux.Handle("POST /api/environment/nodes", s.admin(s.apiEnvNodeCreate))
	s.mux.Handle("PUT /api/environment/nodes/{uid}", s.admin(s.apiEnvNodeUpdate))
	s.mux.Handle("DELETE /api/environment/nodes/{uid}", s.admin(s.apiEnvNodeDelete))
	s.mux.Handle("GET /api/environment/access", s.admin(s.apiEnvAccessList))
	s.mux.Handle("POST /api/environment/access", s.admin(s.apiEnvAccessCreate))
	s.mux.Handle("DELETE /api/environment/access/{id}", s.admin(s.apiEnvAccessRevoke))
}

// envRemote beantwortet eine gebundene Anfrage einer anderen Node; Fehlversuche je IP begrenzt wie die Anmeldung.
func (s *Server) envRemote(path string) func(w http.ResponseWriter, r *http.Request, bind, body []byte) {
	return func(w http.ResponseWriter, r *http.Request, bind, body []byte) {
		// Fehlversuche je Schluessel gebremst (ein widerrufener Schluessel bremst nur sich, nicht gueltige Schluessel
		// derselben Node); je IP zaehlen sie nur fuer Log und Audit-Log (wechselnde Schluessel fuellen sie nicht).
		// Eigene Toepfe: Fehlversuche anderer Nodes sperren nicht die Anmeldeseite.
		ip := s.clientIP(r)
		keyK, keyIP := "envkey:"+environment.KeyID(r.Header), "env:"+ipKey(ip)
		if wait := s.limiter.retryAfter(keyK); wait > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
			writeErr(w, http.StatusTooManyRequests, "too many failed attempts")
			return
		}
		res := s.Env.HandleRemote(r.Context(), path, r.Header, peer.BoundNonce(r), bind, body, ip, s.limiter.retryAfter(keyIP) > 0)
		if res.AuthFailed {
			s.limiter.fail(keyK, keyIP)
		}
		writeJSON(w, res.Status, res.Body)
	}
}

// envAddedRows liefert die hinzugefuegten Nodes mit Status (parallel abgefragt, je 3 s). Nodes, die diese Node oder
// ein Mitglied des Clusters sind, stehen schon dort.
func (s *Server) envAddedRows(ctx context.Context, u *store.User, members []environment.Node) []envAddedRow {
	list, err := s.Env.AddedNodes(ctx)
	if err != nil {
		s.log.Warn("environment nodes not readable", "err", err)
		return nil
	}
	skip := map[string]bool{s.Store.SettingOr(ctx, SettingNodeID, ""): true}
	for _, m := range members {
		skip[m.ID] = true
	}
	rows := make([]envAddedRow, 0, len(list))
	for _, n := range list {
		if n.NodeID != "" && skip[n.NodeID] {
			continue
		}
		rows = append(rows, envAddedRow{AddedNode: n, Open: cmpOr(n.BrowserURL, n.URL), Mine: u != nil && n.HasKey && u.UID != "" && u.UID == n.OwnerUID})
	}
	var wg sync.WaitGroup
	for i := range rows {
		wg.Add(1)
		go func(row *envAddedRow) {
			defer wg.Done()
			row.Status = s.Env.CachedStatus(ctx, &row.AddedNode)
		}(&rows[i])
	}
	wg.Wait()
	for i := range rows {
		r := &rows[i]
		r.Display = r.Name
		if r.Display == "" {
			r.Display = r.Status.Name
		}
		if r.Display == "" {
			if p, err := url.Parse(r.URL); err == nil {
				r.Display = p.Host
			}
		}
		r.Login = r.Mine && r.Status.KeyOK
	}
	return rows
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// envNodeOpen: hinzugefuegte Node oeffnen - mit Schluessel des angemeldeten Benutzers ueber ein Ticket, sonst zur
// Anmeldeseite der Node.
func (s *Server) envNodeOpen(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	n, err := s.Env.AddedNode(ctx, r.PathValue("uid"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	origin := ""
	if n != nil {
		origin = formOrigin(cmpOr(n.BrowserURL, n.URL))
	}
	if origin == "" {
		s.notFound(w, r)
		return
	}
	name := cmpOr(n.Name, origin)
	d := envOpenData{Name: name, URL: origin}
	result := "login page"
	if u := currentUser(r); u != nil && n.HasKey && u.UID != "" && u.UID == n.OwnerUID {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		tok, err := s.Env.RequestRemoteTicket(cctx, n, u.UID, s.role(r), browserOrigin(r)+"/environment")
		cancel()
		if err == nil {
			d.Ticket, result = tok, "ticket (access key)"
		} else {
			result += ": " + err.Error()
			s.log.Info("environment ticket not issued", "node", name, "err", err)
		}
	}
	s.audit(r, "environment.open", name, result)
	s.renderEnvOpen(w, r, d)
}

// ---------------------------------------------------------------- Formular

func (s *Server) envNodeForm(w http.ResponseWriter, r *http.Request) {
	d := envNodeData{}
	v := s.view(r, "environment.title")
	v.Form = map[string]string{}
	if uid := r.PathValue("uid"); uid != "" {
		n, err := s.Env.AddedNode(r.Context(), uid)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if n == nil {
			s.notFound(w, r)
			return
		}
		d.Node = n
		v.Form = map[string]string{"name": n.Name, "url": n.URL, "browser_url": n.BrowserURL, "description": n.Description}
	}
	v.Data = d
	s.render(w, r, http.StatusOK, "environment_node", v)
}

func envNodeInput(r *http.Request) environment.NodeInput {
	return environment.NodeInput{Name: r.PostFormValue("name"), URL: r.PostFormValue("url"), BrowserURL: r.PostFormValue("browser_url"),
		Description: r.PostFormValue("description"), Key: r.PostFormValue("key"), RemoveKey: r.PostFormValue("remove_key") == "1"}
}

// envNodeErr zeigt das Formular mit Fehler erneut (ohne den Schluessel, der muss neu eingegeben werden).
func (s *Server) envNodeErr(w http.ResponseWriter, r *http.Request, n *environment.AddedNode, in environment.NodeInput, err error) {
	v := s.view(r, "environment.title")
	v.Form = map[string]string{"name": in.Name, "url": in.URL, "browser_url": in.BrowserURL, "description": in.Description}
	msg, known := envErrText(v, err)
	if !known {
		s.log.Warn("environment node not saved", "err", err)
	}
	v.Data = envNodeData{Node: n, Message: msg}
	s.render(w, r, http.StatusUnprocessableEntity, "environment_node", v)
}

// envErrText: uebersetzte Meldung (known=false: unerwarteter Fehler, Text allgemein, Details ins Log).
func envErrText(v *View, err error) (msg string, known bool) {
	for _, e := range []struct {
		err error
		key string
	}{{environment.ErrInvalidURL, "environment.err_url"}, {environment.ErrHTTPSRequired, "environment.err_https"},
		{environment.ErrInvalidKey, "environment.err_key"}, {environment.ErrSelfKey, "environment.err_self_key"},
		{environment.ErrUnknownUser, "environment.err_user"}, {environment.ErrNameMissing, "environment.err_name"}} {
		if errors.Is(err, e.err) {
			return v.T(e.key), true
		}
	}
	return v.T("errors.internal"), false
}

func (s *Server) envNodeCreate(w http.ResponseWriter, r *http.Request) {
	in := envNodeInput(r)
	n, err := s.Env.AddNode(r.Context(), in, currentUser(r).UID)
	if err != nil {
		s.envNodeErr(w, r, nil, in, err)
		return
	}
	s.audit(r, "environment.node_add", n.URL, envKeyDetail(n))
	s.flash(w, r, "success", s.tr(r, "environment.node_saved"))
	http.Redirect(w, r, "/environment", http.StatusSeeOther)
}

func envKeyDetail(n *environment.AddedNode) string {
	if n.HasKey {
		return "with access key"
	}
	return "without access key"
}

func (s *Server) envNodeUpdate(w http.ResponseWriter, r *http.Request) {
	in := envNodeInput(r)
	old, err := s.Env.AddedNode(r.Context(), r.PathValue("uid"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if old == nil {
		s.notFound(w, r)
		return
	}
	n, err := s.Env.UpdateNode(r.Context(), old.UID, in, currentUser(r).UID)
	if err != nil {
		s.envNodeErr(w, r, old, in, err)
		return
	}
	s.audit(r, "environment.node_update", n.URL, envKeyDetail(n))
	s.flash(w, r, "success", s.tr(r, "environment.node_saved"))
	http.Redirect(w, r, "/environment", http.StatusSeeOther)
}

func (s *Server) envNodeDelete(w http.ResponseWriter, r *http.Request) {
	n, err := s.Env.AddedNode(r.Context(), r.PathValue("uid"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if n == nil {
		s.notFound(w, r)
		return
	}
	if _, err := s.Env.RemoveNode(r.Context(), n.UID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "environment.node_remove", n.URL, "")
	s.flash(w, r, "success", s.tr(r, "environment.node_removed"))
	http.Redirect(w, r, "/environment", http.StatusSeeOther)
}

// ---------------------------------------------------------------- Zugaenge

func (s *Server) envAccessView(w http.ResponseWriter, r *http.Request, status int, d envAccessData) {
	var err error
	if d.Accesses, err = s.Env.Accesses(r.Context()); err != nil {
		s.fail(w, r, err)
		return
	}
	users, err := s.Store.Users(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, u := range users {
		if !u.Disabled {
			d.Users = append(d.Users, u)
		}
	}
	v := s.view(r, "environment.access_title")
	v.Form = map[string]string{"user": currentUser(r).UID}
	v.Data = d
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, r, status, "environment_access", v)
}

func (s *Server) envAccessPage(w http.ResponseWriter, r *http.Request) {
	s.envAccessView(w, r, http.StatusOK, envAccessData{})
}

func (s *Server) envAccessCreate(w http.ResponseWriter, r *http.Request) {
	a, key, err := s.Env.CreateAccess(r.Context(), r.PostFormValue("name"), r.PostFormValue("user"), currentUser(r).Username)
	if err != nil {
		msg, known := envErrText(s.view(r, "environment.access_title"), err)
		if !known {
			s.log.Warn("environment access not created", "err", err)
		}
		s.envAccessView(w, r, http.StatusUnprocessableEntity, envAccessData{Message: msg})
		return
	}
	s.audit(r, "environment.access_create", a.Name, "user "+a.Username)
	s.envAccessView(w, r, http.StatusOK, envAccessData{Key: key, KeyName: a.Name})
}

func (s *Server) envAccessRevoke(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a, err := s.Env.AccessByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if a == nil {
		s.notFound(w, r)
		return
	}
	if _, err := s.Env.RevokeAccess(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "environment.access_revoke", a.Name, "user "+a.Username)
	s.flash(w, r, "success", s.tr(r, "environment.access_revoked"))
	http.Redirect(w, r, "/environment/access", http.StatusSeeOther)
}

// ---------------------------------------------------------------- API

type envAPINode struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	Origin    string `json:"origin"` // self, cluster, added
	Online    bool   `json:"online"`
	Version   string `json:"version,omitempty"`
	Update    string `json:"update,omitempty"`
	Suspended bool   `json:"suspended,omitempty"`
	Login     bool   `json:"login"` // Oeffnen meldet mit dem eigenen Benutzer an
	// nur hinzugefuegte
	BrowserURL  string `json:"browser_url,omitempty"`
	Description string `json:"description,omitempty"`
	HasKey      bool   `json:"has_key,omitempty"`
	KeyError    string `json:"key_error,omitempty"`
}

func (s *Server) apiEnvironment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := []envAPINode{{ID: s.Store.SettingOr(ctx, SettingNodeID, ""), Name: s.Store.SettingOr(ctx, SettingNodeName, "Node64"), URL: browserOrigin(r),
		Origin: "self", Online: true, Version: s.Version}}
	members := s.Env.Nodes(ctx)
	for _, m := range members {
		out = append(out, envAPINode{ID: m.ID, Name: m.Name, URL: m.URL, Origin: "cluster", Online: m.Online, Version: m.Version, Suspended: m.Suspended, Login: m.Login})
	}
	for _, a := range s.envAddedRows(ctx, currentUser(r), members) {
		out = append(out, envAPINode{ID: a.UID, Name: a.Display, URL: a.URL, Origin: "added", Online: a.Status.Online, Version: a.Status.Version,
			Update: a.Status.Update, Login: a.Login, BrowserURL: a.BrowserURL, Description: a.Description, HasKey: a.HasKey, KeyError: a.Status.KeyErr})
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": out})
}

func (s *Server) apiEnvNodeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, environment.ErrInvalidURL), errors.Is(err, environment.ErrHTTPSRequired), errors.Is(err, environment.ErrInvalidKey),
		errors.Is(err, environment.ErrSelfKey):
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, "database error")
	}
}

func (s *Server) apiEnvNodeCreate(w http.ResponseWriter, r *http.Request) {
	var in environment.NodeInput
	if !decodeJSON(w, r, &in) {
		return
	}
	n, err := s.Env.AddNode(r.Context(), in, currentUser(r).UID)
	if err != nil {
		s.apiEnvNodeErr(w, err)
		return
	}
	s.audit(r, "environment.node_add", n.URL, envKeyDetail(n))
	writeJSON(w, http.StatusCreated, n)
}

func (s *Server) apiEnvNodeUpdate(w http.ResponseWriter, r *http.Request) {
	var in environment.NodeInput
	if !decodeJSON(w, r, &in) {
		return
	}
	n, err := s.Env.UpdateNode(r.Context(), r.PathValue("uid"), in, currentUser(r).UID)
	if err != nil {
		s.apiEnvNodeErr(w, err)
		return
	}
	if n == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	s.audit(r, "environment.node_update", n.URL, envKeyDetail(n))
	writeJSON(w, http.StatusOK, n)
}

func (s *Server) apiEnvNodeDelete(w http.ResponseWriter, r *http.Request) {
	n, err := s.Env.AddedNode(r.Context(), r.PathValue("uid"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	if n == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if _, err := s.Env.RemoveNode(r.Context(), n.UID); err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	s.audit(r, "environment.node_remove", n.URL, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiEnvAccessList(w http.ResponseWriter, r *http.Request) {
	list, err := s.Env.Accesses(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	if list == nil {
		list = []environment.Access{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) apiEnvAccessCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string `json:"name"`
		UserUID string `json:"user_uid"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.UserUID) == "" {
		in.UserUID = currentUser(r).UID // Standard: ich selbst
	}
	a, key, err := s.Env.CreateAccess(r.Context(), in.Name, in.UserUID, currentUser(r).Username)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.audit(r, "environment.access_create", a.Name, "user "+a.Username)
	writeJSON(w, http.StatusCreated, map[string]any{"access": a, "key": key})
}

func (s *Server) apiEnvAccessRevoke(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a, err := s.Env.AccessByID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	if a == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if _, err := s.Env.RevokeAccess(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	s.audit(r, "environment.access_revoke", a.Name, "user "+a.Username)
	w.WriteHeader(http.StatusNoContent)
}
