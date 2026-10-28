package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/usercluster"
)

// Benutzer & Anmeldung im Cluster (internal/usercluster): gleichnamige, aber verschiedene Benutzer stehen auf der
// Seite Cluster zur Wahl (wie die ACME-Konten), bis dahin behaelt jede Node ihren. Dazu die Liste der Benutzer auf der
// Seite Anmeldung mit Loeschen (geht bei eingeschaltetem Bereich an die anderen Nodes).

// userConflictRow ist ein Benutzername mit seinen Versionen im Cluster.
type userConflictRow struct {
	Username string
	Versions []userVersionRow
}

// userVersionRow ist eine Version mit dem Namen ihrer Node.
type userVersionRow struct {
	usercluster.Version
	Name string
}

// userChoices: gleichnamige, verschiedene Benutzer im Cluster (die eigene Version zuerst), nur von Nodes, die noch
// Mitglied sind; nil = keine Abweichung.
func (s *Server) userChoices(ctx context.Context, members []peer.Member) []userConflictRow {
	if s.Users == nil {
		return nil
	}
	names := map[string]string{}
	for _, x := range members {
		names[x.NodeID] = x.Name
	}
	var out []userConflictRow
	for _, c := range s.Users.Conflicts(ctx) {
		row := userConflictRow{Username: c.Username}
		for _, v := range c.Versions {
			name, ok := names[v.Node]
			if !v.Own && !ok {
				continue // Node nicht mehr im Cluster
			}
			if name == "" {
				name = v.Node
			}
			row.Versions = append(row.Versions, userVersionRow{Version: v, Name: name})
		}
		if len(row.Versions) > 1 {
			out = append(out, row)
		}
	}
	return out
}

// userConflictsAPI: Abweichungen fuer die API.
func userConflictsAPI(list []userConflictRow) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, c := range list {
		vs := make([]map[string]any, 0, len(c.Versions))
		for _, v := range c.Versions {
			vs = append(vs, map[string]any{"uid": v.UID, "node_id": v.Node, "node_name": v.Name, "created_at": v.CreatedAt, "two_fa": v.TwoFA,
				"sso_accounts": v.Identities, "own": v.Own})
		}
		out = append(out, map[string]any{"username": c.Username, "versions": vs})
	}
	return out
}

// chooseUser fuehrt die Wahl aus (die eigene Sitzung bleibt) und vermerkt sie samt verworfener Versionen im Audit-Log.
func (s *Server) chooseUser(r *http.Request, uid string) (string, []usercluster.Version, error) {
	name, dropped, err := s.Users.Choose(r.Context(), uid, sessionID(r))
	if err != nil {
		return "", nil, err
	}
	parts := make([]string, 0, len(dropped))
	for _, d := range dropped {
		node := d.Node
		if d.Own {
			node = "self"
		}
		parts = append(parts, node+":"+d.UID[:min(12, len(d.UID))])
	}
	s.audit(r, "user.cluster.choose", name, "uid="+uid[:min(12, len(uid))]+" dropped="+strings.Join(parts, ","))
	return name, dropped, nil
}

// groupUsers waehlt bei gleichnamigen, verschiedenen Benutzern die Version fuer den ganzen Cluster.
func (s *Server) groupUsers(w http.ResponseWriter, r *http.Request) {
	if s.Users == nil {
		s.groupBack(w, r, "danger", s.tr(r, "errors.validation"))
		return
	}
	_, _, err := s.chooseUser(r, r.PostFormValue("uid"))
	if errors.Is(err, usercluster.ErrChoice) {
		s.groupBack(w, r, "danger", s.tr(r, "cluster.users_unknown"))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.groupBack(w, r, "success", s.tr(r, "cluster.users_chosen"))
}

// apiGroupUsers: wie groupUsers per API (Kennung aus user_conflicts).
func (s *Server) apiGroupUsers(w http.ResponseWriter, r *http.Request) {
	if s.Peer == nil || s.Users == nil {
		writeErr(w, http.StatusServiceUnavailable, "not available")
		return
	}
	var in struct {
		UID string `json:"uid"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.UID == "" {
		writeErr(w, http.StatusUnprocessableEntity, "uid is required")
		return
	}
	name, dropped, err := s.chooseUser(r, in.UID)
	if errors.Is(err, usercluster.ErrChoice) {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		s.log.Error("cluster user choice", "err", err)
		writeErr(w, 500, "database error")
		return
	}
	out := make([]map[string]any, 0, len(dropped))
	for _, d := range dropped {
		out = append(out, map[string]any{"uid": d.UID, "node_id": d.Node, "own": d.Own})
	}
	writeJSON(w, 200, map[string]any{"username": name, "chosen": in.UID, "dropped": out})
}

// userDelete loescht einen anderen Benutzer dieser Node (den eigenen nie, damit immer einer bleibt); mit
// eingeschaltetem Bereich „Benutzer“ auch auf den anderen Nodes.
func (s *Server) userDelete(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "sso.title")
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	u, err := s.Store.UserByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if u == nil || u.ID == currentUser(r).ID {
		s.flash(w, r, "danger", v.T("sso.user_self"))
		http.Redirect(w, r, "/settings/login#users", http.StatusSeeOther)
		return
	}
	if _, err := s.Store.DeleteUser(r.Context(), u.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "user.delete", u.Username, "")
	s.flash(w, r, "success", v.T("sso.user_deleted", "name", u.Username))
	http.Redirect(w, r, "/settings/login#users", http.StatusSeeOther)
}
