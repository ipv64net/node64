package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/store"
)

// Benutzer per API: eigener Benutzer (alle), Benutzerverwaltung nur fuer Administratoren (Liste, Loeschen hier, Anlegen,
// Aendern, Passwort setzen, 2FA zuruecksetzen und Gruppen in useradmin.go). Eigenes Passwort, eigene 2FA, Passkeys und
// die Anmelde-Konfiguration (OIDC, Forward-Auth) gibt es bewusst nur in der Oberflaeche.

func (s *Server) apiUserRoutes() {
	s.mux.Handle("GET /api/users", s.admin(s.apiUsers))
	s.mux.Handle("GET /api/users/me", s.auth(s.apiUserMe))
	s.mux.Handle("PUT /api/users/me", s.auth(s.apiUserMePut))
	s.mux.Handle("DELETE /api/users/{id}", s.admin(s.apiUserDelete))
}

// userJSON: Benutzer ohne Hash und Geheimnisse; role ist die wirksame Rolle (eigene und Gruppen), own_role die eigene.
func (s *Server) userJSON(ctx context.Context, u *store.User, self int64) map[string]any {
	orEmpty := func(l []string) []string {
		if l == nil {
			return []string{}
		}
		return l
	}
	out := map[string]any{"id": u.ID, "uid": u.UID, "username": u.Username, "lang": u.Lang, "timezone": u.Timezone,
		"totp": u.TOTPSecret != "", "self": u.ID == self, "created_at": u.CreatedAt,
		"role": s.Store.EffectiveRole(ctx, u), "own_role": u.Role, "source": u.Source, "disabled": u.Disabled, "email": u.Email,
		"groups": orEmpty(u.GroupUIDs), "ext_groups": orEmpty(u.ExtGroupUIDs), "must_change": u.MustChange}
	if !u.LastLoginAt.IsZero() {
		out["last_login_at"] = u.LastLoginAt
	}
	return out
}

// GET /api/users: alle Benutzer dieser Node (z. B. aus dem Cluster).
func (s *Server) apiUsers(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.Users(r.Context())
	if err != nil {
		writeErr(w, 500, "database error")
		return
	}
	me := currentUser(r).ID
	out := make([]map[string]any, 0, len(list))
	for _, u := range list {
		out = append(out, s.userJSON(r.Context(), u, me))
	}
	writeJSON(w, 200, out)
}

// GET /api/users/me: der angemeldete Benutzer bzw. der Inhaber des API-Keys.
func (s *Server) apiUserMe(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	writeJSON(w, 200, s.userJSON(r.Context(), u, u.ID))
}

// PUT /api/users/me {lang, timezone}: eigene Sprache und Zeitzone (fehlende Felder bleiben; die Zeitzone gilt bei
// Administratoren auch fuer die Node).
func (s *Server) apiUserMePut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Lang     *string `json:"lang"`
		Timezone *string `json:"timezone"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	u := currentUser(r)
	lang, tz := u.Lang, u.Timezone
	if in.Lang != nil {
		lang = strings.TrimSpace(*in.Lang)
		if !s.I18n.Has(lang) {
			writeErr(w, http.StatusUnprocessableEntity, "unknown language "+lang)
			return
		}
	}
	if in.Timezone != nil {
		tz = strings.TrimSpace(*in.Timezone)
		if tz != "" && !validTimezone(tz) {
			writeErr(w, http.StatusUnprocessableEntity, "invalid timezone")
			return
		}
	}
	if err := s.saveUserPrefs(r, u, lang, tz, tz != u.Timezone); err != nil {
		writeErr(w, 500, "database error")
		return
	}
	nu, err := s.Store.UserByID(r.Context(), u.ID)
	if err != nil || nu == nil {
		writeErr(w, 500, "database error")
		return
	}
	writeJSON(w, 200, s.userJSON(r.Context(), nu, nu.ID))
}

// DELETE /api/users/{id}: anderen Benutzer loeschen (den eigenen nie); mit eingeschaltetem Bereich „Benutzer“ auch
// auf den anderen Nodes.
func (s *Server) apiUserDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_, err := s.deleteOtherUser(r, id)
	switch {
	case errors.Is(err, errUserUnknown):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, errUserSelf), errors.Is(err, errLastAdmin):
		writeErr(w, http.StatusConflict, err.Error())
	case err != nil:
		writeErr(w, 500, "database error")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
