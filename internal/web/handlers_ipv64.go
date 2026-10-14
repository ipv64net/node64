package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
)

// Zentraler ipv64-API-Key des Containers (Einstellungen); Module bedienen sich ueber ipv64api.Key.

func (s *Server) ipv64Routes() {
	if s.IPv64 == nil {
		return
	}
	s.mux.Handle("POST /settings/ipv64", s.auth(s.ipv64KeySave))
	s.mux.Handle("POST /settings/ipv64/delete", s.auth(s.ipv64KeyDelete))
}

func (s *Server) ipv64KeySave(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	me, err := s.IPv64.Set(ctx, r.PostFormValue("apikey"))
	switch {
	case errors.Is(err, ipv64api.ErrFormat):
		s.flash(w, r, "danger", s.tr(r, "ipv64key.invalid"))
	case errors.Is(err, ipv64api.ErrUnauthorized):
		s.flash(w, r, "danger", s.tr(r, "ipv64key.rejected"))
	case err != nil:
		s.flash(w, r, "danger", s.tr(r, "ipv64key.failed", "error", err.Error()))
	default:
		s.audit(r, "settings.ipv64_key", "", "account="+me.Account())
		s.flash(w, r, "success", s.tr(r, "ipv64key.saved", "account", me.Account()))
	}
	http.Redirect(w, r, "/settings#ipv64", http.StatusSeeOther)
}

func (s *Server) ipv64KeyDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.IPv64.Clear(r.Context()); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "settings.ipv64_key_removed", "", "")
	s.flash(w, r, "success", s.tr(r, "ipv64key.removed"))
	http.Redirect(w, r, "/settings#ipv64", http.StatusSeeOther)
}
