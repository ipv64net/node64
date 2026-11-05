package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ipv64net/node64/internal/selfupdate"
)

// Selbst-Update (internal/selfupdate): Einstellungen → Ueber Node64 und API /api/update.

func (s *Server) updateRoutes() {
	s.mux.Handle("POST /settings/updates/check", s.auth(s.settingsUpdateCheck))
	s.mux.Handle("POST /settings/updates/apply", s.auth(s.settingsUpdateApply))
	s.mux.Handle("POST /settings/updates/reset", s.auth(s.settingsUpdateReset))
	s.mux.Handle("GET /api/update", s.auth(s.apiUpdate))
	s.mux.Handle("POST /api/update/check", s.auth(s.apiUpdateCheck))
	s.mux.Handle("POST /api/update/apply", s.auth(s.apiUpdateApply))
}

// updateView: Zustand fuer die Einstellungen.
type updateView struct {
	selfupdate.Status
	Mode     string
	Channel  string
	Chosen   bool // Kanal selbst gewaehlt (sonst Automatisch: folgt der laufenden Version)
	Window   string
	Modes    []string
	Channels []string
	Latest   *selfupdate.Latest
}

func (s *Server) updateGetter(ctx context.Context) selfupdate.Getter {
	return func(k, d string) string { return s.Store.SettingOr(ctx, k, d) }
}

func (s *Server) updateViewOf(ctx context.Context) *updateView {
	if s.Updater == nil {
		return nil
	}
	get := s.updateGetter(ctx)
	st := s.Updater.Status()
	v := &updateView{Status: st, Mode: selfupdate.Mode(get), Channel: selfupdate.Channel(get, st.Running), Window: selfupdate.Window(get),
		Modes: selfupdate.Modes, Channels: selfupdate.Channels, Chosen: containsString(selfupdate.Channels, get(selfupdate.SetChannel, ""))}
	if raw := s.Store.SettingOr(ctx, selfupdate.SetLatest, ""); raw != "" {
		var l selfupdate.Latest
		// nur ein Ergebnis fuer den aktuellen Kanal; "neuer" gegen die laufende Version (nach einem Update lief sonst
		// die eben installierte Version weiter als "neu verfuegbar")
		if json.Unmarshal([]byte(raw), &l) == nil && (l.Version != "" || l.Error != "") && (l.Channel == "" || l.Channel == v.Channel) {
			l.Newer = l.Version != "" && s.Updater.Newer(&selfupdate.Manifest{Version: l.Version})
			v.Latest = &l
		}
	}
	return v
}

func (s *Server) updateSet(ctx context.Context) func(k, v string) error {
	return func(k, v string) error { return s.Store.SetSetting(ctx, k, v) }
}

func (s *Server) settingsUpdateCheck(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "settings.title")
	if s.Updater == nil {
		http.NotFound(w, r)
		return
	}
	cctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	m, err := s.Updater.CheckNow(cctx, s.updateGetter(r.Context()), s.updateSet(r.Context()))
	switch {
	case err != nil:
		s.flash(w, r, "danger", v.T("settings.upd.check_failed", "error", err.Error()))
	case s.Updater.Newer(m):
		s.flash(w, r, "info", v.T("settings.update_available", "version", m.Version))
	default:
		s.flash(w, r, "success", v.T("settings.update_none", "version", m.Version))
	}
	http.Redirect(w, r, "/settings#about", http.StatusSeeOther)
}

// applyLatest: Manifest holen und die Installation im Hintergrund starten (startet bei Erfolg neu). Download und
// Sicherung der Datenbank dauern laenger, als ein Reverse Proxy auf die Antwort wartet; ein Fehler steht danach in
// updates.latest (ApplyError) und im Log.
func (s *Server) applyLatest(r *http.Request) (string, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	m, err := s.Updater.CheckNow(ctx, s.updateGetter(ctx), s.updateSet(ctx))
	switch {
	case err != nil:
		s.Log.Slog().Warn("self-update failed", "module", "update", "err", err)
		return "", err
	case !s.Updater.Newer(m):
		return m.Version, errNotNewer
	case s.Updater.Busy():
		return m.Version, selfupdate.ErrBusy
	}
	s.audit(r, "update.apply", m.Version, "")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := s.Updater.Apply(ctx, m); err != nil && !errors.Is(err, selfupdate.ErrBusy) {
			s.Log.Slog().Warn("self-update failed", "module", "update", "version", m.Version, "err", err)
			s.noteApplyFailed(ctx, m.Version, err)
		}
	}()
	return m.Version, nil
}

// noteApplyFailed haengt den Fehler an das letzte Pruefergebnis (Anzeige in den Einstellungen und in der API).
func (s *Server) noteApplyFailed(ctx context.Context, ver string, err error) {
	var l selfupdate.Latest
	if json.Unmarshal([]byte(s.Store.SettingOr(ctx, selfupdate.SetLatest, "")), &l) != nil || l.Version != ver {
		return
	}
	l.ApplyError = err.Error()
	b, _ := json.Marshal(l)
	_ = s.Store.SetSetting(ctx, selfupdate.SetLatest, string(b))
}

var errNotNewer = errors.New("no newer version")

func (s *Server) settingsUpdateApply(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "settings.title")
	if s.Updater == nil {
		http.NotFound(w, r)
		return
	}
	ver, err := s.applyLatest(r)
	switch {
	case errors.Is(err, errNotNewer):
		s.flash(w, r, "success", v.T("settings.update_none", "version", ver))
	case err != nil:
		s.flash(w, r, "danger", v.T("settings.upd.apply_failed", "error", err.Error()))
	default:
		s.flash(w, r, "success", v.T("settings.upd.applying", "version", ver))
	}
	http.Redirect(w, r, "/settings#about", http.StatusSeeOther)
}

func (s *Server) settingsUpdateReset(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "settings.title")
	if s.Updater == nil {
		http.NotFound(w, r)
		return
	}
	if err := s.Updater.Reset(); err != nil {
		s.flash(w, r, "danger", v.T("settings.upd.apply_failed", "error", err.Error()))
	} else {
		s.audit(r, "update.reset", "", "")
		s.flash(w, r, "success", v.T("settings.upd.reset_done"))
	}
	http.Redirect(w, r, "/settings#about", http.StatusSeeOther)
}

// GET /api/update: laufende Version, Herkunft, Einstellungen, letztes Pruefergebnis.
func (s *Server) apiUpdate(w http.ResponseWriter, r *http.Request) {
	if s.Updater == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "self-update not available"})
		return
	}
	writeJSON(w, http.StatusOK, s.updateViewOf(r.Context()))
}

// POST /api/update/check: jetzt pruefen.
func (s *Server) apiUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if s.Updater == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "self-update not available"})
		return
	}
	cctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if _, err := s.Updater.CheckNow(cctx, s.updateGetter(r.Context()), s.updateSet(r.Context())); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, s.updateViewOf(r.Context()))
}

// POST /api/update/apply: neueste Version des Kanals installieren; Node64 startet danach neu (202).
func (s *Server) apiUpdateApply(w http.ResponseWriter, r *http.Request) {
	if s.Updater == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "self-update not available"})
		return
	}
	ver, err := s.applyLatest(r)
	switch {
	case errors.Is(err, errNotNewer):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already up to date", "version": ver})
	case errors.Is(err, selfupdate.ErrBusy):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case err != nil:
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "restarting", "version": ver})
	}
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
