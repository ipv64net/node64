package honeypot

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/module"
)

// Lokale API der Fruehwarnung (wie die Seite in watch_ui.go): eigene Netze bei ipv64 auflisten, eintragen und
// entfernen, Treffer sofort abrufen. Die Liste kommt live von ipv64 (zentraler API-Key).

func (m *Module) watchAPIRoutes(mux *http.ServeMux, g module.Guards) {
	api := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /api/honeypot/watch", api(m.apiWatch))
	mux.Handle("POST /api/honeypot/watch", api(m.apiWatchAdd))
	mux.Handle("POST /api/honeypot/watch/check", api(m.apiWatchCheck))
	mux.Handle("DELETE /api/honeypot/watch/{id}", api(m.apiWatchDelete))
}

// watchAPIFail: Fehler von ipv64 mit Code (4xx von ipv64 unveraendert, sonst 502).
func watchAPIFail(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	var ae *ipv64api.APIError
	if errors.As(err, &ae) && ae.Status >= 400 && ae.Status < 500 {
		status = ae.Status
	}
	code := ipv64api.ErrorCode(err)
	if code == "" {
		code = "api"
	}
	apiJSON(w, status, map[string]string{"error": code, "message": err.Error()})
}

func watchNoKey(w http.ResponseWriter) {
	apiJSON(w, http.StatusConflict, map[string]string{"error": "no_key", "message": "no ipv64 API key"})
}

// apiWatch liefert Grenzen, eigene Netze, automatisch ueberwachte DynDNS-IPs (von ipv64) und den Zustand des Abrufs
// samt letzter Treffer (lokal).
func (m *Module) apiWatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, key := m.api(ctx)
	if c == nil || key == "" {
		watchNoKey(w)
		return
	}
	lctx, cancel := context.WithTimeout(ctx, watchAPITimeout)
	defer cancel()
	list, err := c.ThreatWatchList(lctx, key)
	if err != nil {
		m.log.Warn("honeypot watch: list failed", "err", err)
		watchAPIFail(w, err)
		return
	}
	if list.Networks == nil {
		list.Networks = []ipv64api.ThreatWatchNetwork{}
	}
	if list.DynDNS == nil {
		list.DynDNS = []ipv64api.ThreatWatchDynDNS{}
	}
	st := m.watchLoad(ctx)
	if st.Hits == nil {
		st.Hits = []watchHit{}
	}
	apiJSON(w, http.StatusOK, map[string]any{"limits": list.Limits, "networks": list.Networks, "dyndns": list.DynDNS,
		"full": list.Limits.Max > 0 && len(list.Networks) >= list.Limits.Max, "running": m.running() != nil, "state": st})
}

// apiWatchAdd traegt ein Netz (oder eine einzelne IP) bei ipv64 ein; Pruefung wie auf der Seite.
func (m *Module) apiWatchAdd(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CIDR  string `json:"cidr"`
		Label string `json:"label"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	ctx := r.Context()
	c, key := m.api(ctx)
	if c == nil || key == "" {
		watchNoKey(w)
		return
	}
	label, okLabel := cleanLabel(in.Label)
	cidr, code := normalizeCIDR(in.CIDR)
	if code == "" && !okLabel {
		code = "label"
	}
	if code != "" {
		apiJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": code})
		return
	}
	actx, cancel := context.WithTimeout(ctx, watchAPITimeout)
	defer cancel()
	n, err := c.ThreatWatchAdd(actx, key, cidr, label)
	if err != nil {
		m.log.Warn("honeypot watch: add failed", "cidr", cidr, "err", err)
		watchAPIFail(w, err)
		return
	}
	m.log.Info("watch network added", "cidr", n.CIDR, "id", n.ID, "via", "api", "by", m.g.Actor(r))
	m.g.Audit(r, "honeypot.watch.add", n.CIDR, label)
	apiJSON(w, http.StatusCreated, n)
}

// apiWatchDelete entfernt ein Netz bei ipv64 (404 = schon weg).
func (m *Module) apiWatchDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		apiJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_id"})
		return
	}
	ctx := r.Context()
	c, key := m.api(ctx)
	if c == nil || key == "" {
		watchNoKey(w)
		return
	}
	actx, cancel := context.WithTimeout(ctx, watchAPITimeout)
	defer cancel()
	if err := c.ThreatWatchDelete(actx, key, id); err != nil {
		m.log.Warn("honeypot watch: delete failed", "id", id, "err", err)
		watchAPIFail(w, err)
		return
	}
	m.log.Info("watch network removed", "id", id, "via", "api", "by", m.g.Actor(r))
	m.g.Audit(r, "honeypot.watch.delete", "#"+strconv.FormatInt(id, 10), strconv.FormatInt(id, 10))
	w.WriteHeader(http.StatusNoContent)
}

// apiWatchCheck ruft die Treffer sofort ab (auch nach 401/403, z. B. nach neuem Key).
func (m *Module) apiWatchCheck(w http.ResponseWriter, r *http.Request) {
	n, _, err := m.watchCheck(r.Context(), true)
	switch {
	case errors.Is(err, errWatchNoKey):
		watchNoKey(w)
	case err != nil:
		watchAPIFail(w, err)
	default:
		m.log.Info("watch checked", "hits", n, "via", "api", "by", m.g.Actor(r))
		apiJSON(w, http.StatusOK, map[string]any{"new_hits": n, "state": m.watchLoad(r.Context())})
	}
}
