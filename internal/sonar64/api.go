package sonar64

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/sonar"
)

// Lokale JSON-API des Moduls (Doku: internal/web/static/openapi.json, Tag "Sonar64"). Ist das Modul aus: 404.

func (m *Module) apiRoutes(mux *http.ServeMux, g module.Guards) {
	api := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /api/sonar64/status", api(m.apiStatus))
	mux.Handle("GET /api/sonar64/recent", api(m.apiRecent))
	mux.Handle("GET /api/sonar64/inbound", api(m.apiInbound))
	mux.Handle("GET /api/sonar64/settings", api(m.apiSettings))
	mux.Handle("PUT /api/sonar64/settings", api(m.apiSettingsPut))
}

// StatusInfo ist der Zustand fuer GET /api/sonar64/status.
type StatusInfo struct {
	Version     string       `json:"version"`
	Running     bool         `json:"running"`
	StartedAt   time.Time    `json:"started_at,omitzero"`
	KeySet      bool         `json:"key_set"` // zentraler ipv64-API-Key eingetragen (noetig zum Einschalten)
	Participate bool         `json:"participate"`
	Node        sonar.Status `json:"node"` // Zustand des Knotens (leer ohne Teilnahme)
	Error       string       `json:"error,omitempty"`
	PortError   string       `json:"port_error,omitempty"` // UDP 6464 belegt: nur ausgehend
	Me          *sonar.Me    `json:"me"`                   // eigener Knoten bei ipv64 (null = noch unbekannt)
	MeError     string       `json:"me_error,omitempty"`
	Trust       trustView    `json:"trust"`
	PublicURL   string       `json:"public_url,omitempty"`
}

func (m *Module) apiStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s := m.LoadSettings(ctx)
	out := StatusInfo{Version: version, Running: m.running(), KeySet: m.apiKey(ctx) != "", Participate: s.Participate}
	m.mu.Lock()
	out.StartedAt, out.Error, out.PortError, out.MeError = m.started, m.runErr, m.portErr, m.meErr
	m.mu.Unlock()
	if rn := m.runner(); rn != nil {
		out.Node = rn.Status()
	}
	out.Me = m.cachedMe()
	out.Trust = trustOf(out.Me, s.Measured, time.Now())
	if out.Me != nil {
		out.PublicURL = publicURL(out.Me.Slug)
	}
	apiJSON(w, http.StatusOK, out)
}

// recentInfo ist die Antwort von GET /api/sonar64/recent.
type recentInfo struct {
	Results   []resultView  `json:"results"`
	Inbound   []inboundView `json:"inbound"` // live auf UDP 6464 beantwortet
	Responder bool          `json:"responder"`
}

func (m *Module) apiRecent(w http.ResponseWriter, r *http.Request) {
	n := 50
	if v := r.URL.Query().Get("n"); v != "" {
		x, err := strconv.Atoi(v)
		if err != nil || x < 1 {
			apiErr(w, http.StatusBadRequest, "invalid n")
			return
		}
		n = min(x, recentMax)
	}
	out := recentInfo{Results: []resultView{}, Inbound: []inboundView{}}
	if rn := m.runner(); rn != nil {
		res, in := rn.Recent(n)
		m.mu.Lock()
		rows := m.inRows
		m.mu.Unlock()
		out.Results, out.Inbound, out.Responder = resultViews(res), inboundViews(in, rows), rn.Status().Responder
	}
	apiJSON(w, http.StatusOK, out)
}

func (m *Module) apiInbound(w http.ResponseWriter, r *http.Request) {
	var since time.Time
	if v := r.URL.Query().Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			apiErr(w, http.StatusBadRequest, "invalid since (RFC 3339)")
			return
		}
		since = t
	}
	rows, err := m.inboundRows(r.Context(), since)
	if errors.Is(err, ErrNotReady) {
		apiJSON(w, http.StatusOK, map[string]any{"rows": []sonar.InboundRow{}, "ready": false})
		return
	}
	if err != nil {
		m.log.Warn("sonar64 inbound", "err", err)
		apiErr(w, http.StatusBadGateway, "ipv64 not reachable")
		return
	}
	if rows == nil {
		rows = []sonar.InboundRow{}
	}
	apiJSON(w, http.StatusOK, map[string]any{"rows": rows, "ready": true})
}

// SettingsView ist die Einstellung fuer GET/PUT /api/sonar64/settings (lokal plus Profil bei ipv64).
type SettingsView struct {
	Participate bool     `json:"participate"`
	Measured    bool     `json:"measured"`
	Budget      string   `json:"budget"`
	Quiet       string   `json:"quiet"`
	Name        string   `json:"name"`
	Lat         *float64 `json:"lat"`
	Lon         *float64 `json:"lon"`
	Access      string   `json:"access"`
	Device      string   `json:"device"`
}

// settingsPut ist der Body von PUT /api/sonar64/settings (fehlende Felder bleiben unveraendert).
type settingsPut struct {
	Participate   *bool    `json:"participate"`
	Measured      *bool    `json:"measured"`
	Budget        *string  `json:"budget"`
	Quiet         *string  `json:"quiet"`
	Name          string   `json:"name"`
	Lat           *float64 `json:"lat"`
	Lon           *float64 `json:"lon"`
	ClearLocation bool     `json:"clear_location"`
	Access        string   `json:"access"`
	Device        string   `json:"device"`
}

func (p settingsPut) profile() (Profile, bool) {
	pr := Profile{Name: p.Name, Lat: p.Lat, Lon: p.Lon, ClearLoc: p.ClearLocation, Access: p.Access, Device: p.Device}
	return pr, pr.Name != "" || pr.Lat != nil || pr.Lon != nil || pr.ClearLoc || pr.Access != "" || pr.Device != ""
}

func (m *Module) settingsView(r *http.Request) SettingsView {
	s := m.LoadSettings(r.Context())
	v := SettingsView{Participate: s.Participate, Measured: s.Measured, Budget: s.Budget, Quiet: s.Quiet}
	if me := m.cachedMe(); me != nil {
		v.Name, v.Lat, v.Lon, v.Access, v.Device = me.Name, me.Lat, me.Lon, me.Access, me.Device
	}
	return v
}

func (m *Module) apiSettings(w http.ResponseWriter, r *http.Request) {
	apiJSON(w, http.StatusOK, m.settingsView(r))
}

func (m *Module) apiSettingsPut(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in settingsPut
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	prof, hasProf := in.profile()
	cur := m.LoadSettings(ctx)
	s := cur
	if in.Measured != nil {
		s.Measured = *in.Measured
	}
	if in.Budget != nil {
		s.Budget = *in.Budget
	}
	if in.Quiet != nil {
		s.Quiet = *in.Quiet
	}
	// erst alles pruefen, damit nichts halb gespeichert wird
	fe := checkSettings(s)
	if hasProf {
		for k, v := range prof.validate() {
			fe[k] = v
		}
	}
	if len(fe) > 0 {
		m.fieldErrs(w, r, fe)
		return
	}
	// Profil zuerst: der Knoten laeuft noch (neue Einstellungen starten ihn neu)
	if hasProf {
		if _, err := m.SaveProfile(ctx, prof); err != nil {
			code := http.StatusBadGateway
			if errors.Is(err, ErrNotReady) || errors.Is(err, ErrNotJoined) {
				code = http.StatusConflict
			}
			apiJSON(w, code, map[string]string{"error": m.errText(r, err)})
			return
		}
	}
	if in.Participate != nil && !*in.Participate && cur.Participate { // ausschalten vor dem Speichern (kein Neustart)
		if err := m.SetParticipate(ctx, false); err != nil {
			m.fail(w, err)
			return
		}
	}
	if s != cur {
		if _, err := m.SaveSettings(ctx, s); err != nil {
			var fe FieldErrors
			if errors.As(err, &fe) {
				m.fieldErrs(w, r, fe)
				return
			}
			m.fail(w, err)
			return
		}
	}
	if in.Participate != nil && *in.Participate && !cur.Participate {
		if err := m.SetParticipate(ctx, true); err != nil {
			code := http.StatusBadGateway
			if errors.Is(err, ErrNoKey) {
				code = http.StatusConflict
			}
			apiJSON(w, code, map[string]string{"error": m.errText(r, err)})
			return
		}
	}
	m.g.Audit(r, "sonar64.settings", Name, "api")
	apiJSON(w, http.StatusOK, m.settingsView(r))
}

func (m *Module) fieldErrs(w http.ResponseWriter, r *http.Request, fe FieldErrors) {
	fields := map[string]string{}
	for k, v := range fe {
		fields[k] = m.g.T(r, v, "port", strconv.Itoa(sonar.Port))
	}
	apiJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "invalid settings", "fields": fields})
}

func apiJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, status int, msg string) {
	apiJSON(w, status, map[string]string{"error": msg})
}

func (m *Module) fail(w http.ResponseWriter, err error) {
	m.log.Error("api", "err", err)
	apiErr(w, http.StatusInternalServerError, "internal error")
}
