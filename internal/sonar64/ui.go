package sonar64

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/sonar"
)

//go:embed templates
var templateFS embed.FS

//go:embed static/sonar64.js
var liveJS []byte

// Templates liefert die Seiten des Moduls (module.Templater).
func (m *Module) Templates() fs.FS {
	sub, _ := fs.Sub(templateFS, "templates")
	return sub
}

func (m *Module) uiRoutes(mux *http.ServeMux, g module.Guards) {
	page := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /sonar64", page(m.pageOverview))
	mux.Handle("POST /sonar64/participate", page(m.pageParticipate))
	mux.Handle("POST /sonar64/rejoin", page(m.pageRejoin))
	mux.Handle("POST /sonar64/settings", page(m.pageSettings))
	mux.Handle("POST /sonar64/profile", page(m.pageProfile))
	mux.Handle("GET /sonar64/sonar64.js", page(m.serveJS)) // CSP: Skripte nur von der eigenen Adresse
}

// resultView ist eine Zeile „Pings von mir“ (ohne Ziel-Adresse).
type resultView struct {
	At     time.Time `json:"at"`
	Target string    `json:"target"`
	Method string    `json:"method"`
	Family int       `json:"fam"`
	Sent   int       `json:"sent"`
	Recv   int       `json:"recv"`
	MinMs  float64   `json:"min"`
	AvgMs  float64   `json:"avg"`
	MaxMs  float64   `json:"max"`
	Loss   float64   `json:"loss"` // Prozent
	Error  string    `json:"err,omitempty"`
}

// inboundView ist eine live auf UDP 6464 beantwortete Probe (Name, wenn aus den Ergebnissen bei ipv64 bekannt).
type inboundView struct {
	From   string    `json:"from"`
	Name   string    `json:"name,omitempty"`
	Family int       `json:"fam"`
	Count  int       `json:"count"`
	At     time.Time `json:"at"`
}

// shortID ist die Kurzform einer Node-ID in UDP-Proben (erste 4 Byte von SHA-256, hex klein; Vertrag Abschnitt 8).
func shortID(nodeID string) string {
	h := sha256.Sum256([]byte(nodeID))
	return hex.EncodeToString(h[:4])
}

func resultViews(list []sonar.Result) []resultView {
	out := make([]resultView, 0, len(list))
	for _, r := range list {
		v := resultView{At: r.At, Target: r.Target, Method: r.Method, Family: r.Family, Sent: r.Sent, Recv: r.Recv,
			MinMs: r.MinMs, AvgMs: r.AvgMs, MaxMs: r.MaxMs, Error: r.Error}
		if r.Sent > 0 && r.Recv <= r.Sent {
			v.Loss = float64(r.Sent-r.Recv) * 100 / float64(r.Sent)
		}
		out = append(out, v)
	}
	return out
}

// inboundViews ordnet die Kurz-IDs der Proben den Namen aus den Ergebnissen bei ipv64 zu (soweit bekannt).
func inboundViews(list []sonar.Inbound, rows []sonar.InboundRow) []inboundView {
	names := map[string]string{}
	for _, r := range rows {
		names[shortID(r.From)] = r.Name
	}
	out := make([]inboundView, 0, len(list))
	for _, in := range list {
		out = append(out, inboundView{From: in.From, Name: names[in.From], Family: in.Family, Count: in.Count, At: in.At})
	}
	return out
}

type overviewData struct {
	Running     bool
	KeySet      bool
	Settings    Settings
	Status      sonar.Status
	HasRunner   bool
	Registered  bool
	Revoked     bool // von ipv64 abgemeldet (Status.Paused "revoked")
	RunErr      string
	PortErr     string
	Me          *sonar.Me
	MeErr       string
	Trust       trustView
	PublicURL   string
	Budgets     []string
	Accesses    []string
	Devices     []string
	Port        int
	Errors      map[string]string
	Form        map[string]string
	Recent      []resultView
	InboundLive []inboundView
}

func (m *Module) overview(r *http.Request) *overviewData {
	ctx := r.Context()
	s := m.LoadSettings(ctx)
	d := &overviewData{Running: m.running(), KeySet: m.apiKey(ctx) != "", Settings: s, Budgets: Budgets, Accesses: Accesses,
		Devices: Devices, Port: sonar.Port, Errors: map[string]string{}, Form: map[string]string{}, Recent: []resultView{}, InboundLive: []inboundView{}}
	m.mu.Lock()
	d.RunErr, d.PortErr, d.MeErr = m.runErr, m.portErr, m.meErr
	m.mu.Unlock()
	d.Me = m.cachedMe()
	if rn := m.runner(); rn != nil {
		d.HasRunner = true
		d.Status = rn.Status()
		d.Registered = d.Status.Registered
		d.Revoked = d.Status.Paused == "revoked"
		res, in := rn.Recent(50)
		d.Recent = resultViews(res)
		m.mu.Lock()
		rows := m.inRows
		m.mu.Unlock()
		d.InboundLive = inboundViews(in, rows)
	}
	d.Trust = trustOf(d.Me, s.Measured, time.Now())
	if d.Me != nil {
		d.PublicURL = publicURL(d.Me.Slug)
		d.Form["name"], d.Form["access"], d.Form["device"] = d.Me.Name, d.Me.Access, d.Me.Device
		if d.Me.Lat != nil && d.Me.Lon != nil {
			d.Form["lat"] = strconv.FormatFloat(*d.Me.Lat, 'f', -1, 64)
			d.Form["lon"] = strconv.FormatFloat(*d.Me.Lon, 'f', -1, 64)
		}
	}
	if d.Form["device"] == "" {
		d.Form["device"] = "node64"
	}
	d.Form["quiet"] = s.Quiet
	return d
}

func (m *Module) render(w http.ResponseWriter, r *http.Request, status int, d *overviewData) {
	m.g.Render(w, r, status, "sonar64/overview", "nav.sonar64", d)
}

func (m *Module) pageOverview(w http.ResponseWriter, r *http.Request) {
	m.render(w, r, http.StatusOK, m.overview(r))
}

// errText uebersetzt einen Fehler der Teilnahme bzw. des Profils.
func (m *Module) errText(r *http.Request, err error) string {
	switch {
	case errors.Is(err, ErrNoKey):
		return m.g.T(r, "sonar64.err.no_key")
	case errors.Is(err, ErrToken):
		return m.g.T(r, "sonar64.err.token", "error", err.Error())
	case errors.Is(err, ErrNotReady):
		return m.g.T(r, "sonar64.err.not_ready")
	case errors.Is(err, ErrNotJoined):
		return m.g.T(r, "sonar64.err.not_joined")
	case errors.Is(err, sonar.ErrRevoked):
		return m.g.T(r, "sonar64.err.revoked")
	}
	return m.g.T(r, "sonar64.err.api", "error", err.Error())
}

func (m *Module) pageParticipate(w http.ResponseWriter, r *http.Request) {
	on := r.PostFormValue("participate") == "1"
	err := m.SetParticipate(r.Context(), on)
	if errors.Is(err, ErrLeftLocally) { // ausgetreten, nur ipv64 nicht erreicht: Hinweis statt Fehler
		m.g.Audit(r, "sonar64.participate", Name, "off (local)")
		m.g.Flash(w, r, "warning", m.g.T(r, "sonar64.flash.left_local", "error", strings.TrimPrefix(err.Error(), ErrLeftLocally.Error()+": ")))
		http.Redirect(w, r, "/sonar64", http.StatusSeeOther)
		return
	}
	if err != nil {
		m.log.Warn("sonar64 participation not changed", "on", on, "err", err)
		m.g.Flash(w, r, "danger", m.errText(r, err))
		http.Redirect(w, r, "/sonar64", http.StatusSeeOther)
		return
	}
	state := "off"
	if on {
		state = "on"
	}
	m.g.Audit(r, "sonar64.participate", Name, state)
	m.g.Flash(w, r, "success", m.g.T(r, "sonar64.flash.participate_"+state))
	http.Redirect(w, r, "/sonar64", http.StatusSeeOther)
}

// pageRejoin: nach einer Abmeldung durch ipv64 mit neuem Token und neuem Knoten teilnehmen.
func (m *Module) pageRejoin(w http.ResponseWriter, r *http.Request) {
	if err := m.Rejoin(r.Context()); err != nil {
		m.log.Warn("sonar64 rejoin failed", "err", err)
		m.g.Flash(w, r, "danger", m.errText(r, err))
		http.Redirect(w, r, "/sonar64", http.StatusSeeOther)
		return
	}
	m.g.Audit(r, "sonar64.rejoin", Name, "")
	m.g.Flash(w, r, "success", m.g.T(r, "sonar64.flash.rejoined"))
	http.Redirect(w, r, "/sonar64", http.StatusSeeOther)
}

func (m *Module) pageSettings(w http.ResponseWriter, r *http.Request) {
	in := Settings{Measured: r.PostFormValue("measured") == "1", Budget: r.PostFormValue("budget"), Quiet: r.PostFormValue("quiet")}
	if _, err := m.SaveSettings(r.Context(), in); err != nil {
		var fe FieldErrors
		if !errors.As(err, &fe) {
			m.log.Error("sonar64 settings not saved", "err", err)
			m.g.Flash(w, r, "danger", m.errText(r, err))
			http.Redirect(w, r, "/sonar64", http.StatusSeeOther)
			return
		}
		d := m.overview(r)
		d.Settings.Measured, d.Settings.Budget = in.Measured, in.Budget
		d.Form["quiet"] = in.Quiet
		for k, v := range fe {
			d.Errors[k] = m.g.T(r, v, "port", strconv.Itoa(sonar.Port))
		}
		m.render(w, r, http.StatusUnprocessableEntity, d)
		return
	}
	m.g.Audit(r, "sonar64.settings", Name, "measured="+strconv.FormatBool(in.Measured)+" budget="+in.Budget)
	m.g.Flash(w, r, "success", m.g.T(r, "sonar64.flash.saved"))
	http.Redirect(w, r, "/sonar64", http.StatusSeeOther)
}

// parseCoord liest eine Koordinate aus dem Formular (Komma oder Punkt); leer = nil.
func parseCoord(s string) (*float64, bool) {
	s = strings.TrimSpace(strings.ReplaceAll(s, ",", "."))
	if s == "" {
		return nil, true
	}
	if len(s) > 24 {
		return nil, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil, false
	}
	return &f, true
}

func (m *Module) pageProfile(w http.ResponseWriter, r *http.Request) {
	form := map[string]string{}
	for _, k := range []string{"name", "lat", "lon", "access", "device"} {
		v := r.PostFormValue(k)
		if len(v) > 64 {
			v = v[:64]
		}
		form[k] = v
	}
	p := Profile{Name: form["name"], Access: form["access"], Device: form["device"]}
	fe := FieldErrors{}
	var ok1, ok2 bool
	p.Lat, ok1 = parseCoord(form["lat"])
	p.Lon, ok2 = parseCoord(form["lon"])
	if !ok1 {
		fe["lat"] = "sonar64.err.lat"
	}
	if !ok2 {
		fe["lon"] = "sonar64.err.lon"
	}
	// Standort nur loeschen, wenn das Formular einen gezeigt hat (sonst war er nur noch nicht geladen)
	p.ClearLoc = ok1 && ok2 && p.Lat == nil && p.Lon == nil && r.PostFormValue("had_loc") == "1"
	var err error
	if len(fe) == 0 {
		_, err = m.SaveProfile(r.Context(), p)
		if e, isFE := err.(FieldErrors); isFE {
			fe = e
		}
	}
	if len(fe) > 0 {
		d := m.overview(r)
		for k, v := range form {
			d.Form[k] = v
		}
		for k, v := range fe {
			d.Errors[k] = m.g.T(r, v)
		}
		m.render(w, r, http.StatusUnprocessableEntity, d)
		return
	}
	if err != nil {
		m.log.Warn("sonar64 profile not saved", "err", err)
		m.g.Flash(w, r, "danger", m.errText(r, err))
		http.Redirect(w, r, "/sonar64", http.StatusSeeOther)
		return
	}
	m.g.Audit(r, "sonar64.profile", Name, "")
	m.g.Flash(w, r, "success", m.g.T(r, "sonar64.flash.saved"))
	http.Redirect(w, r, "/sonar64", http.StatusSeeOther)
}

func (m *Module) serveJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(liveJS)
}
