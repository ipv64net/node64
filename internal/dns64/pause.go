package dns64

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Blockieren voruebergehend aus (wie bei Pi-hole): der DNS-Dienst laeuft weiter, nur Blocklisten und
// CNAME-Pruefung greifen nicht. Eigene Eintraege, lokale Namen und Freigaben bleiben. Der Stand wird gespeichert,
// eine befristete Pause endet von selbst.

const setPause = "dns64.pause_until" // "" = aktiv, "forever" = bis zum Wiedereinschalten, sonst RFC3339

const pauseForever = int64(-1)

// pauseView ist der Stand fuer die Seiten.
type pauseView struct {
	Active  bool
	Forever bool
	Until   time.Time
}

// loadPause liest den gespeicherten Stand (beim Start und nach Aenderungen).
func (m *Module) loadPause(ctx context.Context) {
	v := m.core.SettingOr(ctx, setPause, "")
	switch {
	case v == "forever":
		m.pauseUntil.Store(pauseForever)
	case v != "":
		if t, err := time.Parse(time.RFC3339, v); err == nil && t.After(time.Now()) {
			m.pauseUntil.Store(t.UnixNano())
			return
		}
		m.pauseUntil.Store(0)
	default:
		m.pauseUntil.Store(0)
	}
}

// paused: Blockieren ist gerade aus (fuer jede Anfrage, daher ohne Datenbank).
func (m *Module) paused() bool {
	u := m.pauseUntil.Load()
	return u == pauseForever || (u > 0 && time.Now().UnixNano() < u)
}

func (m *Module) pauseState() pauseView {
	u := m.pauseUntil.Load()
	switch {
	case u == pauseForever:
		return pauseView{Active: true, Forever: true}
	case u > 0 && time.Now().UnixNano() < u:
		return pauseView{Active: true, Until: time.Unix(0, u)}
	}
	return pauseView{}
}

// setPaused pausiert (minutes > 0: so lange, 0: bis zum Wiedereinschalten) bzw. schaltet wieder ein (minutes < 0).
func (m *Module) setPaused(ctx context.Context, minutes int, by string) error {
	v := ""
	switch {
	case minutes == 0:
		v = "forever"
	case minutes > 0:
		v = time.Now().Add(time.Duration(minutes) * time.Minute).UTC().Format(time.RFC3339)
	}
	if err := m.core.SetSetting(ctx, setPause, v); err != nil {
		return err
	}
	m.loadPause(ctx)
	m.log.Info("blocking", "paused", v != "", "until", v, "by", by)
	return nil
}

// backTo leitet auf die DNS64-Seite zurueck, von der die Anfrage kam.
func backTo(r *http.Request) string {
	if u, err := url.Parse(r.Referer()); err == nil && strings.HasPrefix(u.Path, "/dns64") && u.Host == r.Host {
		return u.Path
	}
	return "/dns64"
}

func (m *Module) pagePause(w http.ResponseWriter, r *http.Request) {
	minutes, err := strconv.Atoi(r.PostFormValue("minutes"))
	if err != nil || minutes < 0 || minutes > 24*60 {
		minutes = 10
	}
	if err := m.setPaused(r.Context(), minutes, m.g.Actor(r)); err != nil {
		m.g.Flash(w, r, "danger", err.Error())
	}
	http.Redirect(w, r, backTo(r), http.StatusSeeOther)
}

func (m *Module) pageResume(w http.ResponseWriter, r *http.Request) {
	if err := m.setPaused(r.Context(), -1, m.g.Actor(r)); err != nil {
		m.g.Flash(w, r, "danger", err.Error())
	}
	http.Redirect(w, r, backTo(r), http.StatusSeeOther)
}

// API: POST /api/dns64/pause {"minutes": 10} (0 = bis zum Wiedereinschalten), POST /api/dns64/resume.
func (m *Module) apiPause(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Minutes *int `json:"minutes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&in); err != nil || in.Minutes == nil || *in.Minutes < 0 || *in.Minutes > 24*60 {
		writeErr(w, http.StatusBadRequest, "minutes: 0 (until resumed) to 1440")
		return
	}
	if err := m.setPaused(r.Context(), *in.Minutes, m.g.Actor(r)); err != nil {
		m.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, m.pauseJSON())
}

func (m *Module) apiResume(w http.ResponseWriter, r *http.Request) {
	if err := m.setPaused(r.Context(), -1, m.g.Actor(r)); err != nil {
		m.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, m.pauseJSON())
}

func (m *Module) pauseJSON() map[string]any {
	p := m.pauseState()
	out := map[string]any{"paused": p.Active, "until_resumed": p.Forever}
	if !p.Until.IsZero() {
		out["paused_until"] = p.Until.UTC()
	}
	return out
}
