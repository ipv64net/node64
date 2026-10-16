package cdn64

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Seite (Karte auf dem Reiter Zugriffslisten) und API der ipv64-Blocklisten.

func (m *Module) pageBlocklistsSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if err := m.blSave(r.Context(), r.PostForm["list"], r.PostFormValue("allow")); err != nil {
		m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.bl.err_allow"))
	} else {
		m.g.Audit(r, "cdn64.blocklists", strings.Join(r.PostForm["list"], ","), "allow="+strings.Join(strings.Fields(r.PostFormValue("allow")), ","))
		m.g.Flash(w, r, "success", m.g.T(r, "cdn64.bl.saved"))
	}
	http.Redirect(w, r, "/cdn64/access#blocklists", http.StatusSeeOther)
}

func (m *Module) pageBlocklistsRefresh(w http.ResponseWriter, r *http.Request) {
	m.blKick(r.Context())
	m.g.Flash(w, r, "success", m.g.T(r, "cdn64.bl.refreshing"))
	http.Redirect(w, r, "/cdn64/access#blocklists", http.StatusSeeOther)
}

type blocklistsView struct {
	Lists   []BlocklistState `json:"lists"`
	Allow   []string         `json:"allow"`
	Blocked int64            `json:"blocked"` // abgewiesen seit dem Start
	Active  bool             `json:"active"`  // mindestens eine Liste geladen und eingeschaltet
}

func (m *Module) blView(r *http.Request) blocklistsView {
	v := blocklistsView{Lists: m.blStates(r.Context()), Allow: strings.Fields(m.core.SettingOr(r.Context(), setBlockAllow, "")), Blocked: m.bl.blocked.Load(),
		Active: m.bl.set.Load() != nil}
	if v.Allow == nil {
		v.Allow = []string{}
	}
	return v
}

func (m *Module) apiBlocklistsGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.blView(r))
}

func (m *Module) apiBlocklistsPut(w http.ResponseWriter, r *http.Request) {
	in := struct {
		Enabled []string `json:"enabled"`
		Allow   []string `json:"allow"`
	}{}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := m.blSave(r.Context(), in.Enabled, strings.Join(in.Allow, "\n")); err != nil {
		m.apiFail(w, err)
		return
	}
	m.g.Audit(r, "cdn64.blocklists", strings.Join(in.Enabled, ","), "allow="+strings.Join(in.Allow, ","))
	writeJSON(w, http.StatusOK, m.blView(r))
}

func (m *Module) apiBlocklistsRefresh(w http.ResponseWriter, r *http.Request) {
	m.blKick(r.Context())
	writeJSON(w, http.StatusAccepted, m.blView(r))
}
