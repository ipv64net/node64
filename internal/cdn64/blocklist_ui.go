package cdn64

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Seite (Karte auf dem Reiter Zugriffslisten) und API der ipv64-Blocklisten.

func (m *Module) pageBlocklistsSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	tok := strings.TrimSpace(r.PostFormValue("token")) // leer = Listen-Token unveraendert
	if !blTokenValid(tok) {
		m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.bl.err_token"))
	} else if err := m.blSave(r.Context(), r.PostForm["list"], r.PostFormValue("allow")); err != nil {
		m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.bl.err_allow"))
	} else {
		m.g.Audit(r, "cdn64.blocklists", strings.Join(r.PostForm["list"], ","), "allow="+strings.Join(strings.Fields(r.PostFormValue("allow")), ","))
		if tok != "" {
			if err := m.blSetToken(r.Context(), tok); err != nil {
				m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.bl.err_token"))
				http.Redirect(w, r, "/cdn64/access#blocklists", http.StatusSeeOther)
				return
			}
			m.g.Audit(r, "cdn64.blocklists.token", "set", "") // das Token selbst nie
		}
		m.g.Flash(w, r, "success", m.g.T(r, "cdn64.bl.saved"))
	}
	http.Redirect(w, r, "/cdn64/access#blocklists", http.StatusSeeOther)
}

// pageBlocklistsTokenDelete loescht das Listen-Token (v64-Listen wieder im Tagesstand).
func (m *Module) pageBlocklistsTokenDelete(w http.ResponseWriter, r *http.Request) {
	if err := m.blSetToken(r.Context(), ""); err != nil {
		m.g.Flash(w, r, "danger", err.Error())
	} else {
		m.g.Audit(r, "cdn64.blocklists.token", "deleted", "")
		m.g.Flash(w, r, "success", m.g.T(r, "cdn64.bl.token_deleted"))
	}
	http.Redirect(w, r, "/cdn64/access#blocklists", http.StatusSeeOther)
}

func (m *Module) pageBlocklistsRefresh(w http.ResponseWriter, r *http.Request) {
	m.blKick(r.Context())
	m.g.Audit(r, "cdn64.blocklists.refresh", "", "")
	m.g.Flash(w, r, "success", m.g.T(r, "cdn64.bl.refreshing"))
	http.Redirect(w, r, "/cdn64/access#blocklists", http.StatusSeeOther)
}

type blocklistsView struct {
	Lists   []BlocklistState `json:"lists"`
	Allow   []string         `json:"allow"`
	Blocked int64            `json:"blocked"` // abgewiesen seit dem Start
	Active  bool             `json:"active"`  // mindestens eine Liste geladen und eingeschaltet

	Countries  []GeoState `json:"countries"`   // Laenderlisten der Laendersperre (Hosts mit Laendersperre)
	GeoBlocked int64      `json:"geo_blocked"` // von der Laendersperre abgewiesen seit dem Start

	TokenSet  bool `json:"token_set"`  // Listen-Token von Hand hinterlegt (das Token wird nie ausgegeben)
	TokenAuto bool `json:"token_auto"` // Listen-Token automatisch ueber den zentralen API-Key geholt

	AIBots AIBotsState `json:"ai_bots"` // User-Agent-Liste der KI-Bots (Hosts mit KI-Sperre)
}

func (m *Module) blView(r *http.Request) blocklistsView {
	v := blocklistsView{Lists: m.blStates(r.Context()), Allow: strings.Fields(m.core.SettingOr(r.Context(), setBlockAllow, "")), Blocked: m.bl.blocked.Load(),
		Active: m.bl.set.Load() != nil, Countries: m.geoStates(), GeoBlocked: m.bl.geo.blocked.Load(), AIBots: m.aiState()}
	v.TokenSet = m.blTokenOf(r.Context(), setBlockToken) != ""
	v.TokenAuto = !v.TokenSet && m.blTokenOf(r.Context(), setBlockTokenAuto) != ""
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

		Token *string `json:"token"` // Listen-Token: fehlt = unveraendert, "" = loeschen
	}{}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.Token != nil && !blTokenValid(*in.Token) {
		m.apiFail(w, ferr("token", "cdn64.bl.err_token"))
		return
	}
	if in.Token == nil || in.Enabled != nil || in.Allow != nil { // nur token: Listen bleiben
		if err := m.blSave(r.Context(), in.Enabled, strings.Join(in.Allow, "\n")); err != nil {
			m.apiFail(w, err)
			return
		}
		m.g.Audit(r, "cdn64.blocklists", strings.Join(in.Enabled, ","), "allow="+strings.Join(in.Allow, ","))
	}
	if in.Token != nil {
		if err := m.blSetToken(r.Context(), *in.Token); err != nil {
			m.apiFail(w, err)
			return
		}
		act := "set"
		if strings.TrimSpace(*in.Token) == "" {
			act = "deleted"
		}
		m.g.Audit(r, "cdn64.blocklists.token", act, "") // das Token selbst nie
	}
	writeJSON(w, http.StatusOK, m.blView(r))
}

func (m *Module) apiBlocklistsRefresh(w http.ResponseWriter, r *http.Request) {
	m.blKick(r.Context())
	m.g.Audit(r, "cdn64.blocklists.refresh", "", "")
	writeJSON(w, http.StatusAccepted, m.blView(r))
}
