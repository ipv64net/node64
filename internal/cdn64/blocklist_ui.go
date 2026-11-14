package cdn64

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"

	"github.com/ipv64net/node64/internal/geoip"
)

// Seite (Karte auf dem Reiter Sicherheit) und API der ipv64-Blocklisten; Freigabe- und Sperrliste auf dem Reiter Zugriffslisten.

func (m *Module) pageBlocklistsSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	tok := strings.TrimSpace(r.PostFormValue("token")) // leer = Listen-Token unveraendert
	allow := r.PostFormValue("allow")
	if _, ok := r.PostForm["allow"]; !ok { // die Ausnahmen stehen als Freigabeliste auf dem Reiter Zugriffslisten
		allow = m.core.SettingOr(r.Context(), setBlockAllow, "")
	}
	if !blTokenValid(tok) {
		m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.bl.err_token"))
	} else if err := m.blSave(r.Context(), r.PostForm["list"], allow); err != nil {
		m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.bl.err_allow"))
	} else {
		m.g.Audit(r, "cdn64.blocklists", strings.Join(r.PostForm["list"], ","), "allow="+strings.Join(strings.Fields(allow), ","))
		if tok != "" {
			if err := m.blSetToken(r.Context(), tok); err != nil {
				m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.bl.err_token"))
				http.Redirect(w, r, "/cdn64/security#blocklists", http.StatusSeeOther)
				return
			}
			m.g.Audit(r, "cdn64.blocklists.token", "set", "") // das Token selbst nie
		}
		m.g.Flash(w, r, "success", m.g.T(r, "cdn64.bl.saved"))
	}
	http.Redirect(w, r, "/cdn64/security#blocklists", http.StatusSeeOther)
}

// pageBlocklistsTokenDelete loescht das Listen-Token (v64-Listen wieder im Tagesstand).
func (m *Module) pageBlocklistsTokenDelete(w http.ResponseWriter, r *http.Request) {
	if err := m.blSetToken(r.Context(), ""); err != nil {
		m.g.Flash(w, r, "danger", err.Error())
	} else {
		m.g.Audit(r, "cdn64.blocklists.token", "deleted", "")
		m.g.Flash(w, r, "success", m.g.T(r, "cdn64.bl.token_deleted"))
	}
	http.Redirect(w, r, "/cdn64/security#blocklists", http.StatusSeeOther)
}

func (m *Module) pageBlocklistsRefresh(w http.ResponseWriter, r *http.Request) {
	m.blKick(r.Context())
	m.g.Audit(r, "cdn64.blocklists.refresh", "", "")
	m.g.Flash(w, r, "success", m.g.T(r, "cdn64.bl.refreshing"))
	http.Redirect(w, r, "/cdn64/security#blocklists", http.StatusSeeOther)
}

type blocklistsView struct {
	Lists   []BlocklistState `json:"lists"`
	Allow   []string         `json:"allow"`   // Freigabeliste
	Deny    []string         `json:"deny"`    // eigene Sperrliste
	Denied  int64            `json:"denied"`  // von der eigenen Sperrliste abgewiesen seit dem Start
	Blocked int64            `json:"blocked"` // abgewiesen seit dem Start
	Active  bool             `json:"active"`  // mindestens eine Liste geladen und eingeschaltet

	Countries  []GeoState `json:"countries"`   // Laenderlisten der Laendersperre (Hosts mit Laendersperre; Rueckfall ohne Standort)
	GeoBlocked int64      `json:"geo_blocked"` // von der Laendersperre abgewiesen seit dem Start
	// GeoData: Standortdaten (DB-IP ueber ipv64.net), nach denen die Laendersperre entscheidet (#139)
	GeoData geoip.Status `json:"geo_data"`

	TokenSet  bool `json:"token_set"`  // Listen-Token von Hand hinterlegt (das Token wird nie ausgegeben)
	TokenAuto bool `json:"token_auto"` // Listen-Token automatisch ueber den zentralen API-Key geholt

	AIBots AIBotsState `json:"ai_bots"` // User-Agent-Liste der KI-Bots (Hosts mit KI-Sperre)
}

func (m *Module) blView(r *http.Request) blocklistsView {
	v := blocklistsView{Lists: m.blStates(r.Context()), Allow: strings.Fields(m.core.SettingOr(r.Context(), setBlockAllow, "")),
		Deny: strings.Fields(m.core.SettingOr(r.Context(), setBlockDeny, "")), Denied: m.bl.denied.Load(), Blocked: m.bl.blocked.Load(),
		Active: m.bl.set.Load() != nil, Countries: m.geoStates(), GeoBlocked: m.bl.geo.blocked.Load(), GeoData: geoip.Current(), AIBots: m.aiState()}
	v.TokenSet = m.blTokenOf(r.Context(), setBlockToken) != ""
	v.TokenAuto = !v.TokenSet && m.blTokenOf(r.Context(), setBlockTokenAuto) != ""
	if v.Allow == nil {
		v.Allow = []string{}
	}
	if v.Deny == nil {
		v.Deny = []string{}
	}
	return v
}

// apiGeoLookup: welches Land die Laendersperre fuer eine Adresse sieht und woher (#139, #54).
func (m *Module) apiGeoLookup(w http.ResponseWriter, r *http.Request) {
	ip, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(r.URL.Query().Get("ip")), "[]"))
	if err != nil || ip.Zone() != "" {
		writeErr(w, http.StatusBadRequest, "ip missing or invalid")
		return
	}
	ip = ip.Unmap()
	cc, src := m.geoSource(ip)
	out := map[string]any{"ip": ip.String(), "country": cc, "source": src, "location_data": geoip.Current().Loaded}
	if cc != "" {
		out["name"] = geoip.Name(cc, r.URL.Query().Get("lang"))
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) apiBlocklistsGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.blView(r))
}

func (m *Module) apiBlocklistsPut(w http.ResponseWriter, r *http.Request) {
	in := struct {
		Enabled []string `json:"enabled"` // fehlt = unveraendert, [] = alle aus
		Allow   []string `json:"allow"`   // Freigabeliste: fehlt = unveraendert
		Deny    []string `json:"deny"`    // eigene Sperrliste: fehlt = unveraendert

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
	if in.Enabled != nil { // Listen schalten (Freigabeliste fehlt = unveraendert)
		allow := m.core.SettingOr(r.Context(), setBlockAllow, "")
		if in.Allow != nil {
			allow = strings.Join(in.Allow, "\n")
		}
		if err := m.blSave(r.Context(), in.Enabled, allow); err != nil {
			m.apiFail(w, err)
			return
		}
		m.g.Audit(r, "cdn64.blocklists", strings.Join(in.Enabled, ","), "allow="+strings.Join(strings.Fields(allow), ","))
	}
	var allow, deny *string // Freigabe-/Sperrliste allein: die eingeschalteten Listen bleiben
	if in.Allow != nil && in.Enabled == nil {
		s := strings.Join(in.Allow, "\n")
		allow = &s
	}
	if in.Deny != nil {
		s := strings.Join(in.Deny, "\n")
		deny = &s
	}
	if allow != nil || deny != nil {
		if err := m.blListsSave(r.Context(), allow, deny); err != nil {
			m.apiFail(w, err)
			return
		}
		if allow != nil {
			m.g.Audit(r, "cdn64.allowlist", strings.Join(in.Allow, ","), "")
		}
		if deny != nil {
			m.g.Audit(r, "cdn64.denylist", strings.Join(in.Deny, ","), "")
		}
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
