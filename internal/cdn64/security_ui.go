package cdn64

import (
	"net/http"
	"sort"
	"strings"
	"time"
)

// Reiter Sicherheit (ipv64-Blocklisten, DoS-Schutz, Honeypot64) sowie Freigabe- und Sperrliste auf dem Reiter
// Zugriffslisten: die Sperrliste zeigt neben den eigenen Eintraegen die automatischen Sperren; "Freigeben" hebt eine
// solche Sperre auf und traegt die Adresse in die Freigabeliste ein.

type securityData struct {
	Tabs []tab
	BL   blocklistsView
	Lim  limitsView
	HP   honeypotView
}

func (m *Module) pageSecurity(w http.ResponseWriter, r *http.Request) {
	d := securityData{Tabs: m.tabs("/cdn64/security"), BL: m.blView(r), Lim: m.limView(r.Context()), HP: m.hpView()}
	m.g.Render(w, r, http.StatusOK, Name+"/security", "cdn64.title", d)
}

// autoBlock ist eine automatische Sperre (Honeypot oder DoS-Schutz).
type autoBlock struct {
	IP     string
	From   string // honeypot | ban
	Reason string // vom Honeypot gemeldeter Grund
	Until  time.Time
}

func (m *Module) autoBlocks() []autoBlock {
	var out []autoBlock
	for _, b := range m.hpList() {
		out = append(out, autoBlock{IP: b.IP, From: "honeypot", Reason: b.Reason, Until: b.Until})
	}
	for _, b := range m.lim.banList() {
		out = append(out, autoBlock{IP: b.IP, From: "ban", Until: b.Until})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Until.After(out[j].Until) })
	return out
}

// pageNetListsSave speichert Freigabe- und/oder Sperrliste (je nach Formular).
func (m *Module) pageNetListsSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	var allow, deny *string
	if v, ok := r.PostForm["allow"]; ok {
		allow = &v[0]
	}
	if v, ok := r.PostForm["deny"]; ok {
		deny = &v[0]
	}
	anchor := "#freigabeliste"
	if deny != nil {
		anchor = "#sperrliste"
	}
	if err := m.blListsSave(r.Context(), allow, deny); err != nil {
		m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.sec.err_nets"))
	} else {
		if allow != nil {
			m.g.Audit(r, "cdn64.allowlist", strings.Join(strings.Fields(*allow), ","), "")
		}
		if deny != nil {
			m.g.Audit(r, "cdn64.denylist", strings.Join(strings.Fields(*deny), ","), "")
		}
		m.g.Flash(w, r, "success", m.g.T(r, "cdn64.sec.saved"))
	}
	http.Redirect(w, r, "/cdn64/access"+anchor, http.StatusSeeOther)
}

// pageRelease hebt eine automatische Sperre auf und traegt die Adresse in die Freigabeliste ein.
func (m *Module) pageRelease(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.PostFormValue("ip"))
	ok := false
	switch r.FormValue("from") {
	case "honeypot":
		ok = m.hpUnblock(ip)
	case "ban":
		ok = m.lim.unban(ip)
	}
	if ok {
		if err := m.blAllowAdd(r.Context(), ip); err != nil {
			m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.sec.err_nets"))
		} else {
			m.g.Audit(r, "cdn64.release", ip, r.FormValue("from"))
			m.g.Flash(w, r, "success", m.g.T(r, "cdn64.sec.released", "ip", ip))
		}
	}
	http.Redirect(w, r, "/cdn64/access#sperrliste", http.StatusSeeOther)
}
