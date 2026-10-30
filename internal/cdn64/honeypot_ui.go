package cdn64

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/hpbridge"
)

// Seite (Karte auf dem Reiter Sicherheit, Sperren in der Sperrliste) und API: PROXY64 und Honeypot64.

type honeypotView struct {
	Settings HoneypotSettings `json:"settings"`
	Decoy    bool             `json:"decoy_available"`  // Honeypot64 bietet gerade einen Web-Koeder an
	Access   bool             `json:"access_available"` // Honeypot64 wertet gerade Zugriffe aus
	Blocks   []HoneypotBlock  `json:"blocks"`
	Rejected int64            `json:"rejected"` // abgewiesen seit dem Start
	Decoyed  int64            `json:"decoyed"`  // an den Koeder gegeben seit dem Start
	Reported int64            `json:"reported"` // an den Log-Sensor gegeben seit dem Start
	// DefaultClose: Standardseite fuer unbekannte Namen steht auf "Verbindung schliessen" (der Koeder antwortet trotzdem)
	DefaultClose bool `json:"default_close"`
	// Wanted: Honeypot64 laeuft mit der Vorlage "Nur ueber PROXY64" - der Koeder gilt dann als eingeschaltet
	Wanted bool `json:"proxy_only"`
	// BlockWanted: Honeypot64 schaltet die Sofort-Sperre ein (Schalter im Honeypot, dort Standard an)
	BlockWanted bool `json:"block_by_honeypot"`
}

func (m *Module) hpView() honeypotView {
	return honeypotView{Settings: m.hpSettings(), Decoy: hpbridge.Decoy() != nil, Access: hpbridge.AccessActive(), Blocks: m.hpList(),
		Rejected: m.hp.rejected.Load(), Decoyed: m.hp.decoyed.Load(), Reported: m.hp.reported.Load(),
		DefaultClose: m.edge != nil && m.edge.Config().Default == edge.DefaultClose, Wanted: hpbridge.Wanted(), BlockWanted: hpbridge.BlockWanted()}
}

func hpAudit(s HoneypotSettings) string {
	out := fmt.Sprintf("decoy=%v access=%v block=%v hours=%d", s.Decoy, s.Access, s.Block, s.BlockHours)
	if r := s.Route; r != nil {
		out += fmt.Sprintf(" route=blocklist:%v,honeypot:%v,exploit:%v,ai_bot:%v,geo:%v", r.Blocklist, r.Honeypot, r.Exploit, r.AIBot, r.Geo)
	}
	return out
}

func (m *Module) pageHoneypotSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	hours, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue("hp_block_hours")))
	s := HoneypotSettings{Decoy: r.PostFormValue("hp_decoy") == "on", Access: r.PostFormValue("hp_access") == "on",
		Block: r.PostFormValue("hp_block") == "on", BlockHours: hours, Route: m.hpSettings().Route}
	if r.PostFormValue("hp_route_form") != "" { // Formular mit den Wegen (sonst bleiben sie)
		on := func(k string) bool { return r.PostFormValue("hp_route_"+k) == "on" }
		s.Route = &HoneypotRoute{Blocklist: on("blocklist"), Honeypot: on("honeypot"), Exploit: on("exploit"), AIBot: on("ai_bot"), Geo: on("geo")}
	}
	if err := m.hpSave(r.Context(), s); err != nil {
		m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.hp.err_hours"))
	} else {
		m.g.Audit(r, "cdn64.honeypot", hpAudit(m.hpSettings()), "")
		m.g.Flash(w, r, "success", m.g.T(r, "cdn64.hp.saved"))
	}
	http.Redirect(w, r, "/cdn64/security#honeypot", http.StatusSeeOther)
}

func (m *Module) pageHoneypotUnblock(w http.ResponseWriter, r *http.Request) {
	ip := r.PostFormValue("ip")
	if m.hpUnblock(ip) {
		m.g.Audit(r, "cdn64.honeypot.unblock", ip, "")
		m.g.Flash(w, r, "success", m.g.T(r, "cdn64.hp.unblocked", "ip", ip))
	}
	http.Redirect(w, r, "/cdn64/access#sperrliste", http.StatusSeeOther)
}

func (m *Module) apiHoneypotGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.hpView())
}

// apiHoneypotPut: fehlende Felder bleiben, wie sie sind.
func (m *Module) apiHoneypotPut(w http.ResponseWriter, r *http.Request) {
	s := m.hpSettings()
	if s.Route != nil { // eigene Kopie: die geltende Einstellung aendert erst hpSave (nach der Pruefung)
		rt := *s.Route
		s.Route = &rt
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&s); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := m.hpSave(r.Context(), s); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	m.g.Audit(r, "cdn64.honeypot", hpAudit(m.hpSettings()), "")
	writeJSON(w, http.StatusOK, m.hpView())
}

func (m *Module) apiHoneypotUnblock(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if !m.hpUnblock(ip) {
		writeErr(w, http.StatusNotFound, "not blocked")
		return
	}
	m.g.Audit(r, "cdn64.honeypot.unblock", ip, "")
	w.WriteHeader(http.StatusNoContent)
}
