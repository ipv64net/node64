package cdn64

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/hpbridge"
)

// Seite (Karte auf dem Reiter Zugriffslisten) und API: PROXY64 und Honeypot64.

type honeypotView struct {
	Settings HoneypotSettings `json:"settings"`
	Decoy    bool             `json:"decoy_available"`  // Honeypot64 bietet gerade einen Web-Koeder an
	Access   bool             `json:"access_available"` // Honeypot64 wertet gerade Zugriffe aus
	Blocks   []HoneypotBlock  `json:"blocks"`
	Rejected int64            `json:"rejected"` // abgewiesen seit dem Start
	Decoyed  int64            `json:"decoyed"`  // an den Koeder gegeben seit dem Start
	Reported int64            `json:"reported"` // an den Log-Sensor gegeben seit dem Start
}

func (m *Module) hpView() honeypotView {
	return honeypotView{Settings: m.hpSettings(), Decoy: hpbridge.Decoy() != nil, Access: hpbridge.AccessActive(), Blocks: m.hpList(),
		Rejected: m.hp.rejected.Load(), Decoyed: m.hp.decoyed.Load(), Reported: m.hp.reported.Load()}
}

func hpAudit(s HoneypotSettings) string {
	return fmt.Sprintf("decoy=%v access=%v block=%v hours=%d", s.Decoy, s.Access, s.Block, s.BlockHours)
}

func (m *Module) pageHoneypotSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	hours, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue("hp_block_hours")))
	s := HoneypotSettings{Decoy: r.PostFormValue("hp_decoy") == "on", Access: r.PostFormValue("hp_access") == "on",
		Block: r.PostFormValue("hp_block") == "on", BlockHours: hours}
	if err := m.hpSave(r.Context(), s); err != nil {
		m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.hp.err_hours"))
	} else {
		m.g.Audit(r, "cdn64.honeypot", hpAudit(m.hpSettings()), "")
		m.g.Flash(w, r, "success", m.g.T(r, "cdn64.hp.saved"))
	}
	http.Redirect(w, r, "/cdn64/access#honeypot", http.StatusSeeOther)
}

func (m *Module) pageHoneypotUnblock(w http.ResponseWriter, r *http.Request) {
	ip := r.PostFormValue("ip")
	if m.hpUnblock(ip) {
		m.g.Audit(r, "cdn64.honeypot.unblock", ip, "")
		m.g.Flash(w, r, "success", m.g.T(r, "cdn64.hp.unblocked", "ip", ip))
	}
	http.Redirect(w, r, "/cdn64/access#honeypot", http.StatusSeeOther)
}

func (m *Module) apiHoneypotGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.hpView())
}

// apiHoneypotPut: fehlende Felder bleiben, wie sie sind.
func (m *Module) apiHoneypotPut(w http.ResponseWriter, r *http.Request) {
	s := m.hpSettings()
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
