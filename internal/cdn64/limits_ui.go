package cdn64

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Seite (Karte auf dem Reiter Sicherheit, Sperren in der Sperrliste) und API: Schutz vor Ueberlastung.

type limitsView struct {
	Limits   Limits `json:"limits"`
	Defaults Limits `json:"defaults"`
	Bans     []Ban  `json:"bans"`
	Rejected int64  `json:"rejected"` // abgewiesen seit dem Start
	Conns    int64  `json:"conns"`    // offene Verbindungen, die gezaehlt werden
}

func (m *Module) limView(ctx context.Context) limitsView {
	return limitsView{Limits: m.limLoad(ctx), Defaults: DefaultLimits(), Bans: m.lim.banList(), Rejected: m.lim.rejected.Load(), Conns: m.lim.conns.Load()}
}

func (m *Module) pageLimitsSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	c := DefaultLimits()
	if r.PostFormValue("reset") == "" {
		num := func(k string) int { n, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue(k))); return n }
		c = Limits{Enabled: r.PostFormValue("lim_enabled") == "on", ExemptLAN: r.PostFormValue("lim_exempt_lan") == "on",
			ConnsPerIP: num("lim_conns_per_ip"), ConnRate: num("lim_conn_rate"), ReqRate: num("lim_req_rate"), ReqBurst: num("lim_req_burst"),
			MaxConns: num("lim_max_conns"), TargetConns: num("lim_target_conns"), BanAfter: num("lim_ban_after"), BanMinutes: num("lim_ban_minutes")}
	}
	if err := m.limSave(r.Context(), c); err != nil {
		m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.lim.err_range"))
	} else {
		m.g.Audit(r, "cdn64.limits", limAudit(c), "")
		m.g.Flash(w, r, "success", m.g.T(r, "cdn64.lim.saved"))
	}
	http.Redirect(w, r, "/cdn64/security#limits", http.StatusSeeOther)
}

func (m *Module) pageLimitsUnban(w http.ResponseWriter, r *http.Request) {
	ip := r.PostFormValue("ip")
	if m.lim.unban(ip) {
		m.g.Audit(r, "cdn64.limits.unban", ip, "")
		m.g.Flash(w, r, "success", m.g.T(r, "cdn64.lim.unbanned", "ip", ip))
	}
	http.Redirect(w, r, "/cdn64/access#sperrliste", http.StatusSeeOther)
}

func limAudit(c Limits) string {
	if !c.Enabled {
		return "off"
	}
	return fmt.Sprintf("conns=%d conn_rate=%d req=%d/%d max=%d target=%d ban=%d/%dmin lan=%v", c.ConnsPerIP, c.ConnRate, c.ReqRate, c.ReqBurst,
		c.MaxConns, c.TargetConns, c.BanAfter, c.BanMinutes, c.ExemptLAN)
}

func (m *Module) apiLimitsGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.limView(r.Context()))
}

// apiLimitsPut: fehlende Felder bleiben, wie sie sind.
func (m *Module) apiLimitsPut(w http.ResponseWriter, r *http.Request) {
	c := m.limLoad(r.Context())
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&c); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := m.limSave(r.Context(), c); err != nil {
		m.apiFail(w, err)
		return
	}
	m.g.Audit(r, "cdn64.limits", limAudit(c), "")
	writeJSON(w, http.StatusOK, m.limView(r.Context()))
}

func (m *Module) apiLimitsUnban(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if !m.lim.unban(ip) {
		writeErr(w, http.StatusNotFound, "not banned")
		return
	}
	m.g.Audit(r, "cdn64.limits.unban", ip, "")
	w.WriteHeader(http.StatusNoContent)
}
