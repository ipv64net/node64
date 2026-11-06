package cdn64

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/ipv64api"
)

// API fuer Aktionen, die sonst nur die Seiten kennen: Docker-Abgleich, Freigeben, lokales DNS, CDN64-Schutz und
// CDN64-Server. Die Logik teilen sich Seite und API (dockerSave, release, addLocal, onlineProtect, set*Servers).

// PUT /api/cdn64/docker {enabled, traefik, docker_host, certificate, accept_tos}: fehlende Felder bleiben.
func (m *Module) apiDockerPut(w http.ResponseWriter, r *http.Request) {
	in := struct {
		dockerSettings
		AcceptTOS bool `json:"accept_tos"`
	}{dockerSettings: m.dockerSettingsOf(r.Context())}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	in.Host = strings.TrimSpace(in.Host)
	if err := m.dockerSave(r, in.dockerSettings, in.AcceptTOS); err != nil {
		m.apiFail(w, err)
		return
	}
	m.apiDocker(w, r)
}

// POST /api/cdn64/release {ip, from}: automatische Sperre (from: honeypot, ban; leer = beide) aufheben und die Adresse
// in die Freigabeliste eintragen.
func (m *Module) apiRelease(w http.ResponseWriter, r *http.Request) {
	in := struct {
		IP   string `json:"ip"`
		From string `json:"from"`
	}{}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	in.IP = strings.TrimSpace(in.IP)
	if in.From != "" && in.From != "honeypot" && in.From != "ban" {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "from must be honeypot, ban or empty", "field": "from"})
		return
	}
	ok, err := m.release(r.Context(), in.IP, in.From)
	if err != nil {
		m.apiFail(w, err)
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "no automatic block for this address")
		return
	}
	m.g.Audit(r, "cdn64.release", in.IP, in.From)
	writeJSON(w, http.StatusOK, m.blView(r))
}

// POST /api/cdn64/hosts/{id}/localdns {ipv4, ipv6}: Namen des Hosts in DNS64 eintragen (beide leer = vorgeschlagene
// Adressen des Reverse-Proxys wie auf der Seite).
func (m *Module) apiHostLocalDNS(w http.ResponseWriter, r *http.Request) {
	h, err := m.host(r.Context(), pathID(r))
	if err != nil {
		m.apiFail(w, err)
		return
	}
	in := struct {
		IPv4 string `json:"ipv4"`
		IPv6 string `json:"ipv6"`
	}{}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(in.IPv4) == "" && strings.TrimSpace(in.IPv6) == "" {
		in.IPv4, in.IPv6 = m.localAddrs(r)
	}
	if m.ldns() == nil {
		writeErr(w, http.StatusConflict, "DNS64 is switched off")
		return
	}
	added, skipped, excluded, err := m.addLocal(r.Context(), h, in.IPv4, in.IPv6)
	if added > 0 {
		m.g.Audit(r, "cdn64.localdns", strings.Join(h.Names, ","), strings.TrimSpace(in.IPv4+" "+in.IPv6))
	}
	if err != nil {
		m.apiFail(w, err)
		return
	}
	if skipped == nil {
		skipped = []string{}
	}
	if excluded == nil {
		excluded = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"added": added, "skipped": skipped, "excluded": excluded, "ipv4": in.IPv4, "ipv6": in.IPv6})
}

// GET /api/cdn64/protection?days=1|7|30: CDN64 Statistik wie auf dem Reiter, je Name mit den Schaltern WAF und JA4.
func (m *Module) apiProtection(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if !slices.Contains(protectionDays, days) {
		days = 7
	}
	p, err := m.protection(r.Context(), days)
	if err != nil {
		m.onlineFail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		*ipv64api.CDN64Protection
		Hosts []protectionRow `json:"hosts"`
	}{p, m.protectionRows(r.Context(), p.Hosts)})
}

// protectionNames: Schalter WAF/JA4 der Namen bei ipv64 (letzter Abgleich).
type protectionName struct {
	ID   int64  `json:"id"`
	FQDN string `json:"fqdn"`
	WAF  bool   `json:"waf"`
	JA4  string `json:"ja4"`
}

func (m *Module) protectionNames(ids []int64) []protectionName {
	out := []protectionName{}
	if rm := m.online.remote.Load(); rm != nil && rm.Data != nil {
		for _, h := range rm.Data.Hosts {
			if slices.Contains(ids, h.ID) {
				out = append(out, protectionName{ID: h.ID, FQDN: h.FQDN, WAF: h.WAF, JA4: h.JA4})
			}
		}
	}
	return out
}

// PUT /api/cdn64/hosts/{id}/protection {waf, ja4}: Schutz der Server fuer alle Namen des Hosts (fehlt = wie bisher).
func (m *Module) apiProtectionSet(w http.ResponseWriter, r *http.Request) {
	h, err := m.host(r.Context(), pathID(r))
	if err != nil {
		m.onlineFail(w, r, err)
		return
	}
	in := struct {
		WAF *bool   `json:"waf"`
		JA4 *string `json:"ja4"`
	}{}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	ids, err := m.onlineHostIDs(r.Context(), h)
	if err != nil {
		m.onlineFail(w, r, err)
		return
	}
	waf, ja4 := false, "off"
	if cur := m.protectionNames(ids); len(cur) > 0 {
		waf, ja4 = cur[0].WAF, cur[0].JA4
	}
	if in.WAF != nil {
		waf = *in.WAF
	}
	if in.JA4 != nil {
		ja4 = *in.JA4
	}
	if !validJA4(ja4) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "ja4 must be off, count or block", "field": "ja4"})
		return
	}
	if err := m.onlineProtect(r.Context(), h, waf, ja4); err != nil {
		m.onlineFail(w, r, err)
		return
	}
	state := "waf=off"
	if waf {
		state = "waf=on"
	}
	m.g.Audit(r, "cdn64.online.protection", h.Names[0], state+" ja4="+ja4)
	writeJSON(w, http.StatusOK, map[string]any{"waf": waf, "ja4": ja4, "names": m.protectionNames(ids)})
}

// serversJSON: Auswahl der Server fuer die API (options: waehlbare Anzahlen, 0 = alle, auch kuenftige;
// session_options: waehlbare Verbindungen je Server, leer = fest).
type serversJSON struct {
	*ipv64api.CDN64Servers
	Options        []int `json:"options"`
	SessionOptions []int `json:"session_options"`
}

func toServersJSON(v *serversView) serversJSON {
	out := serversJSON{CDN64Servers: v.CDN64Servers, Options: v.Options, SessionOptions: v.SessionOptions}
	if out.Options == nil {
		out.Options = []int{}
	}
	if out.SessionOptions == nil {
		out.SessionOptions = []int{}
	}
	return out
}

// serversOf: Auswahl eines Proxy-Hosts (hid > 0, Server je Name) bzw. des eigenen Tunnels aus dem letzten Abgleich.
func (m *Module) serversOf(r *http.Request, hid int64) (*serversView, error) {
	ctx := r.Context()
	if a := m.online.api; a == nil || !a.Ready(ctx) {
		return nil, errOnline("no_api_key")
	}
	if hid == 0 {
		if v := m.onlineServers(ctx, m.remoteData()); v != nil {
			return v, nil
		}
		return nil, errOnline("not_configured")
	}
	h, err := m.host(ctx, hid)
	if err != nil {
		return nil, err
	}
	hl, err := m.hosts(ctx)
	if err != nil {
		return nil, err
	}
	if x := m.onlineIndex(ctx, hl)[h.ID]; x != nil && x.Servers != nil {
		return x.Servers, nil
	}
	return nil, errOnline("not_online")
}

func (m *Module) remoteData() *ipv64api.CDN64Overview {
	if rm := m.online.remote.Load(); rm != nil {
		return rm.Data
	}
	return nil
}

// GET /api/cdn64/hosts/{id}/servers bzw. /api/cdn64/online/servers (eigener Tunnel, Portal ohne Server je Name).
func (m *Module) apiServersGet(w http.ResponseWriter, r *http.Request) {
	v, err := m.serversOf(r, pathID(r))
	if err != nil {
		m.onlineFail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toServersJSON(v))
}

// PUT /api/cdn64/hosts/{id}/servers bzw. /api/cdn64/online/servers {count, sessions}: Server (0 = alle, auch
// kuenftige) und Verbindungen je Server setzen; sessions fehlt = wie bisher.
func (m *Module) apiServersPut(w http.ResponseWriter, r *http.Request) {
	hid := pathID(r)
	in := struct {
		Count    *int `json:"count"`
		Sessions *int `json:"sessions"`
	}{}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	cur, err := m.serversOf(r, hid)
	if err != nil {
		m.onlineFail(w, r, err)
		return
	}
	a, ok := m.online.api.(serversAPI)
	if !ok {
		m.onlineFail(w, r, errOnline("not_configured"))
		return
	}
	ses := cur.CurSessions
	if in.Sessions != nil {
		ses = *in.Sessions
	}
	if in.Count == nil || *in.Count < 0 || ses < 1 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "count (>= 0) required, sessions >= 1", "field": "count"})
		return
	}
	n := *in.Count
	var s *ipv64api.CDN64Servers
	target := strconv.Itoa(n) + "x" + strconv.Itoa(ses)
	if hid > 0 {
		ids := m.onlineRemoteIDs(r.Context(), hid)
		if len(ids) == 0 {
			m.onlineFail(w, r, errOnline("not_online"))
			return
		}
		s, err = m.setHostServers(r.Context(), a, ids, n, ses)
		target = strconv.FormatInt(hid, 10) + ": " + target
	} else {
		c, _, cerr := m.onlineConf(r.Context())
		if cerr != nil || c == nil {
			m.onlineFail(w, r, errOnline("not_configured"))
			return
		}
		s, err = m.setTunnelServers(r.Context(), a, c.Tunnel, n, ses)
	}
	if err != nil {
		m.onlineFail(w, r, err)
		return
	}
	m.g.Audit(r, "cdn64.online.servers", target, strings.Join(s.Assigned, ","))
	writeJSON(w, http.StatusOK, toServersJSON(newServersView(s)))
}
