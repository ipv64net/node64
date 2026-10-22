package dns64

import (
	"net/http"
	"net/url"

	"github.com/ipv64net/node64/internal/module"
)

// Seite (Karte auf "Eigene Eintraege") und API fuer lokale Zonen (zones.go).

func (m *Module) zoneRoutes(mux *http.ServeMux, g module.Guards) {
	h := func(f http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(f)) }
	mux.Handle("POST /dns64/zones", h(m.pageZoneSave))
	mux.Handle("POST /dns64/zones/{id}/edit", h(m.pageZoneSave))
	mux.Handle("POST /dns64/zones/{id}/delete", h(m.pageZoneDelete))
	mux.Handle("POST /dns64/zones/{id}/toggle", h(m.pageZoneToggle))
	mux.Handle("GET /api/dns64/zones", h(m.apiZones))
	mux.Handle("POST /api/dns64/zones", h(m.apiZoneSave))
	mux.Handle("PUT /api/dns64/zones/{id}", h(m.apiZoneSave))
	mux.Handle("DELETE /api/dns64/zones/{id}", h(m.apiZoneDelete))
	mux.Handle("POST /api/dns64/zones/{id}/enable", h(m.apiZoneToggle(true)))
	mux.Handle("POST /api/dns64/zones/{id}/disable", h(m.apiZoneToggle(false)))
	mux.Handle("GET /api/dns64/device-names", h(m.apiDeviceNames))
	mux.Handle("GET /dns64/zones/{id}/zonefile", h(m.pageZoneFile))
	mux.Handle("POST /dns64/zones/{id}/tsig", h(m.pageZoneTSIG))
	mux.Handle("GET /api/dns64/zones/{id}/zonefile", h(m.pageZoneFile))
}

func (m *Module) pageZoneSave(w http.ResponseWriter, r *http.Request) {
	z := Zone{Name: r.PostFormValue("name"), Authoritative: r.PostFormValue("authoritative") == "1", Devices: r.PostFormValue("devices") == "1", Comment: r.PostFormValue("comment"),
		TTL: formInt(r, "ttl"), Refresh: formInt(r, "refresh"), Retry: formInt(r, "retry"), Expire: formInt(r, "expire"), Minimum: formInt(r, "minimum"), Hostmaster: r.PostFormValue("hostmaster")}
	for _, p := range []*int{&z.TTL, &z.Refresh, &z.Retry, &z.Expire, &z.Minimum} {
		if *p < 0 { // leer = Standard
			*p = 0
		}
	}
	var err error
	key := "dns64.zones.added"
	if id := pathID(r); id > 0 {
		z, err = m.UpdateZone(r.Context(), id, z)
		key = "dns64.records.saved"
		if err == nil && r.PostFormValue("from_settings") == "1" { // Einstellungen der Zone: auch dynamische Updates
			err = m.SetZoneDynamic(r.Context(), id, r.PostFormValue("dynamic") == "1", false)
		}
		if err == nil {
			m.audit(r, "dns64.zone.edit", z.Name, "")
		}
	} else if z, err = m.AddZone(r.Context(), z); err == nil {
		m.log.Info("zone added", "zone", z.Name, "by", m.g.Actor(r))
		m.audit(r, "dns64.zone.add", z.Name, "")
		m.g.Flash(w, r, "success", m.g.T(r, key))
		http.Redirect(w, r, "/dns64/local?zone="+url.QueryEscape(z.Name), http.StatusSeeOther) // neue Zone gleich offen
		return
	}
	m.recordBack(w, r, err, key)
}

// pageZoneTSIG erzeugt einen neuen Schluessel fuer dynamische Updates (der alte gilt sofort nicht mehr).
func (m *Module) pageZoneTSIG(w http.ResponseWriter, r *http.Request) {
	err := m.SetZoneDynamic(r.Context(), pathID(r), true, true)
	if err == nil {
		m.audit(r, "dns64.zone.tsig", r.PathValue("id"), "")
	}
	m.recordBack(w, r, err, "dns64.zones.tsig_renewed")
}

func (m *Module) pageZoneDelete(w http.ResponseWriter, r *http.Request) {
	err := m.DeleteZone(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.zone.delete", r.PathValue("id"), "")
		m.g.Flash(w, r, "success", m.g.T(r, "dns64.zones.deleted"))
		http.Redirect(w, r, "/dns64/local", http.StatusSeeOther)
		return
	}
	m.recordBack(w, r, err, "")
}

func (m *Module) pageZoneToggle(w http.ResponseWriter, r *http.Request) {
	on := r.PostFormValue("on") == "1"
	err := m.SetZoneEnabled(r.Context(), pathID(r), on)
	if err == nil {
		m.audit(r, "dns64.zone."+onOff(on), r.PathValue("id"), "")
	}
	m.recordBack(w, r, err, "")
}

func (m *Module) apiZones(w http.ResponseWriter, r *http.Request) {
	list, err := m.Zones(r.Context())
	m.apiResult(w, r, err, http.StatusOK, list)
}

func (m *Module) apiZoneSave(w http.ResponseWriter, r *http.Request) {
	var in Zone
	if !decode(w, r, &in) {
		return
	}
	var err error
	status := http.StatusCreated
	if id := pathID(r); id > 0 {
		in, err = m.UpdateZone(r.Context(), id, in)
		status = http.StatusOK
	} else {
		in, err = m.AddZone(r.Context(), in)
	}
	if err == nil {
		m.audit(r, "dns64.zone."+map[bool]string{true: "add", false: "edit"}[status == http.StatusCreated], in.Name, "")
	}
	m.apiResult(w, r, err, status, in)
}

func (m *Module) apiZoneDelete(w http.ResponseWriter, r *http.Request) {
	err := m.DeleteZone(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.zone.delete", r.PathValue("id"), "")
	}
	m.apiResult(w, r, err, 0, nil)
}

func (m *Module) apiZoneToggle(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := m.SetZoneEnabled(r.Context(), pathID(r), on)
		if err == nil {
			m.audit(r, "dns64.zone."+onOff(on), r.PathValue("id"), "")
		}
		m.apiResult(w, r, err, 0, nil)
	}
}

func (m *Module) apiDeviceNames(w http.ResponseWriter, r *http.Request) {
	out := m.DeviceNames()
	if out == nil {
		out = []deviceName{}
	}
	writeJSON(w, http.StatusOK, out)
}
