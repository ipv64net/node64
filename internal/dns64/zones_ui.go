package dns64

import (
	"net/http"

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
}

func (m *Module) pageZoneSave(w http.ResponseWriter, r *http.Request) {
	z := Zone{Name: r.PostFormValue("name"), Authoritative: r.PostFormValue("authoritative") == "1", Devices: r.PostFormValue("devices") == "1", Comment: r.PostFormValue("comment")}
	var err error
	key := "dns64.zones.added"
	if id := pathID(r); id > 0 {
		z, err = m.UpdateZone(r.Context(), id, z)
		key = "dns64.records.saved"
		if err == nil {
			m.audit(r, "dns64.zone.edit", z.Name, "")
		}
	} else if z, err = m.AddZone(r.Context(), z); err == nil {
		m.log.Info("zone added", "zone", z.Name, "by", m.g.Actor(r))
		m.audit(r, "dns64.zone.add", z.Name, "")
	}
	m.recordBack(w, r, err, key)
}

func (m *Module) pageZoneDelete(w http.ResponseWriter, r *http.Request) {
	err := m.DeleteZone(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.zone.delete", r.PathValue("id"), "")
	}
	m.recordBack(w, r, err, "dns64.records.deleted")
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
