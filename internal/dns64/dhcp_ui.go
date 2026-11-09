package dns64

import (
	"context"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/dns64/dhcp"
	"github.com/ipv64net/node64/internal/module"
)

// Seite (eigener Menuepunkt unter DNS64) und API fuer den DHCP-Server (dhcp.go).

func (m *Module) dhcpRoutes(mux *http.ServeMux, g module.Guards) {
	h := func(f http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(f)) }
	mux.Handle("GET /dns64/dhcp", h(m.pageTab("dhcp", "dns64.dhcp.title")))
	mux.Handle("POST /dns64/dhcp/mode", h(m.pageDHCPMode))
	mux.Handle("POST /dns64/dhcp/scopes", h(m.pageDHCPScopeSave))
	mux.Handle("POST /dns64/dhcp/scopes/{id}/edit", h(m.pageDHCPScopeSave))
	mux.Handle("POST /dns64/dhcp/scopes/{id}/delete", h(m.pageDHCPScopeDelete))
	mux.Handle("POST /dns64/dhcp/scopes/{id}/toggle", h(m.pageDHCPScopeToggle))
	mux.Handle("POST /dns64/dhcp/reservations", h(m.pageDHCPResSave))
	mux.Handle("POST /dns64/dhcp/reservations/{id}/edit", h(m.pageDHCPResSave))
	mux.Handle("POST /dns64/dhcp/reservations/{id}/delete", h(m.pageDHCPResDelete))
	mux.Handle("POST /dns64/dhcp/leases/reserve", h(m.pageDHCPReserve))
	mux.Handle("POST /dns64/dhcp/leases/release", h(m.pageDHCPRelease))
	mux.Handle("GET /api/dns64/dhcp", h(m.apiDHCP))
	mux.Handle("PUT /api/dns64/dhcp/mode", h(m.apiDHCPMode))
	mux.Handle("GET /api/dns64/dhcp/scopes", h(m.apiDHCPScopes))
	mux.Handle("POST /api/dns64/dhcp/scopes", h(m.apiDHCPScopeSave))
	mux.Handle("PUT /api/dns64/dhcp/scopes/{id}", h(m.apiDHCPScopeSave))
	mux.Handle("DELETE /api/dns64/dhcp/scopes/{id}", h(m.apiDHCPScopeDelete))
	mux.Handle("POST /api/dns64/dhcp/scopes/{id}/enable", h(m.apiDHCPScopeToggle(true)))
	mux.Handle("POST /api/dns64/dhcp/scopes/{id}/disable", h(m.apiDHCPScopeToggle(false)))
	mux.Handle("GET /api/dns64/dhcp/reservations", h(m.apiDHCPReservations))
	mux.Handle("POST /api/dns64/dhcp/reservations", h(m.apiDHCPResSave))
	mux.Handle("PUT /api/dns64/dhcp/reservations/{id}", h(m.apiDHCPResSave))
	mux.Handle("DELETE /api/dns64/dhcp/reservations/{id}", h(m.apiDHCPResDelete))
	mux.Handle("DELETE /api/dns64/dhcp/leases/{scope}/{mac}", h(m.apiDHCPRelease))
}

// ---- Ansicht ----

// dhcpScopeView: Netz mit Zustand des laufenden Servers.
type dhcpScopeView struct {
	DHCPScope
	State dhcp.ScopeView
	Pct   int // belegt in Prozent (vergeben + fest)
}

// dhcpLeaseView: Lease mit Netz und fester Adresse.
type dhcpLeaseView struct {
	dhcp.Lease
	ScopeName string
	ResName   string // Name der festen Adresse ("" = keine)
	Fixed     bool
	Active    bool
}

type dhcpPage struct {
	Mode     string
	Bridge   bool
	Running  bool // Server laeuft (Schalter an/Probelauf und mindestens ein Netz)
	Scopes   []dhcpScopeView
	Res      []DHCPReservation
	ResScope map[int64]string // Kennung -> Name des Netzes
	Leases   []dhcpLeaseView
	Events   []dhcp.Event
	Foreign  []dhcp.Foreign
	Ifaces   []dhcpIface
	Suggest  DHCPScope
	Self     string // Adresse dieser Node (Hinweis DNS-Server)
}

func (m *Module) dhcpView(ctx context.Context, d *pageData) error {
	v := dhcpPage{Mode: m.dhcpMode(ctx), Bridge: dhcpBridge(), ResScope: map[int64]string{}, Ifaces: dhcpInterfaces()}
	scopes, err := m.DHCPScopes(ctx)
	if err != nil && !m.noTable(err) {
		return err
	}
	res, err := m.DHCPReservations(ctx)
	if err != nil && !m.noTable(err) {
		return err
	}
	v.Res = res
	var snap dhcp.View
	if s := m.dhcpSrv.Load(); s != nil {
		v.Running, snap = true, s.Snapshot()
	}
	state := map[int64]dhcp.ScopeView{}
	for _, sv := range snap.Scopes {
		state[sv.ID] = sv
	}
	fixed := map[string]DHCPReservation{} // Netz/MAC -> feste Adresse
	for _, r := range res {
		fixed[strconv.FormatInt(r.ScopeID, 10)+"/"+r.MAC] = r
	}
	now := time.Now()
	for _, s := range scopes {
		sv := dhcpScopeView{DHCPScope: s, State: state[s.ID]}
		if sv.State.Size > 0 {
			sv.Pct = min(100, (sv.State.Used+sv.State.Reserved)*100/sv.State.Size)
		}
		v.Scopes = append(v.Scopes, sv)
		v.ResScope[s.ID] = s.label()
		for _, l := range sv.State.Leases {
			r, ok := fixed[strconv.FormatInt(s.ID, 10)+"/"+l.MAC]
			v.Leases = append(v.Leases, dhcpLeaseView{Lease: l, ScopeName: s.label(), ResName: r.Name, Fixed: ok, Active: l.Active(now)})
		}
	}
	v.Events, v.Foreign = snap.Events, snap.Foreign
	if len(v.Ifaces) > 0 {
		v.Suggest = v.Ifaces[0].Suggest
		for _, i := range v.Ifaces { // erste Schnittstelle mit privater Adresse
			if len(i.Addrs) > 0 && i.Addrs[0].Addr().IsPrivate() {
				v.Suggest = i.Suggest
				break
			}
		}
		if p, err := netip.ParsePrefix(v.Suggest.Subnet); err == nil {
			for _, i := range v.Ifaces {
				for _, a := range i.Addrs {
					if p.Contains(a.Addr()) {
						v.Self = a.Addr().String()
					}
				}
			}
		}
	}
	d.DHCP = v
	return nil
}

func (m *Module) dhcpBack(w http.ResponseWriter, r *http.Request, err error, okKey string) {
	if err != nil {
		m.g.Flash(w, r, "danger", m.errText(r, err))
	} else if okKey != "" {
		m.g.Flash(w, r, "success", m.g.T(r, okKey))
	}
	http.Redirect(w, r, "/dns64/dhcp", http.StatusSeeOther)
}

// ---- Seite ----

func (m *Module) pageDHCPMode(w http.ResponseWriter, r *http.Request) {
	mode := r.PostFormValue("mode")
	err := m.SetDHCPMode(r.Context(), mode)
	if err == nil {
		m.log.Info("dhcp mode", "mode", mode, "by", m.g.Actor(r))
		m.audit(r, "dns64.dhcp.mode", mode, "")
	}
	m.dhcpBack(w, r, err, "common.saved")
}

func dhcpScopeForm(r *http.Request) DHCPScope {
	return DHCPScope{Name: r.PostFormValue("name"), Iface: r.PostFormValue("iface"), Subnet: r.PostFormValue("subnet"), Start: r.PostFormValue("start"),
		End: r.PostFormValue("end"), Router: r.PostFormValue("router"), DNS: dhcpList(r.PostFormValue("dns")), Domain: r.PostFormValue("domain"),
		LeaseHours: max(0, formInt(r, "lease_hours")), NTP: dhcpList(r.PostFormValue("ntp")), Authoritative: r.PostFormValue("authoritative") == "1",
		BootServer: r.PostFormValue("boot_server"), BootBIOS: r.PostFormValue("boot_bios"), BootUEFI: r.PostFormValue("boot_uefi"), BootIPXE: r.PostFormValue("boot_ipxe")}
}

func (m *Module) pageDHCPScopeSave(w http.ResponseWriter, r *http.Request) {
	s, err := dhcpScopeForm(r), error(nil)
	key := "dns64.dhcp.scope_added"
	if id := pathID(r); id > 0 {
		s, err = m.UpdateDHCPScope(r.Context(), id, s)
		key = "common.saved"
		if err == nil {
			m.audit(r, "dns64.dhcp.scope_edit", s.label(), "")
		}
	} else if s, err = m.AddDHCPScope(r.Context(), s); err == nil {
		m.audit(r, "dns64.dhcp.scope_add", s.label(), s.Start+"-"+s.End)
	}
	m.dhcpBack(w, r, err, key)
}

func (m *Module) pageDHCPScopeDelete(w http.ResponseWriter, r *http.Request) {
	err := m.DeleteDHCPScope(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.dhcp.scope_delete", r.PathValue("id"), "")
	}
	m.dhcpBack(w, r, err, "dns64.dhcp.scope_deleted")
}

func (m *Module) pageDHCPScopeToggle(w http.ResponseWriter, r *http.Request) {
	on := r.PostFormValue("on") == "1"
	err := m.SetDHCPScopeEnabled(r.Context(), pathID(r), on)
	if err == nil {
		m.audit(r, "dns64.dhcp.scope_"+onOff(on), r.PathValue("id"), "")
	}
	m.dhcpBack(w, r, err, "")
}

func dhcpResForm(r *http.Request) DHCPReservation {
	sid, _ := strconv.ParseInt(r.PostFormValue("scope"), 10, 64)
	return DHCPReservation{ScopeID: sid, MAC: r.PostFormValue("mac"), IP: r.PostFormValue("ip"), Name: r.PostFormValue("name"), Comment: r.PostFormValue("comment")}
}

func (m *Module) pageDHCPResSave(w http.ResponseWriter, r *http.Request) {
	x, err := dhcpResForm(r), error(nil)
	key := "dns64.dhcp.res_added"
	if id := pathID(r); id > 0 {
		x, err = m.UpdateDHCPReservation(r.Context(), id, x)
		key = "common.saved"
	} else {
		x, err = m.AddDHCPReservation(r.Context(), x)
	}
	if err == nil {
		m.audit(r, "dns64.dhcp.res_"+map[bool]string{true: "edit", false: "add"}[pathID(r) > 0], x.MAC, x.IP)
	}
	m.dhcpBack(w, r, err, key)
}

func (m *Module) pageDHCPResDelete(w http.ResponseWriter, r *http.Request) {
	err := m.DeleteDHCPReservation(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.dhcp.res_delete", r.PathValue("id"), "")
	}
	m.dhcpBack(w, r, err, "dns64.dhcp.res_deleted")
}

// pageDHCPReserve macht aus einem Lease eine feste Adresse (gleiche IP, Name vom Client).
func (m *Module) pageDHCPReserve(w http.ResponseWriter, r *http.Request) {
	x := dhcpResForm(r)
	x.Name = deviceSlug(x.Name)
	x, err := m.AddDHCPReservation(r.Context(), x)
	if err == nil {
		m.audit(r, "dns64.dhcp.res_add", x.MAC, x.IP)
	}
	m.dhcpBack(w, r, err, "dns64.dhcp.res_added")
}

func (m *Module) pageDHCPRelease(w http.ResponseWriter, r *http.Request) {
	sid, _ := strconv.ParseInt(r.PostFormValue("scope"), 10, 64)
	mac := strings.ToLower(r.PostFormValue("mac"))
	err := m.ReleaseDHCPLease(r.Context(), sid, mac)
	if err == nil {
		m.audit(r, "dns64.dhcp.release", mac, "")
	}
	m.dhcpBack(w, r, err, "dns64.dhcp.released")
}

// ---- API ----

func (m *Module) apiDHCP(w http.ResponseWriter, r *http.Request) {
	out := struct {
		Mode    string    `json:"mode"`
		Running bool      `json:"running"`
		Bridge  bool      `json:"docker_bridge"`
		View    dhcp.View `json:"state"`
	}{Mode: m.dhcpMode(r.Context()), Bridge: dhcpBridge(), View: dhcp.View{Scopes: []dhcp.ScopeView{}, Events: []dhcp.Event{}, Foreign: []dhcp.Foreign{}}}
	if s := m.dhcpSrv.Load(); s != nil {
		out.Running, out.View = true, s.Snapshot()
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) apiDHCPMode(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Mode string `json:"mode"`
	}
	if !decode(w, r, &in) {
		return
	}
	err := m.SetDHCPMode(r.Context(), in.Mode)
	if err == nil {
		m.audit(r, "dns64.dhcp.mode", in.Mode, "")
	}
	m.apiResult(w, r, err, http.StatusOK, in)
}

func (m *Module) apiDHCPScopes(w http.ResponseWriter, r *http.Request) {
	list, err := m.DHCPScopes(r.Context())
	m.apiResult(w, r, err, http.StatusOK, list)
}

func (m *Module) apiDHCPScopeSave(w http.ResponseWriter, r *http.Request) {
	var s DHCPScope
	if !decode(w, r, &s) {
		return
	}
	var err error
	status := http.StatusCreated
	if id := pathID(r); id > 0 {
		s, err = m.UpdateDHCPScope(r.Context(), id, s)
		status = http.StatusOK
	} else {
		s, err = m.AddDHCPScope(r.Context(), s)
	}
	if err == nil {
		m.audit(r, "dns64.dhcp.scope_"+map[bool]string{true: "add", false: "edit"}[status == http.StatusCreated], s.label(), "")
		if cur, e := m.dhcpScope(r.Context(), s.ID); e == nil {
			s = cur
		}
	}
	m.apiResult(w, r, err, status, s)
}

func (m *Module) apiDHCPScopeDelete(w http.ResponseWriter, r *http.Request) {
	err := m.DeleteDHCPScope(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.dhcp.scope_delete", r.PathValue("id"), "")
	}
	m.apiResult(w, r, err, 0, nil)
}

func (m *Module) apiDHCPScopeToggle(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := m.SetDHCPScopeEnabled(r.Context(), pathID(r), on)
		if err == nil {
			m.audit(r, "dns64.dhcp.scope_"+onOff(on), r.PathValue("id"), "")
		}
		m.apiResult(w, r, err, 0, nil)
	}
}

func (m *Module) apiDHCPReservations(w http.ResponseWriter, r *http.Request) {
	list, err := m.DHCPReservations(r.Context())
	m.apiResult(w, r, err, http.StatusOK, list)
}

func (m *Module) apiDHCPResSave(w http.ResponseWriter, r *http.Request) {
	var x DHCPReservation
	if !decode(w, r, &x) {
		return
	}
	var err error
	status := http.StatusCreated
	if id := pathID(r); id > 0 {
		x, err = m.UpdateDHCPReservation(r.Context(), id, x)
		status = http.StatusOK
	} else {
		x, err = m.AddDHCPReservation(r.Context(), x)
	}
	if err == nil {
		m.audit(r, "dns64.dhcp.res_"+map[bool]string{true: "add", false: "edit"}[status == http.StatusCreated], x.MAC, x.IP)
	}
	m.apiResult(w, r, err, status, x)
}

func (m *Module) apiDHCPResDelete(w http.ResponseWriter, r *http.Request) {
	err := m.DeleteDHCPReservation(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.dhcp.res_delete", r.PathValue("id"), "")
	}
	m.apiResult(w, r, err, 0, nil)
}

func (m *Module) apiDHCPRelease(w http.ResponseWriter, r *http.Request) {
	sid, _ := strconv.ParseInt(r.PathValue("scope"), 10, 64)
	mac := strings.ToLower(r.PathValue("mac"))
	err := m.ReleaseDHCPLease(r.Context(), sid, mac)
	if err == nil {
		m.audit(r, "dns64.dhcp.release", mac, "")
	}
	m.apiResult(w, r, err, 0, nil)
}
