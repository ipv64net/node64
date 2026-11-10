package dns64

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/dns64/dhcp"
	"github.com/ipv64net/node64/internal/dns64/groups"
	"github.com/ipv64net/node64/internal/module"
)

// Seite (eigener Menuepunkt unter DNS64) und API fuer den DHCP-Server (dhcp.go).

func (m *Module) dhcpRoutes(mux *http.ServeMux, g module.Guards) {
	h := func(f http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(f)) }
	mux.Handle("GET /dns64/dhcp", h(m.pageTab("dhcp", "dns64.dhcp.title")))
	mux.Handle("POST /dns64/dhcp/mode", h(m.pageDHCPMode))
	mux.Handle("POST /dns64/dhcp/role", h(m.pageDHCPRole))
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
	mux.Handle("PUT /api/dns64/dhcp/role", h(m.apiDHCPRole))
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
	mux.Handle("POST /dns64/dhcp/ipv6", h(m.pageRASave))
	mux.Handle("POST /dns64/dhcp/ipv6/probe", h(m.pageRAProbe))
	mux.Handle("GET /api/dns64/dhcp/ipv6", h(m.apiRA))
	mux.Handle("PUT /api/dns64/dhcp/ipv6", h(m.apiRASave))
	mux.Handle("POST /api/dns64/dhcp/ipv6/probe", h(m.apiRAProbe))
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
	DNSName   string // Name im DNS (<name>.<Domain>), "" = keiner
	Fixed     bool
	Active    bool
}

// dhcpResView: feste Adresse mit DNS-Namen.
type dhcpResView struct {
	DHCPReservation
	DNSName string
}

// dhcpReserveView: Rolle dieser Node im Cluster (D6).
type dhcpReserveView struct {
	Cluster    bool   // es gibt andere Nodes im Cluster (bzw. Rolle Reserve gesetzt)
	Role       string // primary | reserve
	HasPrimary bool   // Reserve: fuer mindestens ein eigenes Netz gibt es eine Haupt-Node
	Names      string // Reserve: Namen der Haupt-Nodes fuer die eigenen Netze
	Standby    bool   // Reserve bleibt gerade still (eine Haupt-Node lebt)
}

type dhcpPage struct {
	Mode      string
	Bridge    bool
	Running   bool // Server laeuft (Schalter an/Probelauf und mindestens ein Netz)
	Scopes    []dhcpScopeView
	Res       []dhcpResView
	ResScope  map[int64]string // Kennung -> Name des Netzes
	Groups    []groups.Group   // Auswahl "in Geraetegruppe aufnehmen"
	Reserve   dhcpReserveView
	Leases    []dhcpLeaseView
	Events    []dhcp.Event
	Foreign   []dhcp.Foreign
	Ifaces    []dhcpIface
	Suggest   DHCPScope
	Self      string              // Adresse dieser Node (Hinweis DNS-Server)
	Conflicts map[string][]string // Netz -> andere Haupt-Nodes, die dort auch vergeben
	RA        raView              // IPv6-DNS per Router Advertisement
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
	for _, x := range res {
		ip, _ := netip.ParseAddr(x.IP)
		v.Res = append(v.Res, dhcpResView{x, m.dhcpDNSName(ip)})
	}
	if gl, err := m.Groups(ctx); err == nil {
		v.Groups = gl
	}
	v.Reserve.Role = m.dhcpRole(ctx)
	v.Reserve.Cluster = len(m.dhcpPeers(ctx, "")) > 0 || v.Reserve.Role == dhcpReserve // Rolle nur mit anderen Nodes
	cl := m.dhcpClusterState(ctx)                                                      // einmal lesen (Peers, Namen, Zustaende)
	srv := m.dhcpSrv.Load()
	if v.Reserve.Role == dhcpReserve { // je eigenem Netz: lebt eine Haupt-Node?
		var names []string
		for _, s := range scopes {
			if !s.Enabled {
				continue
			}
			alive, prim := cl.primaryAlive(s.Subnet, srv)
			v.Reserve.Standby = v.Reserve.Standby || (alive && len(prim) > 0)
			v.Reserve.HasPrimary = v.Reserve.HasPrimary || len(prim) > 0
			for _, n := range prim {
				if !slices.Contains(names, n) {
					names = append(names, n)
				}
			}
		}
		v.Reserve.Names = strings.Join(names, ", ")
	}
	v.Conflicts = cl.conflicts(m.dhcpOwnNode(ctx))
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
			v.Leases = append(v.Leases, dhcpLeaseView{Lease: l, ScopeName: s.label(), ResName: r.Name, DNSName: m.dhcpDNSName(l.IP), Fixed: ok, Active: l.Active(now)})
		}
	}
	v.Events = snap.Events
	for _, f := range snap.Foreign { // die Haupt-Node einer Reserve ist kein fremder Server
		if !cl.expected(f.Server) {
			v.Foreign = append(v.Foreign, f)
		}
	}
	var pick *dhcpIface // Vorschlag: erste echte Schnittstelle mit privater Adresse (nicht docker0, virbr0 ...)
	for i := range v.Ifaces {
		if virtualIface(v.Ifaces[i].Name) {
			continue
		}
		if pick == nil || (!pick.Addrs[0].Addr().IsPrivate() && v.Ifaces[i].Addrs[0].Addr().IsPrivate()) {
			pick = &v.Ifaces[i]
		}
	}
	if pick != nil {
		v.Suggest, v.Self = pick.Suggest, pick.Addrs[0].Addr().String()
	}
	v.RA = m.raView(ctx, scopes)
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

func (m *Module) pageDHCPRole(w http.ResponseWriter, r *http.Request) {
	role := r.PostFormValue("role")
	err := m.SetDHCPRole(r.Context(), role)
	if err == nil {
		m.log.Info("dhcp role", "role", role, "by", m.g.Actor(r))
		m.audit(r, "dns64.dhcp.role", role, "")
	}
	m.dhcpBack(w, r, err, "common.saved")
}

func dhcpScopeForm(r *http.Request) DHCPScope {
	return DHCPScope{Name: r.PostFormValue("name"), Iface: r.PostFormValue("iface"), Subnet: r.PostFormValue("subnet"), Start: r.PostFormValue("start"),
		End: r.PostFormValue("end"), Router: r.PostFormValue("router"), DNS: dhcpList(r.PostFormValue("dns")), Domain: r.PostFormValue("domain"),
		LeaseHours: max(0, formInt(r, "lease_hours")), NTP: dhcpList(r.PostFormValue("ntp")), Authoritative: r.PostFormValue("authoritative") == "1",
		BootServer: r.PostFormValue("boot_server"), BootBIOS: r.PostFormValue("boot_bios"), BootUEFI: r.PostFormValue("boot_uefi"), BootIPXE: r.PostFormValue("boot_ipxe"),
		Relay: r.PostFormValue("relay") == "1"}
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
	gid, _ := strconv.ParseInt(r.PostFormValue("group"), 10, 64)
	return DHCPReservation{ScopeID: sid, MAC: r.PostFormValue("mac"), IP: r.PostFormValue("ip"), Name: r.PostFormValue("name"), Comment: r.PostFormValue("comment"), GroupID: gid}
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

// dhcpMAC normalisiert eine MAC (aa:bb:cc:dd:ee:ff) wie beim Anlegen fester Adressen.
func dhcpMAC(v string) (string, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(v))
	if err != nil || len(hw) != 6 {
		return "", errCfg("err_dhcp_mac")
	}
	return hw.String(), nil
}

func (m *Module) pageDHCPRelease(w http.ResponseWriter, r *http.Request) {
	sid, _ := strconv.ParseInt(r.PostFormValue("scope"), 10, 64)
	mac, err := dhcpMAC(r.PostFormValue("mac"))
	if err == nil {
		err = m.ReleaseDHCPLease(r.Context(), sid, mac)
	}
	if err == nil {
		m.audit(r, "dns64.dhcp.release", mac, "")
	}
	m.dhcpBack(w, r, err, "dns64.dhcp.released")
}

// ---- API ----

func (m *Module) apiDHCP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := struct {
		Mode      string              `json:"mode"`
		Role      string              `json:"role"`
		Standby   []string            `json:"standby"`   // Reserve: Netze, in denen sie still bleibt (Haupt-Node lebt)
		Conflicts map[string][]string `json:"conflicts"` // Netz -> andere Haupt-Nodes, die dort auch vergeben
		Running   bool                `json:"running"`
		Bridge    bool                `json:"docker_bridge"`
		View      dhcp.View           `json:"state"`
	}{Mode: m.dhcpMode(ctx), Role: m.dhcpRole(ctx), Standby: []string{}, Conflicts: m.dhcpConflicts(ctx), Bridge: dhcpBridge(),
		View: dhcp.View{Scopes: []dhcp.ScopeView{}, Events: []dhcp.Event{}, Foreign: []dhcp.Foreign{}}}
	if s := m.dhcpSrv.Load(); s != nil {
		out.Running, out.View = true, s.Snapshot()
	}
	if out.Role == dhcpReserve {
		scopes, _ := m.DHCPScopes(ctx)
		for _, s := range scopes {
			if alive, prim := m.dhcpPrimaryAlive(ctx, s.Subnet); s.Enabled && (alive || len(prim) == 0) {
				out.Standby = append(out.Standby, s.Subnet)
			}
		}
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

func (m *Module) apiDHCPRole(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Role string `json:"role"`
	}
	if !decode(w, r, &in) {
		return
	}
	err := m.SetDHCPRole(r.Context(), in.Role)
	if err == nil {
		m.audit(r, "dns64.dhcp.role", in.Role, "")
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
	mac, err := dhcpMAC(r.PathValue("mac"))
	if err == nil {
		err = m.ReleaseDHCPLease(r.Context(), sid, mac)
	}
	if err == nil {
		m.audit(r, "dns64.dhcp.release", mac, "")
	}
	m.apiResult(w, r, err, 0, nil)
}
