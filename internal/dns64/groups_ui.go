package dns64

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/dns64/groups"
	"github.com/ipv64net/node64/internal/module"
)

// Seite und API "Gruppen" (Phase G1): Gruppen anlegen, Geraete per MAC, IP oder Netz zuordnen, Geraete der
// letzten 24 Stunden aus dem Abfrage-Log zur Auswahl. Regeln je Gruppe kommen in den naechsten Phasen.

// deviceView ist ein Geraet der letzten 24 Stunden (Seite Gruppen).
type deviceView struct {
	IP      string    `json:"ip"`
	Name    string    `json:"name,omitempty"`
	MAC     string    `json:"mac,omitempty"`
	Group   string    `json:"group,omitempty"`
	GroupID int64     `json:"group_id,omitempty"`
	Queries int64     `json:"queries"`
	Last    time.Time `json:"last_seen"`
}

// devices liefert die Clients der letzten 24 Stunden mit Name (Router), MAC (Nachbartabelle) und Gruppe.
func (m *Module) devices(ctx context.Context, e *engine) ([]deviceView, error) {
	rows, err := e.store.RecentClients(ctx, time.Now().Add(-24*time.Hour), 200)
	if err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(rows))
	for _, r := range rows {
		ips = append(ips, r.Client)
	}
	names := e.local.Hostnames(ctx, ips)
	out := make([]deviceView, 0, len(rows))
	for _, r := range rows {
		d := deviceView{IP: r.Client, Name: names[r.Client], Queries: r.Queries, Last: time.UnixMilli(r.LastSeen)}
		if ip, err := netip.ParseAddr(r.Client); err == nil { // gekuerzte Adressen (Datenschutz) haben weder MAC noch Gruppe
			match := m.grp.For(ip)
			d.MAC, d.Group, d.GroupID = match.MAC, match.Name, match.ID
		}
		out = append(out, d)
	}
	return out, nil
}

func (m *Module) groupRoutes(mux *http.ServeMux, g module.Guards) {
	page := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /dns64/groups", page(m.pageTab("groups", "dns64.groups.title")))
	mux.Handle("POST /dns64/groups", page(m.pageGroupAdd))
	mux.Handle("POST /dns64/groups/{id}/rename", page(m.pageGroupRename))
	mux.Handle("POST /dns64/groups/{id}/delete", page(m.pageGroupDelete))
	mux.Handle("POST /dns64/groups/{id}/move", page(m.pageGroupMove))
	mux.Handle("POST /dns64/groups/{id}/members", page(m.pageMemberAdd))
	mux.Handle("POST /dns64/groups/members/{id}/delete", page(m.pageMemberDelete))
	mux.Handle("POST /dns64/groups/assign", page(m.pageAssign))
	mux.Handle("POST /dns64/groups/{id}/rules", page(m.pageGroupRules))
	mux.Handle("POST /dns64/groups/{id}/domains", page(m.pageGroupDomainAdd))
	mux.Handle("POST /dns64/groups/domains/{id}/delete", page(m.pageGroupDomainDelete))

	plain := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /api/dns64/groups", plain(m.apiGroups))
	mux.Handle("POST /api/dns64/groups", plain(m.apiGroupAdd))
	mux.Handle("PUT /api/dns64/groups/{id}", plain(m.apiGroupRename))
	mux.Handle("DELETE /api/dns64/groups/{id}", plain(m.apiGroupDelete))
	mux.Handle("POST /api/dns64/groups/{id}/move", plain(m.apiGroupMove))
	mux.Handle("POST /api/dns64/groups/{id}/members", plain(m.apiMemberAdd))
	mux.Handle("DELETE /api/dns64/groups/members/{id}", plain(m.apiMemberDelete))
	mux.Handle("GET /api/dns64/devices", plain(m.apiDevices))
	mux.Handle("PUT /api/dns64/groups/{id}/rules", plain(m.apiGroupRules))
	mux.Handle("POST /api/dns64/groups/{id}/domains", plain(m.apiGroupDomainAdd))
	mux.Handle("DELETE /api/dns64/groups/domains/{id}", plain(m.apiGroupDomainDelete))
}

// ---- Seite ----

func (m *Module) groupBack(w http.ResponseWriter, r *http.Request, err error, okKey string) {
	if err != nil {
		m.g.Flash(w, r, "danger", m.errText(r, err))
	} else if okKey != "" {
		m.g.Flash(w, r, "success", m.g.T(r, okKey))
	}
	http.Redirect(w, r, "/dns64/groups", http.StatusSeeOther)
}

func pathID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}

func (m *Module) pageGroupAdd(w http.ResponseWriter, r *http.Request) {
	g, err := m.AddGroup(r.Context(), r.PostFormValue("name"))
	if err == nil {
		m.audit(r, "dns64.group.add", g.Name, "")
	}
	m.groupBack(w, r, err, "dns64.groups.added")
}

func (m *Module) pageGroupRename(w http.ResponseWriter, r *http.Request) {
	name := r.PostFormValue("name")
	err := m.RenameGroup(r.Context(), pathID(r), name)
	if err == nil {
		m.audit(r, "dns64.group.rename", r.PathValue("id"), name)
	}
	m.groupBack(w, r, err, "")
}

func (m *Module) pageGroupDelete(w http.ResponseWriter, r *http.Request) {
	err := m.DeleteGroup(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.group.delete", r.PathValue("id"), "")
	}
	m.groupBack(w, r, err, "dns64.groups.deleted")
}

func (m *Module) pageGroupMove(w http.ResponseWriter, r *http.Request) {
	up := r.PostFormValue("dir") == "up"
	err := m.MoveGroup(r.Context(), pathID(r), up)
	if err == nil {
		m.audit(r, "dns64.group.move", r.PathValue("id"), map[bool]string{true: "up", false: "down"}[up])
	}
	m.groupBack(w, r, err, "")
}

func (m *Module) pageMemberAdd(w http.ResponseWriter, r *http.Request) {
	x, err := m.AddMember(r.Context(), groups.Member{GroupID: pathID(r), Kind: r.PostFormValue("kind"), Value: r.PostFormValue("value"), Label: r.PostFormValue("label")})
	if err == nil {
		m.audit(r, "dns64.group.member.add", r.PathValue("id"), x.Kind+" "+x.Value)
	}
	m.groupBack(w, r, err, "")
}

func (m *Module) pageMemberDelete(w http.ResponseWriter, r *http.Request) {
	x, err := m.RemoveMember(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.group.member.remove", strconv.FormatInt(x.GroupID, 10), x.Kind+" "+x.Value)
	}
	m.groupBack(w, r, err, "")
}

// pageAssign ordnet ein Geraet aus der Liste einer Gruppe zu (per MAC, wenn bekannt, sonst per IP); Gruppe 0
// nimmt es aus seiner Gruppe.
func (m *Module) pageAssign(w http.ResponseWriter, r *http.Request) {
	gid, _ := strconv.ParseInt(r.PostFormValue("group_id"), 10, 64)
	mac, ip, label := r.PostFormValue("mac"), r.PostFormValue("ip"), r.PostFormValue("label")
	var err error
	if gid == 0 {
		err = m.UnassignDevice(r.Context(), mac, ip)
		if err == nil {
			m.audit(r, "dns64.group.member.remove", "", firstOr([]string{mac}, ip))
		}
	} else {
		x := groups.Member{GroupID: gid, Kind: groups.KindIP, Value: ip, Label: label}
		if mac != "" {
			x.Kind, x.Value = groups.KindMAC, mac
		}
		if x, err = m.AddMember(r.Context(), x); err == nil {
			m.audit(r, "dns64.group.member.add", strconv.FormatInt(gid, 10), x.Kind+" "+x.Value)
		}
	}
	m.groupBack(w, r, err, "")
}

// ---- API ----

func (m *Module) apiGroups(w http.ResponseWriter, r *http.Request) {
	list, err := m.Groups(r.Context())
	if err != nil {
		m.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// apiResult beantwortet einen Aenderungsaufruf (Fehler mit Text in der Sprache der Anfrage).
func (m *Module) apiResult(w http.ResponseWriter, r *http.Request, err error, status int, body any) {
	var ce *cfgError
	switch {
	case errors.Is(err, errNotFound):
		writeErr(w, http.StatusNotFound, m.errText(r, err))
	case errors.As(err, &ce):
		writeErr(w, http.StatusBadRequest, m.errText(r, err))
	case err != nil:
		m.fail(w, err)
	case body == nil:
		w.WriteHeader(http.StatusNoContent)
	default:
		writeJSON(w, status, body)
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return false
	}
	return true
}

func (m *Module) apiGroupAdd(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	g, err := m.AddGroup(r.Context(), in.Name)
	if err == nil {
		m.audit(r, "dns64.group.add", g.Name, "")
	}
	m.apiResult(w, r, err, http.StatusCreated, g)
}

func (m *Module) apiGroupRename(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	err := m.RenameGroup(r.Context(), pathID(r), in.Name)
	if err == nil {
		m.audit(r, "dns64.group.rename", r.PathValue("id"), in.Name)
	}
	m.apiResult(w, r, err, 0, nil)
}

func (m *Module) apiGroupDelete(w http.ResponseWriter, r *http.Request) {
	err := m.DeleteGroup(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.group.delete", r.PathValue("id"), "")
	}
	m.apiResult(w, r, err, 0, nil)
}

func (m *Module) apiGroupMove(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Up bool `json:"up"`
	}
	if !decode(w, r, &in) {
		return
	}
	err := m.MoveGroup(r.Context(), pathID(r), in.Up)
	if err == nil {
		m.audit(r, "dns64.group.move", r.PathValue("id"), map[bool]string{true: "up", false: "down"}[in.Up])
	}
	m.apiResult(w, r, err, 0, nil)
}

func (m *Module) apiMemberAdd(w http.ResponseWriter, r *http.Request) {
	var in groups.Member
	if !decode(w, r, &in) {
		return
	}
	in.GroupID = pathID(r)
	x, err := m.AddMember(r.Context(), in)
	if err == nil {
		m.audit(r, "dns64.group.member.add", r.PathValue("id"), x.Kind+" "+x.Value)
	}
	m.apiResult(w, r, err, http.StatusCreated, x)
}

func (m *Module) apiMemberDelete(w http.ResponseWriter, r *http.Request) {
	x, err := m.RemoveMember(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.group.member.remove", strconv.FormatInt(x.GroupID, 10), x.Kind+" "+x.Value)
	}
	m.apiResult(w, r, err, 0, nil)
}

func (m *Module) apiDevices(w http.ResponseWriter, r *http.Request) {
	e := m.running()
	if e == nil {
		writeErr(w, http.StatusServiceUnavailable, errNotRunning.Error())
		return
	}
	list, err := m.devices(r.Context(), e)
	m.apiResult(w, r, err, http.StatusOK, list)
}

// ---- Regeln je Gruppe (G2) ----

func (m *Module) pageGroupRules(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	in := groups.Rules{ListsMode: r.PostFormValue("lists_mode"), Lists: r.PostForm["lists"], Cats: r.PostForm["cats"],
		SafeSearch: r.PostFormValue("safesearch") != "", YouTube: r.PostFormValue("youtube"), Bypass: r.PostFormValue("bypass") != ""}
	err := m.SetGroupRules(r.Context(), pathID(r), in)
	if err == nil {
		m.audit(r, "dns64.group.rules", r.PathValue("id"), rulesDetail(in))
	}
	m.groupBack(w, r, err, "dns64.groups.rules_saved")
}

func rulesDetail(in groups.Rules) string {
	return "lists=" + in.ListsMode + " (" + strconv.Itoa(len(in.Lists)) + ") cats=" + strings.Join(in.Cats, ",") +
		" safesearch=" + strconv.FormatBool(in.SafeSearch) + " youtube=" + in.YouTube + " bypass=" + strconv.FormatBool(in.Bypass)
}

func (m *Module) pageGroupDomainAdd(w http.ResponseWriter, r *http.Request) {
	x, err := m.AddGroupDomain(r.Context(), groups.Domain{GroupID: pathID(r), Domain: r.PostFormValue("domain"), Action: r.PostFormValue("action")})
	if err == nil {
		m.audit(r, "dns64.group.domain.add", r.PathValue("id"), x.Action+" "+x.Domain)
	}
	m.groupBack(w, r, err, "")
}

func (m *Module) pageGroupDomainDelete(w http.ResponseWriter, r *http.Request) {
	x, err := m.RemoveGroupDomain(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.group.domain.remove", strconv.FormatInt(x.GroupID, 10), x.Action+" "+x.Domain)
	}
	m.groupBack(w, r, err, "")
}

func (m *Module) apiGroupRules(w http.ResponseWriter, r *http.Request) {
	var in groups.Rules
	if !decode(w, r, &in) {
		return
	}
	err := m.SetGroupRules(r.Context(), pathID(r), in)
	if err == nil {
		m.audit(r, "dns64.group.rules", r.PathValue("id"), rulesDetail(in))
	}
	m.apiResult(w, r, err, 0, nil)
}

func (m *Module) apiGroupDomainAdd(w http.ResponseWriter, r *http.Request) {
	var in groups.Domain
	if !decode(w, r, &in) {
		return
	}
	in.GroupID = pathID(r)
	x, err := m.AddGroupDomain(r.Context(), in)
	if err == nil {
		m.audit(r, "dns64.group.domain.add", r.PathValue("id"), x.Action+" "+x.Domain)
	}
	m.apiResult(w, r, err, http.StatusCreated, x)
}

func (m *Module) apiGroupDomainDelete(w http.ResponseWriter, r *http.Request) {
	x, err := m.RemoveGroupDomain(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.group.domain.remove", strconv.FormatInt(x.GroupID, 10), x.Action+" "+x.Domain)
	}
	m.apiResult(w, r, err, 0, nil)
}
