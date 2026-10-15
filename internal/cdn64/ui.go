package cdn64

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/module"
)

func (m *Module) uiRoutes(mux *http.ServeMux, g module.Guards) {
	page := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /cdn64", page(m.pageHosts))
	mux.Handle("GET /proxy", page(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/cdn64", http.StatusMovedPermanently)
	}))
	mux.Handle("POST /cdn64/check", page(m.pageCheck))
	mux.Handle("GET /cdn64/hosts/new", page(m.pageNew))
	mux.Handle("POST /cdn64/hosts", page(m.pageCreate))
	mux.Handle("GET /cdn64/hosts/{id}", page(m.pageEdit))
	mux.Handle("POST /cdn64/hosts/{id}", page(m.pageUpdate))
	mux.Handle("POST /cdn64/hosts/{id}/delete", page(m.pageDelete))
	mux.Handle("POST /cdn64/hosts/{id}/enable", page(m.pageToggle))
	mux.Handle("POST /cdn64/hosts/{id}/disable", page(m.pageToggle))
}

// tab ist ein Reiter des Moduls.
type tab struct {
	Path, Icon, TitleKey string
	Active               bool
}

func tabs(active string) []tab {
	t := []tab{{Path: "/cdn64", Icon: "bi-arrow-left-right", TitleKey: "cdn64.tab.hosts"}}
	for i := range t {
		t[i].Active = t[i].Path == active
	}
	return t
}

// certInfo: wie es um das Zertifikat eines Hosts steht.
type certInfo struct {
	State string // http, ok, soon, expired, missing, fixed_missing
	Name  string
	Days  int
	Miss  string // Name ohne passendes Zertifikat
}

func (m *Module) certFor(ctx context.Context, h *Host, all map[int64]*certs.Cert) certInfo {
	if !h.HTTPS() {
		return certInfo{State: "http"}
	}
	if m.certs == nil {
		return certInfo{State: "missing", Miss: h.Names[0]}
	}
	pick := func(c *certs.Cert) certInfo {
		ci := certInfo{State: "ok", Name: c.Title(), Days: c.DaysLeft()}
		switch {
		case c.NotAfter.IsZero():
			ci.State = "missing"
		case time.Now().After(c.NotAfter):
			ci.State = "expired"
		case ci.Days < 14:
			ci.State = "soon"
		}
		return ci
	}
	if h.CertID > 0 {
		if c := all[h.CertID]; c != nil {
			return pick(c)
		}
		return certInfo{State: "missing", Miss: h.Names[0]}
	}
	var first *certs.Cert
	for _, n := range h.Names {
		id := m.certs.MatchID(n)
		if id == 0 || all[id] == nil {
			return certInfo{State: "missing", Miss: n}
		}
		if first == nil {
			first = all[id]
		}
	}
	return pick(first)
}

type hostRow struct {
	*Host
	Reach    Reach
	Requests int64
	Errors   int64
	Blocked  int64
	URL      string
	Cert     certInfo
	RouteErr string
}

type listData struct {
	Tabs      []tab
	Rows      []hostRow
	EdgeErr   string
	EdgeOpen  bool
	Listeners []edge.ListenerStatus
	CacheN    int
	CacheB    int64
	StartedAt time.Time
}

func (m *Module) rows(ctx context.Context) ([]hostRow, error) {
	list, err := m.hosts(ctx)
	if err != nil {
		return nil, err
	}
	all := map[int64]*certs.Cert{}
	if m.certs != nil {
		if cl, err := m.certs.List(ctx); err == nil {
			for _, c := range cl {
				all[c.ID] = c
			}
		}
	}
	m.mu.Lock()
	routeErr := m.routeErr
	m.mu.Unlock()
	out := make([]hostRow, 0, len(list))
	for _, h := range list {
		st := m.statsOf(h.ID)
		out = append(out, hostRow{Host: h, Reach: m.reach.get(h.ID), Requests: st.requests.Load(), Errors: st.errors.Load(), Blocked: st.blocked.Load(),
			URL: firstURL(h), Cert: m.certFor(ctx, h, all), RouteErr: routeErr[h.ID]})
	}
	return out, nil
}

func (m *Module) pageHosts(w http.ResponseWriter, r *http.Request) {
	rows, err := m.rows(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d := listData{Tabs: tabs("/cdn64"), Rows: rows, EdgeErr: m.edgeError()}
	if m.edge != nil {
		d.Listeners = m.edge.Status().Listeners
		for _, l := range d.Listeners {
			d.EdgeOpen = d.EdgeOpen || l.Running
		}
	}
	n, b, _, _ := m.cache.stats()
	d.CacheN, d.CacheB = n, int64(b)
	m.mu.Lock()
	d.StartedAt = m.startedAt
	m.mu.Unlock()
	m.g.Render(w, r, http.StatusOK, Name+"/hosts", "cdn64.title", d)
}

func (m *Module) pageCheck(w http.ResponseWriter, r *http.Request) {
	m.checkSoon(0)
	m.g.Flash(w, r, "success", m.g.T(r, "cdn64.checking"))
	http.Redirect(w, r, "/cdn64", http.StatusSeeOther)
}

type formData struct {
	Tabs   []tab
	Host   *Host
	Names  string
	Certs  []*certs.Cert
	New    bool
	Errors map[string]string
}

func (m *Module) form(ctx context.Context, h *Host, isNew bool) formData {
	d := formData{Tabs: tabs("/cdn64"), Host: h, Names: strings.Join(h.Names, "\n"), New: isNew, Errors: map[string]string{}}
	if m.certs != nil {
		d.Certs, _ = m.certs.List(ctx)
	}
	return d
}

func (m *Module) pageNew(w http.ResponseWriter, r *http.Request) {
	m.g.Render(w, r, http.StatusOK, Name+"/host_form", "cdn64.new", m.form(r.Context(), newHost(), true))
}

func (m *Module) pageEdit(w http.ResponseWriter, r *http.Request) {
	h, ok := m.hostFromPath(w, r)
	if !ok {
		return
	}
	m.g.Render(w, r, http.StatusOK, Name+"/host_form", "cdn64.edit", m.form(r.Context(), h, false))
}

func (m *Module) hostFromPath(w http.ResponseWriter, r *http.Request) (*Host, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		if h, err := m.host(r.Context(), id); err == nil {
			return h, true
		}
	}
	http.NotFound(w, r)
	return nil, false
}

// hostFromForm liest das Formular in h (Haken fehlen im Formular, wenn sie aus sind).
func hostFromForm(r *http.Request, h *Host) {
	on := func(k string) bool { return r.PostFormValue(k) == "on" }
	h.Names = ParseNames(r.PostFormValue("names"))
	h.Scheme = r.PostFormValue("scheme")
	h.TargetHost = strings.TrimSpace(r.PostFormValue("target_host"))
	h.TargetPort, _ = strconv.Atoi(strings.TrimSpace(r.PostFormValue("target_port")))
	h.Enabled, h.WebSockets, h.BlockExploits, h.CacheAssets = on("enabled"), on("websockets"), on("block_exploits"), on("cache_assets")
	h.CertID, _ = strconv.ParseInt(r.PostFormValue("cert_id"), 10, 64)
	h.ForceSSL, h.HTTP2, h.HTTP3, h.HSTS, h.HSTSSubdomains = on("force_ssl"), on("http2"), on("http3"), on("hsts"), on("hsts_subdomains")
	h.MinTLS, h.VerifyTarget = r.PostFormValue("min_tls"), on("verify_target")
}

func (m *Module) pageCreate(w http.ResponseWriter, r *http.Request) {
	h := newHost()
	hostFromForm(r, h)
	m.saveForm(w, r, h, true)
}

func (m *Module) pageUpdate(w http.ResponseWriter, r *http.Request) {
	h, ok := m.hostFromPath(w, r)
	if !ok {
		return
	}
	hostFromForm(r, h)
	m.saveForm(w, r, h, false)
}

func (m *Module) saveForm(w http.ResponseWriter, r *http.Request, h *Host, isNew bool) {
	ctx := r.Context()
	names := h.Names
	if err := m.saveHost(ctx, h); err != nil {
		d := m.form(ctx, h, isNew)
		d.Names = strings.Join(names, "\n")
		var fe *FieldError
		if errors.As(err, &fe) {
			d.Errors[fe.Field] = m.g.T(r, fe.Key, "name", fe.Name)
		} else {
			d.Errors["_"] = err.Error()
		}
		title := "cdn64.edit"
		if isNew {
			title = "cdn64.new"
		}
		m.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/host_form", title, d)
		return
	}
	action := "cdn64.host.update"
	if isNew {
		action = "cdn64.host.create"
	}
	m.g.Audit(r, action, strings.Join(h.Names, ","), h.summary())
	m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	http.Redirect(w, r, "/cdn64", http.StatusSeeOther)
}

func (m *Module) pageDelete(w http.ResponseWriter, r *http.Request) {
	h, ok := m.hostFromPath(w, r)
	if !ok {
		return
	}
	if err := m.deleteHost(r.Context(), h.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	m.g.Audit(r, "cdn64.host.delete", strings.Join(h.Names, ","), "target="+h.Target())
	m.g.Flash(w, r, "success", m.g.T(r, "cdn64.deleted", "name", h.Names[0]))
	http.Redirect(w, r, "/cdn64", http.StatusSeeOther)
}

func (m *Module) pageToggle(w http.ResponseWriter, r *http.Request) {
	h, ok := m.hostFromPath(w, r)
	if !ok {
		return
	}
	on := strings.HasSuffix(r.URL.Path, "/enable")
	if err := m.setEnabled(r.Context(), h.ID, on); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	action := "cdn64.host.disable"
	if on {
		action = "cdn64.host.enable"
	}
	m.g.Audit(r, action, strings.Join(h.Names, ","), "")
	http.Redirect(w, r, "/cdn64", http.StatusSeeOther)
}

func itoa(n int) string { return strconv.Itoa(n) }
