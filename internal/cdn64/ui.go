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
	mux.Handle("GET /cdn64", page(m.listOf(KindProxy)))
	mux.Handle("GET /cdn64/redirects", page(m.listOf(KindRedirect)))
	mux.Handle("GET /cdn64/dead", page(m.listOf(KindDead)))
	mux.Handle("GET /cdn64/default", page(m.pageDefault))
	mux.Handle("POST /cdn64/default", page(m.pageDefaultSave))
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
	m.certRoutes(mux, page)
	m.streamRoutes(mux, page)
	m.c4Routes(mux, page)
}

// listPath: Liste der Hosts einer Art.
func listPath(kind string) string {
	switch kind {
	case KindRedirect:
		return "/cdn64/redirects"
	case KindDead:
		return "/cdn64/dead"
	case KindPass:
		return "/cdn64/streams"
	}
	return "/cdn64"
}

// tab ist ein Reiter des Moduls.
type tab struct {
	Path, Icon, TitleKey string
	Active               bool
}

func tabs(active string) []tab {
	t := []tab{{Path: "/cdn64", Icon: "bi-arrow-left-right", TitleKey: "cdn64.tab.hosts"},
		{Path: "/cdn64/redirects", Icon: "bi-signpost-split", TitleKey: "cdn64.tab.redirects"},
		{Path: "/cdn64/dead", Icon: "bi-sign-stop", TitleKey: "cdn64.tab.dead"},
		{Path: "/cdn64/streams", Icon: "bi-ethernet", TitleKey: "cdn64.tab.streams"},
		{Path: "/cdn64/access", Icon: "bi-person-lock", TitleKey: "cdn64.tab.access"},
		{Path: "/certificates", Icon: "bi-shield-lock", TitleKey: "cdn64.tab.certs"}, // Kernseite
		{Path: "/cdn64/log", Icon: "bi-list-columns", TitleKey: "cdn64.tab.log"},
		{Path: "/cdn64/default", Icon: "bi-question-square", TitleKey: "cdn64.tab.default"}}
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
	if h.Kind == KindPass {
		return certInfo{State: "pass"}
	}
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
	Day      HostStat // letzte 24 Stunden (aus cdn64.db)
	ACLName  string
	Watch    []Watch // Healthchecks auf genau dieses Ziel
}

type listData struct {
	Kind         string
	Tabs         []tab
	Rows         []hostRow
	EdgeErr      string
	EdgeOpen     bool
	Listeners    []edge.ListenerStatus
	CacheN       int
	CacheB       int64
	StartedAt    time.Time
	StatsOn      bool  // cdn64.db verfuegbar (Statistik-Karte)
	BlockedTotal int64 // abgewiesen seit dem Start: Exploits, Zugriffslisten, Blocklisten
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
	var day map[int64]HostStat
	if sdb := m.stats2.Load(); sdb != nil {
		day, _ = sdb.sums(ctx, time.Now().Add(-24*time.Hour))
	}
	acls := map[int64]string{}
	if al, err := m.accessLists(ctx); err == nil {
		for _, a := range al {
			acls[a.ID] = a.Name
		}
	}
	watch := m.watchIndex(ctx)
	out := make([]hostRow, 0, len(list))
	for _, h := range list {
		st := m.statsOf(h.ID)
		row := hostRow{Host: h, Reach: m.reach.get(h.ID), Requests: st.requests.Load(), Errors: st.errors.Load(), Blocked: st.blocked.Load(),
			URL: firstURL(h), Cert: m.certFor(ctx, h, all), RouteErr: routeErr[h.ID], Day: day[h.ID], ACLName: acls[h.AccessListID]}
		if h.probed() {
			row.Watch = watch.of(h.TargetHost, h.TargetPort)
		}
		out = append(out, row)
	}
	return out, nil
}

// rowsOf: Hosts einer Art.
func (m *Module) rowsOf(ctx context.Context, kind string) ([]hostRow, error) {
	all, err := m.rows(ctx)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, r := range all {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *Module) listOf(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { m.pageHosts(w, r, kind) }
}

func (m *Module) pageHosts(w http.ResponseWriter, r *http.Request, kind string) {
	rows, err := m.rowsOf(r.Context(), kind)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d := listData{Kind: kind, Tabs: tabs(listPath(kind)), Rows: rows, EdgeErr: m.edgeError(), StatsOn: m.stats2.Load() != nil, BlockedTotal: m.bl.blocked.Load()}
	for _, row := range rows {
		d.BlockedTotal += row.Blocked
	}
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
	back := r.PostFormValue("back")
	if !strings.HasPrefix(back, "/cdn64") {
		back = "/cdn64"
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

type formData struct {
	Tabs    []tab
	Host    *Host
	Names   string
	Certs   []*certs.Cert
	New     bool
	Back    string // Liste dieser Art
	NewCert bool   // "Zertifikat gleich mit anfordern" gewaehlt (nach einem Fehler im Formular)
	Errors  map[string]string
	ACLs    []*AccessList
	DNS     []*certs.DNSAccount // Zugaenge fuer "Zertifikat gleich mit anfordern"
	IPv64   bool                // DNS-Eintrag bei ipv64 moeglich (API-Key)
	Zones   []string            // ipv64-Domains (Ziel fuer CNAME)
	Locs    []Location          // vorhandene Locations und zwei leere Zeilen
	Adv     advText
	CFNets  string
}

// advText: die weiteren Optionen als Text fuer das Formular.
type advText struct {
	ReqSet, ReqDel, RespSet, RespDel, Trusted string
	HostMode, HostValue                       string
}

func headersText(list []Header) string {
	var b strings.Builder
	for _, x := range list {
		b.WriteString(x.Name + ": " + x.Value + "\n")
	}
	return b.String()
}

func parseHeaders(text string) []Header {
	var out []Header
	for _, line := range strings.Split(text, "\n") {
		name, val, ok := strings.Cut(strings.TrimRight(line, "\r"), ":")
		if !ok || strings.TrimSpace(name) == "" {
			continue
		}
		out = append(out, Header{Name: strings.TrimSpace(name), Value: strings.TrimSpace(val)})
	}
	return out
}

func lines(text string) []string {
	var out []string
	for _, l := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ' ' }) {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (m *Module) form(ctx context.Context, h *Host, isNew bool) formData {
	d := formData{Tabs: tabs(listPath(h.Kind)), Back: listPath(h.Kind), Host: h, Names: strings.Join(h.Names, "\n"), New: isNew, Errors: map[string]string{}}
	if m.certs != nil {
		d.Certs, _ = m.certs.List(ctx)
	}
	d.ACLs, _ = m.accessLists(ctx)
	if m.certs != nil {
		d.DNS, _ = m.certs.DNSAccounts(ctx)
	}
	if isNew && m.dnsrec != nil && m.dnsrec.Ready(ctx) {
		d.IPv64 = true
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		d.Zones, _ = m.dnsrec.Domains(dctx)
		cancel()
	}
	d.Locs = append(append([]Location{}, h.Locations...), Location{Scheme: "http", WebSockets: true}, Location{Scheme: "http", WebSockets: true})
	a := h.Advanced
	d.Adv = advText{ReqSet: headersText(a.RequestHeaders), ReqDel: strings.Join(a.RequestRemove, "\n"), RespSet: headersText(a.ResponseHeaders),
		RespDel: strings.Join(a.ResponseRemove, "\n"), Trusted: strings.Join(a.TrustedProxies, "\n")}
	switch a.HostHeader {
	case "", "target":
		d.Adv.HostMode = a.HostHeader
	default:
		d.Adv.HostMode, d.Adv.HostValue = "custom", a.HostHeader
	}
	d.CFNets = strings.Join(CloudflareNets, "\n")
	return d
}

func (m *Module) pageNew(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if !validKind(kind) {
		kind = KindProxy
	}
	m.g.Render(w, r, http.StatusOK, Name+"/host_form", "cdn64.new", m.form(r.Context(), newHostKind(kind), true))
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
	h.RedirectTarget, h.RedirectScheme, h.PreservePath = strings.TrimSpace(r.PostFormValue("redirect_target")), r.PostFormValue("redirect_scheme"), on("preserve_path")
	h.RedirectCode, _ = strconv.Atoi(r.PostFormValue("redirect_code"))
	h.AccessListID, _ = strconv.ParseInt(r.PostFormValue("access_list_id"), 10, 64)
	if r.PostFormValue("has_locations") == "1" { // Reiter Locations war im Formular
		n, _ := strconv.Atoi(r.PostFormValue("loc_count"))
		h.Locations = []Location{}
		for i := 0; i < n && i < 50; i++ {
			k := "loc_" + strconv.Itoa(i) + "_"
			path := strings.TrimSpace(r.PostFormValue(k + "path"))
			if path == "" {
				continue
			}
			port, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue(k + "port")))
			acl, _ := strconv.ParseInt(r.PostFormValue(k+"acl"), 10, 64)
			h.Locations = append(h.Locations, Location{Path: path, Scheme: r.PostFormValue(k + "scheme"), TargetHost: strings.TrimSpace(r.PostFormValue(k + "host")),
				TargetPort: port, ForwardPath: r.PostFormValue(k + "forward"), WebSockets: on(k + "ws"), AccessListID: acl})
		}
	}
	if r.PostFormValue("has_advanced") == "1" { // Reiter Erweitert war im Formular
		a := &h.Advanced
		a.RequestHeaders, a.RequestRemove = parseHeaders(r.PostFormValue("adv_req_set")), lines(r.PostFormValue("adv_req_del"))
		a.ResponseHeaders, a.ResponseRemove = parseHeaders(r.PostFormValue("adv_resp_set")), lines(r.PostFormValue("adv_resp_del"))
		switch r.PostFormValue("adv_host_mode") {
		case "target":
			a.HostHeader = "target"
		case "custom":
			a.HostHeader = strings.TrimSpace(r.PostFormValue("adv_host_value"))
		default:
			a.HostHeader = ""
		}
		a.TimeoutSeconds, _ = strconv.Atoi(strings.TrimSpace(r.PostFormValue("adv_timeout")))
		a.MaxBodyMB, _ = strconv.Atoi(strings.TrimSpace(r.PostFormValue("adv_max_body")))
		a.NoBuffering, a.Gzip, a.AccessLog = on("adv_no_buffering"), on("adv_gzip"), on("adv_access_log")
		a.TrustedProxies = lines(r.PostFormValue("adv_trusted"))
	}
	if h.Kind == KindPass {
		h.CertID = CertNone
	}
}

func (m *Module) pageCreate(w http.ResponseWriter, r *http.Request) {
	kind := r.PostFormValue("kind")
	if !validKind(kind) {
		kind = KindProxy
	}
	h := newHostKind(kind)
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
		d.NewCert = r.PostFormValue("cert_id") == "new"
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
	if r.PostFormValue("dns_create") == "on" { // DNS-Eintrag bei ipv64
		res, err := m.createRecords(ctx, h.Names, DNSRequest{Type: r.PostFormValue("dns_type"), Content: r.PostFormValue("dns_content")})
		if err != nil {
			var fe *FieldError
			msg := err.Error()
			if errors.As(err, &fe) {
				msg = m.g.T(r, fe.Key)
			}
			m.g.Flash(w, r, "warning", m.g.T(r, "cdn64.dnsrec.failed", "error", msg))
		} else {
			n, text := dnsSummary(res)
			m.g.Audit(r, "certs.dns.create", strings.Join(h.Names, ","), text)
			m.g.Flash(w, r, "info", m.g.T(r, "cdn64.dnsrec.result", "n", n, "details", text))
		}
	}
	if r.PostFormValue("cert_id") == "new" && m.certs != nil { // Zertifikat gleich mit anfordern
		src, dnsAcc := r.PostFormValue("cert_source"), int64(0)
		if v, ok := strings.CutPrefix(src, "dns:"); ok { // "dns:<Zugang>"
			src = "dns"
			dnsAcc, _ = strconv.ParseInt(v, 10, 64)
		}
		c, err := m.requestCert(ctx, h.Names, src, "", "", dnsAcc, false)
		if err != nil {
			m.g.Flash(w, r, "warning", m.g.T(r, "certs.host_saved_no_cert", "error", m.certError(r, err)))
			http.Redirect(w, r, listPath(h.Kind), http.StatusSeeOther)
			return
		}
		m.auditCert(r, c)
		m.g.Flash(w, r, "success", m.g.T(r, "certs.host_saved_cert", "name", c.Title()))
		http.Redirect(w, r, listPath(h.Kind), http.StatusSeeOther)
		return
	}
	m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	http.Redirect(w, r, listPath(h.Kind), http.StatusSeeOther)
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
	http.Redirect(w, r, listPath(h.Kind), http.StatusSeeOther)
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
	http.Redirect(w, r, listPath(h.Kind), http.StatusSeeOther)
}

func itoa(n int) string { return strconv.Itoa(n) }
