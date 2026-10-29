package cdn64

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/module"
)

func (m *Module) uiRoutes(mux *http.ServeMux, g module.Guards) {
	page := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /cdn64", page(m.listOf(KindProxy)))
	mux.Handle("GET /cdn64/redirects", page(m.listOf(KindRedirect)))
	mux.Handle("GET /cdn64/dead", page(m.listOf(KindDead)))
	mux.Handle("GET /cdn64/status", page(m.listOf(KindStatus)))
	mux.Handle("GET /cdn64/streamnames", page(m.listOf(KindStream)))
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
	mux.Handle("POST /cdn64/hosts/{id}/maintenance", page(m.pageMaint))
	mux.Handle("GET /cdn64/hosts/{id}/maintenance/preview", page(m.pageMaintPreview))
	m.certRoutes(mux, page)
	m.streamRoutes(mux, page)
	m.c4Routes(mux, page)
	m.protectionRoutes(mux, page)
	m.dockerRoutes(mux, page)
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
	case KindStatus:
		return "/cdn64/status"
	case KindStream:
		return "/cdn64/streamnames"
	}
	return "/cdn64"
}

// tab ist ein Reiter des Moduls.
type tab struct {
	Path, Icon, TitleKey string
	Active               bool
}

// tabs: Reiter des Moduls; "CDN64 Statistik" nur mit CDN64-Namen im Konto (protectionOn), steht nach den Zugriffen.
func (m *Module) tabs(active string) []tab {
	t := []tab{{Path: "/cdn64", Icon: "bi-arrow-left-right", TitleKey: "cdn64.tab.hosts"},
		{Path: "/cdn64/redirects", Icon: "bi-signpost-split", TitleKey: "cdn64.tab.redirects"},
		{Path: "/cdn64/dead", Icon: "bi-sign-stop", TitleKey: "cdn64.tab.dead"},
		{Path: "/cdn64/status", Icon: "bi-clipboard-pulse", TitleKey: "cdn64.tab.status"},
		{Path: "/cdn64/streams", Icon: "bi-ethernet", TitleKey: "cdn64.tab.streams"},
		{Path: "/cdn64/access", Icon: "bi-person-lock", TitleKey: "cdn64.tab.access"},
		{Path: "/certificates", Icon: "bi-shield-lock", TitleKey: "cdn64.tab.certs"}, // Kernseite
		{Path: "/cdn64/log", Icon: "bi-list-columns", TitleKey: "cdn64.tab.log"},
		{Path: "/cdn64/docker", Icon: "bi-box-seam", TitleKey: "cdn64.tab.docker"},
		{Path: "/cdn64/default", Icon: "bi-question-square", TitleKey: "cdn64.tab.default"}}
	if m.protectionOn() {
		t = slices.Insert(t, 8, tab{Path: "/cdn64/protection", Icon: "bi-shield-check", TitleKey: "cdn64.tab.protection"}) // nach den Zugriffen, vor Docker
	}
	if active == "/cdn64/streamnames" { // Namen nur fuer Streams gehoeren zum Reiter Streams
		active = "/cdn64/streams"
	}
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
	if h.Kind == KindStream {
		return certInfo{State: "stream"}
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
	Watch    []Watch    // Healthchecks auf genau dieses Ziel
	Online   *onlineRow // CDN64 online (nil = aus)
	LocalN   int        // Namen, die schon in DNS64 stehen (lokaler Zugriff)
	Docker   string     // von Docker verwaltet: Container (Tooltip des Abzeichens), "" = von Hand angelegt
	DockerRO bool       // ... und Docker-Labels an: nicht loeschbar (Schalter aus: loeschbar wie in der API)

	Status *StatusPageInfo // Hostart status: die Seite (nil = unbekannt bzw. Healthchecks aus)
}

// onlineQuota: Kontingent unter der Liste (zwei Kacheln; Traffic in Byte, altes CDN mitgezaehlt).
type onlineQuota struct {
	Used, Limit, OldCDN, Mbit int
	Traffic, TrafficLimit     int64
	DomPct, TrafficPct        int       // Fuellstand in Prozent (0-100)
	DomBar, TrafficBar        float64   // Breite der Balken (bei Verbrauch mindestens 1 %, sonst unsichtbar)
	DomClass, TrafficClass    string    // Farbe der Balken (module.BarClassOf; Traffic gelb auch bei Short)
	Projected                 int64     // Prognose fuer den ganzen Monat bei gleichbleibendem Verbrauch (0 = noch keine)
	Short                     bool      // Prognose ueber dem Limit
	EmptyAt                   time.Time // voraussichtlich aufgebraucht (nur mit Short)
	MonthEnd                  time.Time
}

// newOnlineQuota rechnet Fuellstand und Prognose (ab dem zweiten Tag des Monats, linear hochgerechnet).
func newOnlineQuota(q ipv64api.CDN64Quota, now time.Time) *onlineQuota {
	o := &onlineQuota{Used: q.Domains.Used, Limit: q.Domains.Limit, OldCDN: q.Domains.OldCDN, Traffic: int64(q.TrafficMB.Used * (1 << 20)),
		TrafficLimit: int64(q.TrafficMB.Limit) << 20, Mbit: q.BandwidthMbit}
	pct := func(a, b int64) int {
		if b <= 0 {
			if a > 0 {
				return 100 // nicht im Tarif, aber belegt (ipv64 zaehlt das als ueberschritten)
			}
			return 0
		}
		return int(min(100, a*100/b))
	}
	o.DomPct, o.TrafficPct = pct(int64(o.Used), int64(o.Limit)), pct(o.Traffic, o.TrafficLimit)
	o.DomBar, o.TrafficBar = module.BarWidth(float64(o.DomPct), o.Used > 0), module.BarWidth(float64(o.TrafficPct), o.Traffic > 0)
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	o.MonthEnd = start.AddDate(0, 1, 0)
	if el := now.Sub(start); el >= 24*time.Hour && o.Traffic > 0 {
		rate := float64(o.Traffic) / el.Seconds() // Byte je Sekunde bisher
		o.Projected = int64(rate * o.MonthEnd.Sub(start).Seconds())
		if o.TrafficLimit > 0 && o.Projected > o.TrafficLimit {
			o.Short = true
			if left := o.TrafficLimit - o.Traffic; left > 0 {
				o.EmptyAt = now.Add(time.Duration(float64(left)/rate) * time.Second)
			} else {
				o.EmptyAt = now
			}
		}
	}
	o.DomClass, o.TrafficClass = module.BarClassOf(float64(o.DomPct), false), module.BarClassOf(float64(o.TrafficPct), o.Short)
	return o
}

type listData struct {
	Kind      string
	Tabs      []tab
	Rows      []hostRow
	EdgeErr   string
	Pub       edge.Published // Docker-Bridge-Netz: fehlen HTTP/HTTPS des Eingangs auf dem Host?
	EdgeOpen  bool
	Listeners []edge.ListenerStatus
	CacheN    int
	CacheB    int64
	StartedAt time.Time
	StatsOn   bool          // cdn64.db verfuegbar (Statistik-Karte)
	OnlineOn  bool          // CDN64 online verfuegbar (ipv64 angebunden)
	LimitsOn  bool          // Schutz vor Ueberlastung (Rate-Limits) eingeschaltet
	Quota     *onlineQuota  // Kontingent bei ipv64 (nur wenn Namen eingeschaltet sind)
	Others    []onlineOther // Namen des Accounts, die diese Node nicht verwaltet (Modus 3 von ipv64.net, andere Nodes)
	OnlineL   string        // Texte fuer cdn64-online.js (JSON)
	LocalOn   bool          // DNS64 laeuft (Knopf "lokal eintragen")
	LocalV4   string        // vorgeschlagene Adressen des Reverse-Proxys
	LocalV6   string
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
	onl := m.onlineIndex(ctx, list)
	ldns := m.localIndex(ctx)
	pages := map[int64]*StatusPageInfo{}
	for _, h := range list {
		if h.Kind == KindStatus { // nur abfragen, wenn es Status-Hosts gibt
			sp := m.statusPages(ctx)
			for i := range sp {
				pages[sp[i].ID] = &sp[i]
			}
			break
		}
	}
	out := make([]hostRow, 0, len(list))
	for _, h := range list {
		st := m.statsOf(h.ID)
		row := hostRow{Host: h, Reach: m.reach.get(h.ID), Requests: st.requests.Load(), Errors: st.errors.Load(), Blocked: st.blocked.Load(),
			URL: firstURL(h), Cert: m.certFor(ctx, h, all), RouteErr: routeErr[h.ID], Day: day[h.ID], ACLName: acls[h.AccessListID], Online: onl[h.ID]}
		row.LocalN = localCount(ldns, h.Names)
		if h.DockerContainer != "" {
			row.Docker, row.DockerRO = m.dockerHostLabel(h), m.dockerOn(ctx)
		}
		if h.probed() {
			row.Watch = watch.of(h.TargetHost, h.TargetPort)
		}
		if h.Kind == KindStatus {
			row.Status = pages[h.StatusPageID]
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
	d := listData{Kind: kind, Tabs: m.tabs(listPath(kind)), Rows: rows, EdgeErr: m.edgeError(), Pub: m.published(r.Context()), StatsOn: m.stats2.Load() != nil,
		OnlineOn: m.online.api != nil && m.edge != nil, OnlineL: m.onlineStrings(r), LimitsOn: m.limLoad(r.Context()).Enabled}
	if d.LocalOn = m.ldns() != nil; d.LocalOn {
		d.LocalV4, d.LocalV6 = m.localAddrs(r)
	}
	rm := m.online.remote.Load()
	if d.OnlineOn && (rm == nil || time.Since(rm.At) > time.Minute) { // auch ohne eigene Namen bald nachsehen (Modus 3)
		m.online.want.Store(true)
		m.onlineKick()
	}
	if rm != nil && rm.Data != nil && len(rm.Data.Hosts) > 0 && kind == KindProxy { // Kontingent nur unter den Proxy-Hosts
		d.Quota = newOnlineQuota(rm.Data.Quota, time.Now())
		if d.OnlineOn {
			d.Others = m.onlineOthers(r.Context())
		}
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
	m.g.Audit(r, "cdn64.check", "", "")
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
	Back    string        // Liste dieser Art
	NewCert bool          // "Zertifikat gleich mit anfordern" gewaehlt (nach einem Fehler im Formular)
	CertSrc string        // ... und der gewaehlte Weg (auto, ipv64, http, dns:<Zugang>, ca:<CA>, self)
	ACME    certs.Account // Let's-Encrypt-Konto (Nutzungsbedingungen angenommen?) fuer "Zertifikat gleich mit anfordern"
	Errors  map[string]string
	ACLs    []*AccessList
	DNS     []*certs.DNSAccount // Zugaenge fuer "Zertifikat gleich mit anfordern"
	CAs     []*certs.CA         // eigene CAs fuer "Zertifikat gleich mit anfordern"
	DNSKey  bool                // ipv64 DNS-01 moeglich (API-Key)
	IPv64   bool                // DNS-Eintrag bei ipv64 moeglich (API-Key)
	Zones   []string            // ipv64-Domains (Ziel fuer CNAME)
	Locs    []Location          // vorhandene Locations und zwei leere Zeilen
	Adv     advText
	CFNets  string

	GeoText   string       // Laender der Laendersperre (Komma)
	Countries []geoCountry // Auswahl aus index.json (leer, solange nicht geladen)

	StatusOn    bool             // Healthchecks verfuegbar (Hostart status)
	StatusPages []StatusPageInfo // Auswahl der Statusseite
	StatusKnown bool             // gewaehlte Seite gibt es auf dieser Node

	Docker    string // von Docker verwaltet: Container (Namen, Schema und Ziel gesperrt), "" = von Hand angelegt
	DockerRO  bool   // ... und Docker-Labels an: nicht loeschbar
	DockerACL string // Zugriffsliste aus den Labels (Auswahl gesperrt)
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
	d := formData{Tabs: m.tabs(listPath(h.Kind)), Back: listPath(h.Kind), Host: h, Names: strings.Join(h.Names, "\n"), New: isNew, Errors: map[string]string{}}
	if m.certs != nil {
		d.Certs, _ = m.certs.List(ctx)
		d.ACME = m.certs.Account(ctx)
	}
	d.ACLs, _ = m.accessLists(ctx)
	if m.certs != nil {
		d.DNS, _ = m.certs.DNSAccounts(ctx)
		d.CAs, _ = m.certs.CAs(ctx)
		d.DNSKey = m.certs.DNSReady(ctx)
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
	if h.DockerContainer != "" {
		d.Docker, d.DockerRO = m.dockerHostLabel(h), m.dockerOn(ctx)
		d.DockerACL = m.dockerACLFrom(ctx, h)
	}
	d.GeoText = strings.Join(a.GeoCountries, ", ")
	m.bl.mu.Lock()
	d.Countries = m.bl.countries
	m.bl.mu.Unlock()
	if h.Kind == KindStatus {
		d.StatusPages = m.statusPages(ctx)
		d.StatusOn = d.StatusPages != nil // nil = Healthchecks aus
		for _, p := range d.StatusPages {
			d.StatusKnown = d.StatusKnown || p.ID == h.StatusPageID
		}
	}
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
	h.StatusPageID, _ = strconv.ParseInt(r.PostFormValue("status_page_id"), 10, 64)
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
		a.NoBuffering, a.Gzip, a.AccessLog, a.NoLimits = on("adv_no_buffering"), on("adv_gzip"), on("adv_access_log"), on("adv_no_limits")
		a.TrustedProxies = lines(r.PostFormValue("adv_trusted"))
	}
	if r.PostFormValue("has_geo") == "1" { // Laendersperre war im Formular
		h.Advanced.GeoMode, h.Advanced.GeoCountries = r.PostFormValue("geo_mode"), lines(r.PostFormValue("geo_countries"))
	}
	if r.PostFormValue("has_ai") == "1" { // KI-Bots waren im Formular (Haken "Nutzer-Abrufe auch sperren" = nicht AllowUser)
		h.Advanced.AIBots, h.Advanced.AIBotsAllowUser, h.Advanced.AIRobots = on("ai_bots"), !on("ai_bots_user"), on("ai_robots")
	}
	if r.PostFormValue("has_maint") == "1" { // Reiter Wartung war im Formular
		h.Advanced.Maintenance, h.Advanced.MaintenanceStyle = on("maint_on"), r.PostFormValue("maint_style")
		h.Advanced.MaintenanceHTML = strings.ReplaceAll(r.PostFormValue("maint_html"), "\r\n", "\n")
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
	old := *h
	hostFromForm(r, h)
	if h.DockerContainer != "" { // Namen, Schema und Ziel kommen aus den Docker-Labels (Formularwerte zaehlen nicht)
		h.Names, h.Scheme, h.TargetHost, h.TargetPort, h.Kind = old.Names, old.Scheme, old.TargetHost, old.TargetPort, old.Kind
		if m.dockerACLFrom(r.Context(), &old) != "" { // Zugriffsliste kommt aus den Labels
			h.AccessListID = old.AccessListID
		}
	}
	m.saveForm(w, r, h, false)
}

func (m *Module) saveForm(w http.ResponseWriter, r *http.Request, h *Host, isNew bool) {
	ctx := r.Context()
	names := h.Names
	// Zertifikat gleich mit anfordern: ohne Let's-Encrypt-Konto (Nutzungsbedingungen) nicht - im Formular annehmen
	// (Haken) oder vorher unter Zertifikate; sonst bleibt der Host ungespeichert und das Formular zeigt den Hinweis
	// (eigene CA und selbst signiert brauchen kein Let's-Encrypt-Konto)
	src := r.PostFormValue("cert_source")
	acme := src != "self" && !strings.HasPrefix(src, "ca:")
	if r.PostFormValue("cert_id") == "new" && m.certs != nil && h.Kind != KindPass && acme {
		if acc := m.certs.Account(ctx); !acc.TOSAccepted {
			if r.PostFormValue("accept_tos") != "on" {
				d := m.form(ctx, h, isNew)
				d.Names, d.NewCert, d.CertSrc = strings.Join(names, "\n"), true, src
				d.Errors["cert_id"] = m.g.T(r, "certs.err.tos")
				title := "cdn64.edit"
				if isNew {
					title = "cdn64.new"
				}
				m.g.Render(w, r, http.StatusUnprocessableEntity, Name+"/host_form", title, d)
				return
			}
			if err := m.certs.SetAccount(ctx, acc.Email, true); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			m.g.Audit(r, "cert.account", "", "accept_tos=true")
		}
	}
	if err := m.saveHost(ctx, h); err != nil {
		d := m.form(ctx, h, isNew)
		d.Names = strings.Join(names, "\n")
		d.NewCert, d.CertSrc = r.PostFormValue("cert_id") == "new", src
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
		dnsAcc := int64(0)
		if v, ok := strings.CutPrefix(src, "dns:"); ok { // "dns:<Zugang>"
			src = "dns"
			dnsAcc, _ = strconv.ParseInt(v, 10, 64)
		}
		var c *certs.Cert
		var err error
		switch {
		case src == "self": // selbst signiert, wie unter Zertifikate (ECDSA, Standardlaufzeit)
			c, err = m.certs.Create(ctx, certs.Request{Names: h.Names, Source: "self"})
		case strings.HasPrefix(src, "ca:"): // "ca:<CA>": eigene CA
			caID, _ := strconv.ParseInt(strings.TrimPrefix(src, "ca:"), 10, 64)
			c, err = m.certs.Create(ctx, certs.Request{Names: h.Names, Source: "ca", CAID: caID})
		default:
			c, err = m.requestCert(ctx, h.Names, src, "", "", dnsAcc, false)
		}
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
	if h.DockerContainer != "" && m.dockerOn(r.Context()) { // geloescht wird mit dem Label bzw. Container (docker.go)
		m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.docker.err.delete"))
		http.Redirect(w, r, listPath(h.Kind), http.StatusSeeOther)
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

// POST /cdn64/hosts/{id}/maintenance: Wartungsmodus des Hosts ein- bzw. ausschalten (Liste).
func (m *Module) pageMaint(w http.ResponseWriter, r *http.Request) {
	h, ok := m.hostFromPath(w, r)
	if !ok {
		return
	}
	if h.Kind != KindProxy {
		http.Error(w, "maintenance mode only for proxy hosts", http.StatusBadRequest)
		return
	}
	h.Advanced.Maintenance = !h.Advanced.Maintenance
	if err := m.saveHost(r.Context(), h); err != nil {
		var fe *FieldError
		if errors.As(err, &fe) {
			m.g.Flash(w, r, "danger", m.g.T(r, fe.Key))
		} else {
			m.g.Flash(w, r, "danger", err.Error())
		}
		http.Redirect(w, r, listPath(h.Kind), http.StatusSeeOther)
		return
	}
	state := "off"
	if h.Advanced.Maintenance {
		state = "on"
	}
	m.g.Audit(r, "cdn64.host.maintenance", strings.Join(h.Names, ","), state)
	m.g.Flash(w, r, "success", m.g.T(r, "cdn64.maint.flash_"+state, "name", h.Names[0]))
	http.Redirect(w, r, listPath(h.Kind), http.StatusSeeOther)
}

// GET /cdn64/hosts/{id}/maintenance/preview?style=: Wartungsseite ansehen (Stil aus der Abfrage, sonst der des Hosts).
// Eigenes HTML laeuft in einer Sandbox (eigener Ursprung): Skripte darin kommen nicht an die Oberflaeche von Node64.
func (m *Module) pageMaintPreview(w http.ResponseWriter, r *http.Request) {
	h, ok := m.hostFromPath(w, r)
	if !ok {
		return
	}
	style := r.URL.Query().Get("style")
	if style != MaintMatrix && style != MaintGear && style != MaintCustom {
		style = h.Advanced.MaintenanceStyle
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "sandbox allow-scripts")
	_, _ = w.Write([]byte(maintPage(style, h.Advanced.MaintenanceHTML, h.Names[0])))
}

func itoa(n int) string { return strconv.Itoa(n) }
