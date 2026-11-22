package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/netstat"
	"github.com/ipv64net/node64/internal/ports"
)

// Einstellungen in fuenf Seiten: Allgemein (/settings), Mein Konto (/settings/account, jeder Benutzer), Module
// (/settings/modules), Ports (/settings/ports) und Daten & Sicherung (/settings/data). Die Formulare posten wie bisher an /settings/…; hier nur die Seiten und die
// Port-Tabelle.

func (s *Server) settingsPageRoutes() {
	s.mux.Handle("GET /settings/account", s.auth(s.settingsAccountPage))
	s.mux.Handle("GET /settings/modules", s.auth(s.settingsModulesPage))
	s.mux.Handle("GET /settings/ports", s.auth(s.settingsPortsPage))
	s.mux.Handle("GET /settings/data", s.auth(s.settingsDataPage))
	s.mux.Handle("POST /settings/reach", s.auth(s.settingsReach))
}

// settingsMoved: alte Sprungmarken auf /settings und ihr neuer Ort (app.js leitet weiter; der Server sieht #… nicht).
var settingsMoved = map[string]string{
	"modules": "/settings/modules",
	"ports":   "/settings/ports",
	"edge":    "/settings/ports#edge",
	"data":    "/settings/data#retention",
	"backup":  "/settings/data#backup",
	"restore": "/settings/data#restore",
	"export":  "/settings/data#export",
	"import":  "/settings/data#import",
	"reset":   "/settings/data#reset",
	// Einstellungen des Benutzers (eigene Seite Mein Konto)
	"user":       accountPath + "#user",
	"appearance": accountPath + "#appearance",
	"twofa":      accountPath + "#twofa",
	"passkeys":   accountPath + "#passkeys",
	"identities": accountPath + "#identities",
}

// accountPath: Einstellungen des angemeldeten Benutzers (Sprache, Zeitzone, Passwort, Darstellung, 2FA, Passkeys, SSO).
const accountPath = "/settings/account"

// ---------------------------------------------------------------- Mein Konto

// settingsAccountPage: Einstellungen des angemeldeten Benutzers - fuer jeden Benutzer, auch "Nur lesen".
func (s *Server) settingsAccountPage(w http.ResponseWriter, r *http.Request) {
	v := s.settingsView(r)
	v.Title = v.T("nav.settings_account")
	s.render(w, r, http.StatusOK, "settings_account", v)
}

// ---------------------------------------------------------------- Module

// settingsModulesPage: alle Module mit Kurzbeschreibung, zwei Highlights und Schalter (POST /settings/modules).
func (s *Server) settingsModulesPage(w http.ResponseWriter, r *http.Request) {
	v := s.settingsView(r)
	v.Title = v.T("nav.settings_modules")
	s.render(w, r, http.StatusOK, "settings_modules", v)
}

// ---------------------------------------------------------------- Daten & Sicherung

func (s *Server) settingsDataPage(w http.ResponseWriter, r *http.Request) {
	v := s.settingsView(r)
	v.Title = v.T("settings.data_page")
	s.render(w, r, http.StatusOK, "settings_data", v)
}

// ---------------------------------------------------------------- Erreichbarkeit (Allgemein)

// reachView: wie die Oberflaeche erreichbar ist (Karte Erreichbarkeit dieser Node).
type reachView struct {
	HTTPPort, HTTPSPort       int
	EnvHTTPPort, EnvHTTPSPort int    // Standard aus der Umgebung
	Bridge                    bool   // Docker-Bridge-Netz: Hinweis auf -p
	Cluster                   bool   // in einem Cluster: die anderen Nodes kennen die alte Adresse
	Ignored                   string // eingestellte Ports, die sich beim Start nicht oeffnen liessen ("" = keine)
	Bind                      string
	URLs                      []string // Adressen dieser Node mit Web-Port
	EdgeOn                    bool     // Name am Eingang moeglich
	EdgeHTTP, EdgeHTTPS       int      // Ports des Eingangs
	UIName                    string
	UIPublic                  bool
	UICert                    uiCertView
	HTTPSRedirect             bool // Seitenaufrufe per HTTP auf HTTPS umleiten
}

func (s *Server) reachData(ctx context.Context) *reachView {
	rv := &reachView{HTTPPort: s.Cfg.HTTPPort, HTTPSPort: s.Cfg.HTTPSPort, Bind: s.Cfg.BindAddr, EdgeOn: s.Edge != nil, Bridge: bridgeNet(),
		UIName: s.Store.SettingOr(ctx, setUIName, ""), UIPublic: s.Store.SettingOr(ctx, setUIPublic, "0") == "1", UICert: s.uiCertData(ctx)}
	rv.EnvHTTPPort, rv.EnvHTTPSPort = s.envPorts()
	rv.HTTPSRedirect = s.httpsRedirect.Load()
	if h, hs, set := WebPorts(ctx, s.Store, rv.EnvHTTPPort, rv.EnvHTTPSPort); set && (h != s.Cfg.HTTPPort || hs != s.Cfg.HTTPSPort) {
		rv.Ignored = strconv.Itoa(h) + "/" + strconv.Itoa(hs)
	}
	if s.Peer != nil {
		if list, err := s.Peer.Members(ctx); err == nil && len(list) > 0 {
			rv.Cluster = true
		}
	}
	if s.Edge != nil {
		ec := s.Edge.Config()
		rv.EdgeHTTP, rv.EdgeHTTPS = ec.HTTPPort, ec.HTTPSPort
	}
	rv.URLs = localURLs(s.Cfg.BindAddr, s.Cfg.HTTPPort, s.Cfg.HTTPSPort)
	return rv
}

// localURLs: Adressen der Schnittstellen (ohne Loopback und Link-local) mit Web-Port, hoechstens acht.
func localURLs(bind string, httpPort, httpsPort int) []string {
	var ips []netip.Addr
	if b, err := netip.ParseAddr(strings.Trim(bind, "[]")); err == nil && !b.IsUnspecified() {
		ips = append(ips, b)
	} else if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := p.Addr().Unmap()
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
				continue
			}
			ips = append(ips, ip)
		}
	}
	sort.SliceStable(ips, func(i, j int) bool { return ips[i].Is4() && !ips[j].Is4() }) // IPv4 zuerst
	var out []string
	for _, ip := range ips {
		if httpsPort > 0 {
			out = append(out, "https://"+net.JoinHostPort(ip.String(), strconv.Itoa(httpsPort)))
		} else if httpPort > 0 {
			out = append(out, "http://"+net.JoinHostPort(ip.String(), strconv.Itoa(httpPort)))
		}
		if len(out) == 8 {
			break
		}
	}
	return out
}

// settingsReach speichert Ports, Name und Zertifikat der Oberflaeche (Karte Erreichbarkeit). Aendern sich die Ports,
// startet Node64 neu und der Browser wechselt auf den neuen Port.
func (s *Server) settingsReach(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	v := s.view(r, "settings.title")
	changed, httpPort, httpsPort, perr := s.saveWebPorts(r)
	if perr != nil {
		s.flash(w, r, "danger", s.webPortsError(v, perr))
		http.Redirect(w, r, "/settings#reach", http.StatusSeeOther)
		return
	}
	err := s.saveUICertForm(r)
	if err == nil {
		err = s.saveUIRouteForm(r)
	}
	if err == nil {
		err = s.saveHTTPSRedirect(r)
	}
	if err != nil {
		s.flash(w, r, "danger", v.T("ports.err_save", "error", err.Error()))
	} else if !changed {
		s.flash(w, r, "success", v.T("common.saved"))
	}
	if changed {
		s.audit(r, "settings.web_ports", "", fmt.Sprintf("http=%d https=%d (before http=%d https=%d)", httpPort, httpsPort, s.Cfg.HTTPPort, s.Cfg.HTTPSPort))
		s.renderPortSwitch(w, r, portSwitchURL(r, s.Cfg.HTTPPort, s.Cfg.HTTPSPort, httpPort, httpsPort))
		s.restartInPlace("web ports changed, restarting")
		return
	}
	http.Redirect(w, r, "/settings#reach", http.StatusSeeOther)
}

// ---------------------------------------------------------------- Ports

// listenerSource liefert die lauschenden Sockets (Tests: feste Liste).
var listenerSource = netstat.Listeners

// privilegeSource liefert die Rechte fuer Ports unter 1024 (Tests: fest).
var privilegeSource = netstat.ReadPrivileges

// portRow ist eine Zeile der Port-Tabelle.
type portRow struct {
	ports.Claim
	Kind      string   // listen (Node64 oeffnet ihn), via (laeuft ueber den Port eines anderen Teils), out (ausgehend)
	Via       string   // bei via: Teil, dem der Port gehoert (edge, web)
	Open      string   // yes, no, unknown; leer bei via/out
	Published string   // Docker-Bridge-Netz, Eingang: yes/no = auf dem Docker-Host veroeffentlicht, unknown = nicht pruefbar; sonst leer
	Foreign   bool     // offen, aber kein Teil von Node64 hat ihn offen (anderes Programm im selben Netz)
	Conflicts []string // "dns64 (DoH)" …
	Low       bool     // Port unter 1024
	LowDenied bool     // … und der Prozess darf ihn nicht oeffnen
	Names     []string // via edge: Namen am Eingang
	Mod       portModule
}

type portModule struct {
	Owner, TitleKey, Icon, Image string
}

// portsPage sind die Daten der Seite Ports.
type portsPage struct {
	Rows                           []portRow
	Owners                         []portModule // fuer den Filter
	Module, State                  string       // Filter
	StateOptions                   []string
	Total, Open, Conflicts, Errors int
	Checked                        bool // offene Ports pruefbar (Linux)
	Priv                           netstat.Privileges
	LowPorts                       []int  // eingestellte Ports unter 1024
	LowDenied                      bool   // mindestens einer davon nicht erlaubt
	DockerArgs                     string // -p … fuer docker run
	WebPort, HTTPPort, HTTPSPort   int
	Edge                           *edge.Status   // Formular des Eingangs (nil = nicht verfuegbar; Name der Oberflaeche: reachView)
	Pub                            edge.Published // Docker-Bridge-Netz: HTTP/HTTPS des Eingangs auf dem Host veroeffentlicht?
}

var portStates = []string{"open", "closed", "conflict", "error", "foreign", "via", "out"}

func (s *Server) settingsPortsPage(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "settings.ports_page")
	q := r.URL.Query()
	d := s.portsPageData(r.Context(), q.Get("module"), q.Get("state"))
	v.Data = d
	s.render(w, r, http.StatusOK, "settings_ports", v)
}

// ownerMeta: Titel und Symbol je Teil (Module aus der Registry, Kern fest).
func (s *Server) ownerMeta(ctx context.Context) map[string]portModule {
	out := map[string]portModule{
		"web":     {Owner: "web", TitleKey: "ports.owner_web", Icon: "bi-window"},
		"edge":    {Owner: "edge", TitleKey: "ports.owner_edge", Icon: "bi-signpost-split"},
		"peer":    {Owner: "peer", TitleKey: "nav.cluster", Icon: "bi-hdd-network"},
		"mcp":     {Owner: "mcp", TitleKey: "mcp.title", Icon: "bi-robot"},
		"metrics": {Owner: "metrics", TitleKey: "ports.owner_metrics", Icon: "bi-graph-up"},
	}
	for _, m := range s.Modules.List(ctx) {
		out[m.Info.Name] = portModule{Owner: m.Info.Name, TitleKey: m.Info.TitleKey, Icon: m.Info.Icon, Image: m.Info.Image}
	}
	return out
}

func (s *Server) portsPageData(ctx context.Context, module, state string) *portsPage {
	d := &portsPage{Module: module, State: state, StateOptions: portStates, HTTPPort: s.Cfg.HTTPPort, HTTPSPort: s.Cfg.HTTPSPort,
		Priv: privilegeSource()}
	if s.Ports != nil && s.Edge != nil { // wie portRoutes (POST /settings/edge)
		st := s.Edge.Status()
		d.Edge = &st
	}
	if s.Edge != nil {
		d.Pub = s.Edge.Published(ctx)
	}
	meta := s.ownerMeta(ctx)
	webPort := s.Cfg.HTTPPort
	if webPort == 0 {
		webPort = s.Cfg.HTTPSPort
	}
	d.WebPort = webPort
	var rows []portRow
	if s.Ports != nil {
		for _, e := range s.Ports.Overview(ctx) {
			rows = append(rows, portRow{Claim: e.Claim, Kind: "listen", Conflicts: e.Conflicts})
		}
	} else { // ohne Port-Verwaltung (Tests, Modus ohne Eingang): zumindest die Oberflaeche
		if s.Cfg.HTTPPort > 0 {
			rows = append(rows, portRow{Claim: ports.Claim{Owner: "web", Purpose: "HTTP", Proto: ports.TCP, Port: s.Cfg.HTTPPort, Bind: s.Cfg.BindAddr, Active: true}, Kind: "listen"})
		}
		if s.Cfg.HTTPSPort > 0 {
			rows = append(rows, portRow{Claim: ports.Claim{Owner: "web", Purpose: "HTTPS", Proto: ports.TCP, Port: s.Cfg.HTTPSPort, Bind: s.Cfg.BindAddr, Active: true}, Kind: "listen"})
		}
	}
	// ueber den Web-Port: Cluster (HTTPS), MCP, Prometheus/API
	if s.Peer != nil {
		p := s.Cfg.HTTPSPort
		if p == 0 {
			p = s.Cfg.HTTPPort
		}
		rows = append(rows, portRow{Claim: ports.Claim{Owner: "peer", Purpose: "Cluster (HTTPS)", Proto: ports.TCP, Port: p, Bind: s.Cfg.BindAddr, Active: true}, Kind: "via", Via: "web"})
	}
	if s.mcpEnabled(ctx) {
		rows = append(rows, portRow{Claim: ports.Claim{Owner: "mcp", Purpose: "MCP /mcp", Proto: ports.TCP, Port: webPort, Bind: s.Cfg.BindAddr, Active: true}, Kind: "via", Via: "web"})
	}
	rows = append(rows, portRow{Claim: ports.Claim{Owner: "metrics", Purpose: "Prometheus /api/metrics", Proto: ports.TCP, Port: webPort, Bind: s.Cfg.BindAddr, Active: true}, Kind: "via", Via: "web"})
	// ueber den Eingang (PROXY64): Namen je Abnehmer (Proxy-Hosts, DoH, Oberflaeche, Honeypot-Koeder …)
	if s.Edge != nil {
		st := s.Edge.Status()
		running := false
		for _, l := range st.Listeners {
			if l.Name == "https" {
				running = l.Running
			}
		}
		byOwner := map[string][]string{}
		var order []string
		for _, n := range st.Names {
			if _, ok := byOwner[n.Owner]; !ok {
				order = append(order, n.Owner)
			}
			byOwner[n.Owner] = append(byOwner[n.Owner], n.Name+n.Path)
		}
		for _, o := range order {
			rows = append(rows, portRow{Claim: ports.Claim{Owner: o, Purpose: "HTTPS", Proto: ports.TCP, Port: st.Config.HTTPSPort, Bind: st.Config.Bind, Active: running},
				Kind: "via", Via: "edge", Names: byOwner[o]})
		}
	}
	if s.Ports != nil {
		for _, c := range s.Ports.Outbound(ctx) {
			rows = append(rows, portRow{Claim: c, Kind: "out"})
		}
	}

	// wirklich offen? (Netz-Namensraum dieses Prozesses)
	listeners, checked := listenerSource()
	d.Checked = checked
	low := map[int]bool{}
	docker := map[string]bool{}
	for i := range rows {
		row := &rows[i]
		row.Mod = meta[row.Owner]
		if row.Mod.Owner == "" {
			row.Mod = portModule{Owner: row.Owner, TitleKey: "ports.owner_" + row.Owner, Icon: "bi-box"}
		}
		if row.Kind != "listen" {
			continue
		}
		row.Open = "unknown"
		if checked {
			row.Open = "no"
			for _, l := range listeners {
				if l.Covers(string(row.Proto), row.Bind, row.Port) {
					row.Open = "yes"
					break
				}
			}
		}
		if d.Pub.Bridge && row.Owner == edge.Owner && row.Proto == ports.TCP && row.Active {
			row.Published = d.Pub.PortState(row.Port) // yes, no, unknown (Gateway ohne Hairpin, #243) oder leer
		}
		if row.Port > 0 && row.Port < 1024 {
			row.Low, row.LowDenied = true, d.Priv.Known && !d.Priv.LowPortOK(row.Port)
			low[row.Port] = true
			d.LowDenied = d.LowDenied || row.LowDenied
		}
		if b, err := netip.ParseAddr(strings.Trim(row.Bind, "[]")); err != nil || !b.IsLoopback() {
			arg := strconv.Itoa(row.Port) + ":" + strconv.Itoa(row.Port)
			if row.Proto == ports.UDP {
				arg += "/udp"
			}
			docker[arg] = true
		}
	}
	for i := range rows { // offen, aber von keinem Teil: anderes Programm (oder ein Teil, der ihn nicht meldet)
		row := &rows[i]
		if row.Kind != "listen" || row.Open != "yes" || row.Active {
			continue
		}
		row.Foreign = true
		for j, o := range rows {
			if j != i && o.Kind == "listen" && o.Active && ports.Overlap(row.Claim, o.Claim) {
				row.Foreign = false
			}
		}
	}
	for p := range low {
		d.LowPorts = append(d.LowPorts, p)
	}
	sort.Ints(d.LowPorts)
	args := make([]string, 0, len(docker))
	for a := range docker {
		args = append(args, a)
	}
	sort.Slice(args, func(i, j int) bool {
		pi, _ := strconv.Atoi(strings.Split(args[i], ":")[0])
		pj, _ := strconv.Atoi(strings.Split(args[j], ":")[0])
		if pi != pj {
			return pi < pj
		}
		return args[i] < args[j]
	})
	for _, a := range args {
		d.DockerArgs += " -p " + a
	}
	d.DockerArgs = strings.TrimSpace(d.DockerArgs)

	// Filter und Zaehler
	seen := map[string]bool{}
	for _, row := range rows {
		if !seen[row.Owner] {
			seen[row.Owner] = true
			d.Owners = append(d.Owners, row.Mod)
		}
		if row.Kind == "listen" {
			d.Total++
			if row.Open == "yes" || (row.Open == "unknown" && row.Active) {
				d.Open++
			}
		}
		if len(row.Conflicts) > 0 {
			d.Conflicts++
		}
		if row.Error != "" {
			d.Errors++
		}
		if (module == "" || row.Owner == module) && rowMatches(row, state) {
			d.Rows = append(d.Rows, row)
		}
	}
	return d
}

// rowMatches: Zeile passt zum Filter Zustand ("" = alle).
func rowMatches(row portRow, state string) bool {
	switch state {
	case "open":
		return row.Kind == "listen" && (row.Open == "yes" || (row.Open == "unknown" && row.Active))
	case "closed":
		return row.Kind == "listen" && (row.Open == "no" || (row.Open == "unknown" && !row.Active))
	case "conflict":
		return len(row.Conflicts) > 0
	case "error":
		return row.Error != "" || row.LowDenied
	case "foreign":
		return row.Foreign
	case "via", "out":
		return row.Kind == state
	}
	return true
}
