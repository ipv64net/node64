package cdn64

import (
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/ipv64net/node64/internal/edge"
)

// Erweitert: feste Felder statt freier nginx-Konfiguration.

// Header ist eine Kopfzeile zum Setzen.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Advanced sind die weiteren Optionen eines Hosts.
type Advanced struct {
	RequestHeaders  []Header `json:"request_headers,omitempty"`  // an das Ziel setzen
	RequestRemove   []string `json:"request_remove,omitempty"`   // vor dem Ziel entfernen
	ResponseHeaders []Header `json:"response_headers,omitempty"` // an den Besucher setzen
	ResponseRemove  []string `json:"response_remove,omitempty"`  // vor dem Besucher entfernen
	HostHeader      string   `json:"host_header,omitempty"`      // "" = Name des Besuchers, "target" = Ziel, sonst fester Wert
	TimeoutSeconds  int      `json:"timeout_seconds,omitempty"`  // bis zur Antwort des Ziels, 0 = ohne
	MaxBodyMB       int      `json:"max_body_mb,omitempty"`      // hoechstens so viel hochladen, 0 = unbegrenzt
	NoBuffering     bool     `json:"no_buffering,omitempty"`     // sofort weiterreichen (Streaming, SSE)
	Gzip            bool     `json:"gzip,omitempty"`             // Antworten komprimieren (zstd, Brotli, gzip; Name aus der ersten Fassung)
	TrustedProxies  []string `json:"trusted_proxies,omitempty"`  // echte Client-IP aus diesen Proxys (z. B. Cloudflare)
	AccessLog       bool     `json:"access_log,omitempty"`       // jede Anfrage protokollieren
	NoLimits        bool     `json:"no_limits,omitempty"`        // ohne Anfrage-Limit je IP und ohne Platzgrenze beim Ziel
	BWDownMbit      int      `json:"bw_down_mbit,omitempty"`     // Bandbreite zum Besucher (Download) in Mbit/s, 0 = unbegrenzt (bandwidth.go)
	BWUpMbit        int      `json:"bw_up_mbit,omitempty"`       // Bandbreite vom Besucher (Upload) in Mbit/s, 0 = unbegrenzt
	trusted         []netip.Prefix

	// Laendersperre (geo.go): "" = aus, block = diese Laender sperren, allow = nur diese Laender zulassen
	GeoMode      string   `json:"geo_mode,omitempty"`
	GeoCountries []string `json:"geo_countries,omitempty"` // ISO-Laendercodes, z. B. DE

	// KI-Bots (aibots.go): User-Agent aus der Liste von ipv64.net abweisen (403); AllowUser = Nutzer-Abrufe (ChatGPT-User
	// u. a.) durchlassen; AIRobots = /robots.txt mit KI-Sperre ausliefern, wenn das Ziel keine hat
	AIBots          bool `json:"ai_bots,omitempty"`
	AIBotsAllowUser bool `json:"ai_bots_allow_user,omitempty"`
	AIRobots        bool `json:"ai_robots,omitempty"`

	// Wartungsmodus (maintenance.go, nur Proxy-Hosts): Wartungsseite (503) statt Ziel
	Maintenance      bool   `json:"maintenance,omitempty"`
	MaintenanceStyle string `json:"maintenance_style,omitempty"` // matrix (Standard), gear oder custom
	MaintenanceHTML  string `json:"maintenance_html,omitempty"`  // eigenes HTML (custom), hoechstens 64 KB

	// Eigene Fehlerseite (maintenance.go, nur Proxy-Hosts): statt der neutralen Seite bei 502/503/504 von PROXY64
	// selbst (Ziel nicht erreichbar, ueberlastet); ErrorOverride ersetzt auch 5xx-Antworten des Ziels (Status bleibt)
	ErrorHTML     string `json:"error_html,omitempty"` // hoechstens 64 KB, {{STATUS}} und {{HOST}} werden ersetzt
	ErrorOverride bool   `json:"error_override,omitempty"`

	// Ziel des Hosts (nur Proxy-Hosts): Pfad, der vor jede Anfrage gesetzt wird (/suppe -> /rezepte/suppe, #43);
	// "" = unveraendert. OnlyLocations: nur die Locations beantworten, alle anderen Pfade 404 (#11)
	TargetPath    string `json:"target_path,omitempty"`
	OnlyLocations bool   `json:"only_locations,omitempty"`

	// Protokoll zum Ziel (#53, nur Proxy-Hosts): "" = automatisch, h1 = nur HTTP/1.1, h2c = HTTP/2 ohne Aushandeln
	TargetHTTP string `json:"target_http,omitempty"`

	// PROXY-Protokoll zum Ziel (#52, nur TLS durchreichen): "" = aus, v1, v2 (proxyVersion)
	ProxyProtocol string `json:"proxy_protocol,omitempty"`

	// NoProbe: Ziel nicht auf Erreichbarkeit pruefen (z. B. Dienst ohne Weboberflaeche; Forum 5100)
	NoProbe bool `json:"no_probe,omitempty"`
}

// PROXY-Protokoll zum Ziel (Advanced.ProxyProtocol bei TLS durchreichen, Stream.ProxyProtocol bei TCP-Streams): der
// Kopf mit der echten Besucher-Adresse geht vor allen Daten an das Ziel (edge.ProxyHeader). Nur auf Wunsch - ein
// Ziel, das keinen Kopf erwartet, versteht die Verbindung sonst nicht.
const (
	ProxyOff = ""
	ProxyV1  = "v1"
	ProxyV2  = "v2"
)

// cleanProxyProtocol: Wert in Grundform; false = unbekannt.
func cleanProxyProtocol(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case ProxyOff, ProxyV1, ProxyV2:
		return s, true
	}
	return s, false
}

// proxyVersion: Version fuer edge.ProxyHeader (0 = kein Kopf).
func proxyVersion(s string) int {
	switch s {
	case ProxyV1:
		return edge.ProxyV1
	case ProxyV2:
		return edge.ProxyV2
	}
	return 0
}

// Protokoll zum Ziel (Advanced.TargetHTTP, LocationAdvanced.TargetHTTP).
const (
	TargetHTTPAuto = ""     // https-Ziel: HTTP/2 per ALPN, wenn das Ziel es anbietet, sonst HTTP/1.1; http-Ziel: HTTP/1.1
	TargetHTTP1    = "h1"   // nur HTTP/1.1 (NTLM/Kerberos bei Exchange/IIS, Sonderfaelle)
	TargetH2C      = "h2c"  // http-Ziel: HTTP/2 mit Vorwissen (gRPC ohne TLS), https-Ziel: nur HTTP/2
	targetHTTPLoc  = "auto" // nur bei Locations: ausdruecklich automatisch ("" = wie der Host)
)

// cleanTargetHTTP: Protokoll zum Ziel in Grundform; false = unbekannt. loc: Location ("auto" bleibt, "" = wie Host).
func cleanTargetHTTP(s string, loc bool) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case TargetHTTPAuto, TargetHTTP1, TargetH2C:
		return s, true
	case targetHTTPLoc:
		if loc {
			return s, true
		}
		return TargetHTTPAuto, true
	}
	return s, false
}

// Location ist ein Pfad mit eigenem Ziel (Custom Location), gesperrt oder mit fester Antwort.
type Location struct {
	Path         string `json:"path"`         // Praefix, z. B. /api
	Scheme       string `json:"scheme"`       // http | https
	TargetHost   string `json:"target_host"`  // Name oder IP
	TargetPort   int    `json:"target_port"`  // Port
	ForwardPath  string `json:"forward_path"` // ersetzt den Praefix beim Ziel ("" = unveraendert)
	WebSockets   bool   `json:"websockets"`
	AccessListID int64  `json:"access_list_id"` // 0 = wie der Host

	// Bei verweigertem Zugriff (#55): Weiterleitung (302) statt Fehlerseite, wenn die Zugriffsliste ablehnt (403);
	// nicht, wenn eine Anmeldung helfen koennte (401, Login-Seite). Relativer Pfad oder http(s)-URL, "" = Fehlerseite.
	DeniedRedirect string `json:"denied_redirect,omitempty"`

	// Aktion (#11): "" = an das Ziel, block = sperren (Status 400-499, Standard 403), respond = feste Antwort (Status
	// 200-599, Standard 200, Inhalt hoechstens 64 KB) - beide ohne Ziel
	Action      string `json:"action,omitempty"`
	Status      int    `json:"status,omitempty"`
	Body        string `json:"body,omitempty"`
	ContentType string `json:"content_type,omitempty"` // Standard text/plain; charset=utf-8

	Advanced *LocationAdvanced `json:"advanced,omitempty"` // eigene Werte; nil = wie der Host
}

// Aktionen einer Location.
const (
	LocProxy   = ""
	LocBlock   = "block"
	LocRespond = "respond"
)

// maxLocBody: hoechstens so gross ist die feste Antwort einer Location.
const maxLocBody = 64 << 10

// LocationAdvanced: "Erweitert" je Location (Forum 4974). Nicht gesetzte Werte kommen vom Host; die Kopfzeilen gelten
// zusaetzlich zu denen des Hosts (gleicher Name: die der Location).
type LocationAdvanced struct {
	TimeoutSeconds  int      `json:"timeout_seconds,omitempty"` // bis zur Antwort des Ziels, 0 = wie der Host
	MaxBodyMB       int      `json:"max_body_mb,omitempty"`     // 0 = wie der Host, -1 = unbegrenzt
	Buffering       string   `json:"buffering,omitempty"`       // "" = wie der Host, on = puffern, off = sofort weiterreichen
	RequestHeaders  []Header `json:"request_headers,omitempty"`
	RequestRemove   []string `json:"request_remove,omitempty"`
	ResponseHeaders []Header `json:"response_headers,omitempty"`
	ResponseRemove  []string `json:"response_remove,omitempty"`
	TargetHTTP      string   `json:"target_http,omitempty"` // "" = wie der Host, auto, h1 oder h2c (Advanced.TargetHTTP)
}

// empty: nichts Eigenes gesetzt.
func (a *LocationAdvanced) empty() bool {
	return a == nil || a.TimeoutSeconds == 0 && a.MaxBodyMB == 0 && a.Buffering == "" && len(a.RequestHeaders) == 0 && len(a.RequestRemove) == 0 &&
		len(a.ResponseHeaders) == 0 && len(a.ResponseRemove) == 0 && a.TargetHTTP == ""
}

// targetHTTP: Protokoll zum Ziel dieser Location (host = das des Hosts).
func (a *LocationAdvanced) targetHTTP(host string) string {
	switch {
	case a == nil || a.TargetHTTP == "":
		return host
	case a.TargetHTTP == targetHTTPLoc:
		return TargetHTTPAuto
	}
	return a.TargetHTTP
}

// normalize prueft die Werte einer Location (Kopfzeilen wie beim Host).
func (a *LocationAdvanced) normalize(path string) error {
	if a.TimeoutSeconds < 0 || a.TimeoutSeconds > 86400 || a.MaxBodyMB < -1 || a.MaxBodyMB > 1<<20 ||
		a.Buffering != "" && a.Buffering != "on" && a.Buffering != "off" {
		return &FieldError{Field: "locations", Key: "cdn64.err.location_limits", Name: path}
	}
	th, ok := cleanTargetHTTP(a.TargetHTTP, true)
	if !ok {
		return &FieldError{Field: "locations", Key: "cdn64.err.target_http", Name: path + ": " + a.TargetHTTP}
	}
	a.TargetHTTP = th
	tmp := Advanced{RequestHeaders: a.RequestHeaders, RequestRemove: a.RequestRemove, ResponseHeaders: a.ResponseHeaders, ResponseRemove: a.ResponseRemove}
	if err := tmp.normalize(); err != nil {
		var fe *FieldError
		if errors.As(err, &fe) {
			return &FieldError{Field: "locations", Key: fe.Key, Name: fe.Name}
		}
		return err
	}
	a.RequestHeaders, a.RequestRemove, a.ResponseHeaders, a.ResponseRemove = tmp.RequestHeaders, tmp.RequestRemove, tmp.ResponseHeaders, tmp.ResponseRemove
	return nil
}

// effective: Optionen des Hosts mit den eigenen Werten der Location (fuer den Proxy dieser Location).
func (l *Location) effective(host *Advanced) Advanced {
	a := *host
	la := l.Advanced
	if la.empty() {
		return a
	}
	if la.TimeoutSeconds > 0 {
		a.TimeoutSeconds = la.TimeoutSeconds
	}
	switch {
	case la.MaxBodyMB < 0:
		a.MaxBodyMB = 0
	case la.MaxBodyMB > 0:
		a.MaxBodyMB = la.MaxBodyMB
	}
	a.TargetHTTP = la.targetHTTP(host.TargetHTTP)
	switch la.Buffering {
	case "on":
		a.NoBuffering = false
	case "off":
		a.NoBuffering = true
	}
	// was die Location entfernt, setzt auch der Host hier nicht (Entfernen laeuft vor dem Setzen)
	a.RequestHeaders = mergeHeaders(dropHeaders(host.RequestHeaders, la.RequestRemove), la.RequestHeaders)
	a.ResponseHeaders = mergeHeaders(dropHeaders(host.ResponseHeaders, la.ResponseRemove), la.ResponseHeaders)
	a.RequestRemove = append(append([]string{}, host.RequestRemove...), la.RequestRemove...)
	a.ResponseRemove = append(append([]string{}, host.ResponseRemove...), la.ResponseRemove...)
	return a
}

// dropHeaders: Kopfzeilen ohne die genannten (Gross-/Kleinschreibung egal); die Liste des Hosts bleibt unveraendert.
func dropHeaders(hs []Header, names []string) []Header {
	if len(names) == 0 {
		return hs
	}
	out := make([]Header, 0, len(hs))
	for _, h := range hs {
		if !slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, h.Name) }) {
			out = append(out, h)
		}
	}
	return out
}

// mergeHeaders: Kopfzeilen des Hosts, gleichnamige durch die der Location ersetzt.
func mergeHeaders(host, own []Header) []Header {
	if len(own) == 0 {
		return host
	}
	out := make([]Header, 0, len(host)+len(own))
	for _, h := range host {
		dup := false
		for _, o := range own {
			if strings.EqualFold(h.Name, o.Name) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, h)
		}
	}
	return append(out, own...)
}

// cleanTargetPath: Pfad beim Ziel ("" = keiner), mit fuehrendem und ohne abschliessenden Schraegstrich; false =
// ungueltig (Leerzeichen, ? oder #, Backslash, Punkt-Segmente, zu lang).
func cleanTargetPath(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", true
	}
	s = "/" + strings.Trim(s, "/")
	if s == "/" {
		return "", true
	}
	if strings.ContainsAny(s, " ?#\\") || len(s) > 200 {
		return "", false
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "." || seg == ".." {
			return "", false
		}
	}
	return s, true
}

// Cloudflare-Netze (Stand 2026, https://www.cloudflare.com/ips/) als Vorlage fuer vertrauenswuerdige Proxys.
var CloudflareNets = []string{"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
	"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14",
	"172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
	"2c0f:f248::/32"}

func validHeaderName(n string) bool {
	if n == "" || len(n) > 100 {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// ownHeaders setzt Node64 selbst (echte Client-Adresse - darauf baut z. B. die Pruefung von /mcp -, Schleifenschutz):
// weder ueberschreibbar noch entfernbar
var ownHeaders = map[string]bool{"x-forwarded-for": true, "x-real-ip": true, strings.ToLower(loopHeader): true}

// hop-by-hop und Kopfzeilen, die Node64 selbst setzt: nicht ueberschreibbar
var fixedHeaders = map[string]bool{"connection": true, "upgrade": true, "transfer-encoding": true, "content-length": true, "te": true,
	"trailer": true, "keep-alive": true, "proxy-connection": true, "x-forwarded-for": true, "x-real-ip": true, strings.ToLower(loopHeader): true}

// normalize prueft die weiteren Optionen.
func (a *Advanced) normalize() error {
	for _, list := range [][]Header{a.RequestHeaders, a.ResponseHeaders} {
		for i := range list {
			list[i].Name = strings.TrimSpace(list[i].Name)
			if !validHeaderName(list[i].Name) || fixedHeaders[strings.ToLower(list[i].Name)] || strings.ContainsAny(list[i].Value, "\r\n") || len(list[i].Value) > 1000 {
				return &FieldError{Field: "advanced", Key: "cdn64.err.header", Name: list[i].Name}
			}
		}
	}
	for j, list := range [][]string{a.RequestRemove, a.ResponseRemove} {
		for i := range list {
			list[i] = strings.TrimSpace(list[i])
			if !validHeaderName(list[i]) || (j == 0 && ownHeaders[strings.ToLower(list[i])]) {
				return &FieldError{Field: "advanced", Key: "cdn64.err.header", Name: list[i]}
			}
		}
	}
	a.HostHeader = strings.TrimSpace(a.HostHeader)
	if strings.ContainsAny(a.HostHeader, " \r\n/") || len(a.HostHeader) > 253 {
		return &FieldError{Field: "advanced", Key: "cdn64.err.host_header", Name: a.HostHeader}
	}
	if a.TimeoutSeconds < 0 || a.TimeoutSeconds > 86400 || a.MaxBodyMB < 0 || a.MaxBodyMB > 1<<20 {
		return &FieldError{Field: "advanced", Key: "cdn64.err.limits"}
	}
	if a.BWDownMbit < 0 || a.BWDownMbit > bwMaxMbit || a.BWUpMbit < 0 || a.BWUpMbit > bwMaxMbit {
		return &FieldError{Field: "advanced", Key: "cdn64.err.bandwidth"}
	}
	var nets []string
	for _, n := range a.TrustedProxies {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		p, err := parsePrefix(n)
		if err != nil || p.Bits() == 0 {
			return &FieldError{Field: "advanced", Key: "cdn64.err.trusted", Name: n}
		}
		nets = append(nets, p.String())
	}
	a.TrustedProxies = nets
	tp, ok := cleanTargetPath(a.TargetPath)
	if !ok {
		return &FieldError{Field: "target_path", Key: "cdn64.err.location_path", Name: a.TargetPath}
	}
	a.TargetPath = tp
	th, ok := cleanTargetHTTP(a.TargetHTTP, false)
	if !ok {
		return &FieldError{Field: "advanced", Key: "cdn64.err.target_http", Name: a.TargetHTTP}
	}
	a.TargetHTTP = th
	pp, ok := cleanProxyProtocol(a.ProxyProtocol)
	if !ok {
		return &FieldError{Field: "proxy_protocol", Key: "cdn64.err.proxy_protocol", Name: a.ProxyProtocol}
	}
	a.ProxyProtocol = pp
	return nil
}

func (a *Advanced) prepare() {
	a.trusted = a.trusted[:0]
	for _, n := range a.TrustedProxies {
		if p, err := parsePrefix(n); err == nil {
			a.trusted = append(a.trusted, p)
		}
	}
}

func (a *Advanced) isTrusted(ip netip.Addr) bool {
	for _, p := range a.trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// cfNets: CloudflareNets fuer die Pruefung von CF-Connecting-IP.
var cfNets = func() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(CloudflareNets))
	for _, n := range CloudflareNets {
		out = append(out, netip.MustParsePrefix(n))
	}
	return out
}()

func isCloudflare(ip netip.Addr) bool {
	for _, p := range cfNets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP: echte Gegenstelle; kommt sie von einem vertrauenswuerdigen Proxy, die Adresse aus CF-Connecting-IP
// (nur, wenn die Gegenstelle selbst bei Cloudflare liegt - sonst koennte jeder andere vertrauenswuerdige Proxy den
// Kopf einfach durchreichen) bzw. der letzte nicht vertrauenswuerdige Eintrag in X-Forwarded-For (alle Zeilen).
func (a *Advanced) clientIP(r *http.Request) netip.Addr {
	peer := peerIP(r)
	if !peer.IsValid() || !a.isTrusted(peer) {
		return peer
	}
	if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); v != "" && isCloudflare(peer.Unmap()) {
		if ip, err := netip.ParseAddr(v); err == nil {
			return ip.Unmap()
		}
	}
	parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip, err := xffAddr(parts[i])
		if err != nil {
			break
		}
		if !a.isTrusted(ip) {
			return ip
		}
	}
	return peer
}

// xffAddr: Eintrag aus X-Forwarded-For - Adresse, auch mit Port ("[2001:db8::1]:443", "192.0.2.1:80") oder in
// Klammern ("[2001:db8::1]"); entmappt und ohne Zone.
func xffAddr(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone(""), nil
	}
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	return a.Unmap().WithZone(""), err
}
