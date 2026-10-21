package cdn64

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/httpcompress"
)

// Der Proxy eines Hosts: httputil.ReverseProxy (WebSockets, Streaming, HTTP/2 kommen von Go selbst), davor
// Exploit-Sperre, Asset-Cache, HSTS, Schleifenschutz und Zaehler.

const loopHeader = "X-Node64-Proxy"

// hostStats zaehlt seit dem Start des Moduls.
type hostStats struct {
	requests atomic.Int64
	errors   atomic.Int64 // 5xx und nicht erreichbar
	blocked  atomic.Int64 // Block Common Exploits, Blocklisten, Limits
}

func (m *Module) statsOf(id int64) *hostStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.stats[id]
	if st == nil {
		st = &hostStats{}
		m.stats[id] = st
	}
	return st
}

// transport: geteilte Verbindungen zu den Zielen (mit bzw. ohne Pruefung des Ziel-Zertifikats).
func newTransport(verify bool) *http.Transport {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: !verify, MinVersion: tls.VersionTLS12}, //nolint:gosec // Heimnetz-Ziele oft selbstsigniert, abschaltbar je Host
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

func (m *Module) transport(verify bool) http.RoundTripper {
	if verify {
		return m.trVerify
	}
	return m.trInsecure
}

// inner: was ein Host tut (Proxy, Weiterleitung, 404, Statusseite).
func (m *Module) inner(h *Host, st *hostStats) http.Handler {
	switch h.Kind {
	case KindRedirect:
		return redirectHandler(h)
	case KindDead:
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { page(w, http.StatusNotFound) })
	case KindStatus:
		return m.statusHandler(h)
	}
	return m.proxyHandler(h, st)
}

// redirectHandler leitet weiter (Schema "auto" = wie die Anfrage).
func redirectHandler(h *Host) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme := h.RedirectScheme
		if scheme != "http" && scheme != "https" {
			scheme = "http"
			if r.TLS != nil {
				scheme = "https"
			}
		}
		target := scheme + "://" + h.RedirectTarget
		if h.PreservePath {
			target += r.URL.RequestURI()
		} else if !strings.Contains(h.RedirectTarget, "/") {
			target += "/"
		}
		http.Redirect(w, r, target, h.RedirectCode)
	})
}

// transportFor: geteilte Verbindungen, mit eigenem Timeout nur fuer Hosts, die einen eingestellt haben.
func (m *Module) transportFor(h *Host) http.RoundTripper {
	base := m.transport(h.VerifyTarget)
	if h.Advanced.TimeoutSeconds <= 0 {
		return base
	}
	tr := base.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = time.Duration(h.Advanced.TimeoutSeconds) * time.Second
	m.mu.Lock()
	if old := m.hostTr[h.ID]; old != nil {
		old.CloseIdleConnections()
	}
	m.hostTr[h.ID] = tr
	m.mu.Unlock()
	return tr
}

// target ist ein Ziel des Proxys (der Host selbst oder eine Location).
type target struct {
	url     *url.URL
	prefix  string // Location: Pfad beim Besucher
	forward string // Location: Pfad beim Ziel ("" = unveraendert)
}

// reverseProxy baut den Proxy zu einem Ziel mit den Optionen des Hosts.
func (m *Module) reverseProxy(h *Host, t target, st *hostStats, tr http.RoundTripper) http.Handler {
	token := m.loopToken
	adv := &h.Advanced
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(t.url)
			if t.forward != "" { // /api/x -> /v1/x
				rest := strings.TrimPrefix(strings.TrimPrefix(pr.In.URL.Path, t.prefix), "/")
				pr.Out.URL.Path = t.forward
				if rest != "" || strings.HasSuffix(pr.In.URL.Path, "/") {
					pr.Out.URL.Path = strings.TrimSuffix(t.forward, "/") + "/" + rest
				}
				pr.Out.URL.RawPath = ""
			}
			switch adv.HostHeader {
			case "": // wie NPM: das Ziel sieht den Namen, unter dem der Besucher kam
				pr.Out.Host = pr.In.Host
			case "target": // Name des Ziels (SetURL)
			default:
				pr.Out.Host = adv.HostHeader
			}
			pr.SetXForwarded() // mitgeschickte X-Forwarded-* verwirft Rewrite; For danach mit der echten Client-IP
			if ip := clientOf(pr.In); ip.IsValid() {
				pr.Out.Header.Set("X-Forwarded-For", ip.String())
				pr.Out.Header.Set("X-Real-IP", ip.String())
			}
			for _, n := range adv.RequestRemove {
				if !ownHeaders[strings.ToLower(n)] { // auch aeltere gespeicherte Einstellungen
					pr.Out.Header.Del(n)
				}
			}
			for _, x := range adv.RequestHeaders {
				if !fixedHeaders[strings.ToLower(x.Name)] {
					pr.Out.Header.Set(x.Name, x.Value)
				}
			}
			pr.Out.Header.Set(loopHeader, token)
		},
		Transport: tr,
		ErrorLog:  log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			st.errors.Add(1)
			if !errors.Is(err, context.Canceled) {
				m.log.Debug("target not reachable", "host", r.Host, "target", t.url.Host, "err", err)
			}
			status := http.StatusBadGateway
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				status = http.StatusRequestEntityTooLarge
			}
			page(w, status)
		},
	}
	rp.ModifyResponse = func(resp *http.Response) error {
		httpcompress.TrackBody(resp) // Cache: nur ganz gelesene Antworten
		for _, n := range adv.ResponseRemove {
			resp.Header.Del(n)
		}
		for _, x := range adv.ResponseHeaders {
			resp.Header.Set(x.Name, x.Value)
		}
		return nil
	}
	if adv.NoBuffering {
		rp.FlushInterval = -1
	}
	return rp
}

// route ist ein Pfad eines Hosts mit eigenem Proxy und eigener Zugriffsliste.
type route struct {
	prefix string // "" = Host selbst
	ws     bool
	acl    int64
	next   http.Handler
}

// proxyHandler baut den Reverse-Proxy eines Hosts mit seinen Locations (laengster Praefix gewinnt).
func (m *Module) proxyHandler(h *Host, st *hostStats) http.Handler {
	tr := m.transportFor(h)
	mk := func(scheme, host string, port int) *url.URL {
		return &url.URL{Scheme: scheme, Host: net.JoinHostPort(host, strconv.Itoa(port))}
	}
	var next http.Handler = m.reverseProxy(h, target{url: mk(h.Scheme, h.TargetHost, h.TargetPort)}, st, tr)
	if h.Advanced.Gzip { // vor dem Cache: der legt die fertig komprimierte Fassung ab (was er ablegt, staerker)
		next = httpcompress.Handler(next, httpcompress.Options{Static: func(r *http.Request, hd http.Header) bool {
			return h.CacheAssets && r.Method == http.MethodGet && cacheable(r) && httpcompress.StaticExt(r.URL.Path) && storable(hd)
		}})
	}
	if h.CacheAssets {
		next = m.cache.cached(h.ID, next)
	}
	routes := []route{{ws: h.WebSockets, acl: h.AccessListID, next: next}}
	for _, l := range h.Locations {
		var ln http.Handler = m.reverseProxy(h, target{url: mk(l.Scheme, l.TargetHost, l.TargetPort), prefix: l.Path, forward: l.ForwardPath}, st, tr)
		if h.Advanced.Gzip {
			ln = httpcompress.Handler(ln, httpcompress.Options{})
		}
		acl := l.AccessListID
		if acl == 0 {
			acl = h.AccessListID
		}
		routes = append(routes, route{prefix: l.Path, ws: l.WebSockets, acl: acl, next: ln})
	}
	sort.SliceStable(routes, func(i, j int) bool { return len(routes[i].prefix) > len(routes[j].prefix) })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt := &routes[len(routes)-1]
		for i := range routes {
			p := routes[i].prefix
			if p == "" || r.URL.Path == p || strings.HasPrefix(r.URL.Path, p+"/") {
				rt = &routes[i]
				break
			}
		}
		if !rt.ws && r.Header.Get("Upgrade") != "" {
			r.Header.Del("Upgrade")
			r.Header.Del("Connection")
		}
		if !m.allowed(w, r, h, rt.acl) {
			return
		}
		rt.next.ServeHTTP(w, r)
	})
}

// allowed prueft die Zugriffsliste; false = Antwort ist schon geschrieben (401/403/429).
func (m *Module) allowed(w http.ResponseWriter, r *http.Request, h *Host, acl int64) bool {
	if acl <= 0 {
		return true
	}
	m.mu.Lock()
	g := m.acl[acl]
	m.mu.Unlock()
	if g == nil { // Liste geloescht: lieber sperren als offen lassen
		page(w, http.StatusForbidden)
		return false
	}
	ip := clientOf(r)
	if m.authFail.blocked(ip) {
		setReject(r, rejACL)
		w.Header().Set("Retry-After", strconv.Itoa(int(authBlockFor.Seconds())))
		page(w, http.StatusTooManyRequests)
		return false
	}
	ok, status, failed := g.decide(r, ip)
	if ok {
		if len(g.list.Users) > 0 && !g.list.PassAuth {
			r.Header.Del("Authorization")
		}
		return true
	}
	if failed {
		setAuthFail(r)
	}
	if failed && m.authFail.failed(ip) {
		m.log.Warn("access list: too many failed logins, ip blocked", "host", h.Names[0], "ip", ip, "minutes", int(authBlockFor.Minutes()))
		if m.g.Audit != nil {
			m.g.Audit(r, "cdn64.access.blocked", h.Names[0], "ip="+ip.String())
		}
	}
	if status != http.StatusUnauthorized { // 401 ist die normale Passwortabfrage
		setReject(r, rejACL)
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+strings.ReplaceAll(g.list.Name, `"`, "")+`", charset="UTF-8"`)
	}
	page(w, status)
	return false
}

// ctxClient: echte Client-IP (nach den vertrauenswuerdigen Proxys des Hosts), im Kontext der Anfrage.
type ctxClientKey struct{}

// ctxRejectKey: Grund, falls die Anfrage abgewiesen wird (fuer Statistik und Log).
type ctxRejectKey struct{}

func setReject(r *http.Request, reason string) {
	if p, ok := r.Context().Value(ctxRejectKey{}).(*string); ok {
		*p = reason
	}
}

func clientOf(r *http.Request) netip.Addr {
	if ip, ok := r.Context().Value(ctxClientKey{}).(netip.Addr); ok {
		return ip
	}
	return peerIP(r)
}

// handlerFor: was ein Host tut, mit Zaehlern, Statistik, Schleifenschutz, Exploit-Sperre, Upload-Grenze und HSTS.
func (m *Module) handlerFor(h *Host, st *hostStats) http.Handler {
	h.Advanced.prepare()
	next := m.inner(h, st)
	token := m.loopToken
	hsts := ""
	if h.HSTS {
		hsts = "max-age=63072000"
		if h.HSTSSubdomains {
			hsts += "; includeSubDomains"
		}
	}
	maxBody := int64(h.Advanced.MaxBodyMB) << 20
	limited := !h.Advanced.NoLimits
	var sl slots // gleichzeitige Anfragen an das Ziel
	if c := m.lim.config(); h.Kind == KindProxy && limited && c.Enabled && c.TargetConns > 0 {
		sl = make(slots, c.TargetConns)
	}
	if h.Kind == KindProxy && !h.WebSockets && len(h.Locations) == 0 {
		next = stripUpgrade(next)
	}
	if h.Kind != KindProxy && h.AccessListID > 0 { // Weiterleitung mit Zugriffsliste
		inner, acl := next, h.AccessListID
		next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m.allowed(w, r, h, acl) {
				inner.ServeHTTP(w, r)
			}
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		st.requests.Add(1)
		client := h.Advanced.clientIP(r)
		reject, authFail := new(string), new(bool)
		ctx := context.WithValue(context.WithValue(r.Context(), ctxClientKey{}, client), ctxRejectKey{}, reject)
		r = r.WithContext(context.WithValue(ctx, ctxAuthFailKey{}, authFail))
		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			m.hpReport(r, client, true, sw.code(), *authFail)
			if sdb := m.stats2.Load(); sdb != nil {
				sdb.add(hit{time: start, hostID: h.ID, client: client, method: r.Method, host: hostOnly(r.Host), path: trunc(r.URL.RequestURI(), 500),
					status: sw.code(), bytes: sw.bytes, ms: time.Since(start).Milliseconds(), ua: trunc(r.UserAgent(), 200), log: h.Advanced.AccessLog,
					reason: *reject})
			}
		}()
		if m.bl.Blocked(client) { // ipv64-Blocklisten (echte Client-IP hinter vertrauenswuerdigen Proxys)
			*reject = rejBlocklist
			st.blocked.Add(1)
			page(sw, http.StatusForbidden)
			return
		}
		if m.hpBlocked(client) { // vom Honeypot gemeldet (Sofort-Sperre)
			*reject = rejHoneypot
			st.blocked.Add(1)
			page(sw, http.StatusForbidden)
			return
		}
		if m.geoBlocked(&h.Advanced, client) { // Laendersperre des Hosts
			*reject = rejGeo
			st.blocked.Add(1)
			page(sw, http.StatusForbidden)
			return
		}
		if m.lim.banned(client) { // gesperrt wegen Ueberlastung
			*reject = rejBan
			st.blocked.Add(1)
			page(sw, http.StatusForbidden)
			return
		}
		if limited && !m.lim.request(client) { // zu viele Anfragen von dieser Adresse
			*reject = rejReqRate
			st.blocked.Add(1)
			sw.Header().Set("Retry-After", "10")
			page(sw, http.StatusTooManyRequests)
			return
		}
		if r.Header.Get(loopHeader) == token { // Ziel zeigt auf diesen Proxy selbst
			st.errors.Add(1)
			page(sw, http.StatusLoopDetected)
			return
		}
		if h.BlockExploits && blocked(r) {
			*reject = rejExploit
			st.blocked.Add(1)
			page(sw, http.StatusForbidden)
			return
		}
		if maxBody > 0 {
			if r.ContentLength > maxBody {
				page(sw, http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(sw, r.Body, maxBody)
		}
		if hsts != "" && r.TLS != nil {
			sw.Header().Set("Strict-Transport-Security", hsts)
		}
		if sl != nil && r.Header.Get("Upgrade") == "" { // WebSockets laufen lange und zaehlen nicht
			if !sl.acquire(r.Context(), limQueueWait) {
				if r.Context().Err() == nil {
					*reject = rejTarget
					m.overload("target", h.Names[0])
					m.lim.rejected.Add(1)
					st.blocked.Add(1)
					sw.Header().Set("Retry-After", "10")
					page(sw, http.StatusServiceUnavailable)
				}
				return
			}
			defer sl.release()
		}
		next.ServeHTTP(sw, r)
		if sw.status >= 500 && sw.status != http.StatusBadGateway { // 502 zaehlt der ErrorHandler schon
			st.errors.Add(1)
		}
	})
}

func stripUpgrade(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "" {
			r.Header.Del("Upgrade")
			r.Header.Del("Connection")
		}
		next.ServeHTTP(w, r)
	})
}

func hostOnly(h string) string {
	if x, _, err := net.SplitHostPort(h); err == nil {
		return x
	}
	return h
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

// code: Status der Antwort (0 = abgebrochen bzw. WebSocket uebernommen).
func (w *statusWriter) code() int {
	if w.status == 0 {
		return 499
	}
	return w.status
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap: fuer http.ResponseController (WebSockets brauchen Hijack).
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func peerIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

var pageText = map[int]string{
	http.StatusBadGateway:   "The service behind this address is not reachable at the moment.",
	http.StatusForbidden:    "This request was blocked.",
	http.StatusLoopDetected: "This address points to itself.",
}

// page: neutrale Fehlerseite (verraet nichts ueber Node64 oder das Ziel).
func page(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>"+strconv.Itoa(status)+" "+http.StatusText(status)+
		"</title></head><body style=\"font-family:sans-serif;text-align:center;margin-top:15vh;color:#555\"><h1>"+strconv.Itoa(status)+
		"</h1><p>"+pageText[status]+"</p></body></html>\n")
}

// ---------------------------------------------------------------- Routen beim Eingang

// apply meldet alle eingeschalteten Hosts beim gemeinsamen Eingang an. Gehoert ein Name schon einem anderen
// Teil (z. B. DNS64), bleibt nur dieser Host draussen und bekommt den Fehler angezeigt.
func (m *Module) apply(ctx context.Context) {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	m.mu.Lock()
	on := m.running
	m.mu.Unlock()
	if !on || m.edge == nil {
		return
	}
	list, err := m.hosts(ctx)
	if err != nil {
		m.log.Error("hosts not readable", "err", err)
		return
	}
	guards := m.guards(ctx)
	m.limExempt(ctx, list)
	m.mu.Lock()
	m.acl = guards
	m.mu.Unlock()
	errs := map[int64]string{}
	var active []*Host
	for _, h := range list {
		if h.Enabled {
			active = append(active, h)
		}
	}
	m.geoNeed(active)
	for {
		routes := make([]edge.Route, 0, len(active))
		for _, h := range active {
			routes = append(routes, m.routeFor(h))
		}
		err := m.edge.Set(Name, routes)
		var taken *edge.NameTakenError
		if err == nil || !errors.As(err, &taken) {
			if err != nil {
				m.log.Error("routes not applied", "err", err)
			}
			break
		}
		keep := active[:0]
		for _, h := range active {
			if contains(h.Names, taken.Name) {
				errs[h.ID] = "name " + taken.Name + " is used by " + taken.Owner
				continue
			}
			keep = append(keep, h)
		}
		active = keep
	}
	m.mu.Lock()
	m.routeErr = errs
	m.mu.Unlock()
}

func (m *Module) routeFor(h *Host) edge.Route {
	handler := m.handlerFor(h, m.statsOf(h.ID))
	if h.Kind == KindPass { // TLS durchreichen: auf Port 80 nur Weiterleitung auf HTTPS
		st := m.statsOf(h.ID)
		rt := edge.Route{Names: h.Names, Passthrough: net.JoinHostPort(h.TargetHost, strconv.Itoa(h.TargetPort)), Count: func() { st.requests.Add(1) },
			HTTP: http.HandlerFunc(m.toHTTPS)}
		if h.Advanced.GeoMode != "" { // Laendersperre: Verbindung gleich nach dem ersten TLS-Paket schliessen
			rt.Allow = func(ip netip.Addr) bool {
				if m.geoBlocked(&h.Advanced, ip) {
					st.blocked.Add(1)
					m.rejectConn(ip, rejGeo, h.Names[0])
					return false
				}
				return true
			}
		}
		return rt
	}
	rt := edge.Route{Names: h.Names, NoHTTP2: !h.HTTP2, HTTP3: h.HTTP3, MinTLS: tls.VersionTLS12}
	if h.MinTLS == "1.3" {
		rt.MinTLS = tls.VersionTLS13
	}
	if !h.HTTPS() {
		rt.HTTP = handler
		return rt
	}
	if h.CertID > 0 {
		rt.CertID = h.CertID
	}
	rt.Handler = handler
	if !h.ForceSSL {
		rt.HTTP = handler
	}
	return rt
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// certUsers: welche Zertifikate die Hosts benutzen (Anzeige "benutzt von", Schutz beim Loeschen).
func (m *Module) certUsers(ctx context.Context) map[int64][]string {
	out := map[int64][]string{}
	if m.certs == nil {
		return out
	}
	list, err := m.hosts(ctx)
	if err != nil {
		return out
	}
	for _, h := range list {
		if !h.Enabled || !h.HTTPS() {
			continue
		}
		if h.CertID > 0 {
			out[h.CertID] = append(out[h.CertID], h.Names[0])
			continue
		}
		seen := map[int64]bool{}
		for _, n := range h.Names {
			if id := m.certs.MatchID(n); id > 0 && !seen[id] {
				seen[id] = true
				out[id] = append(out[id], h.Names[0])
			}
		}
	}
	return out
}

// hostOfName: fuer Anzeigen (Link auf den ersten Namen).
func firstURL(h *Host) string {
	if strings.HasPrefix(h.Names[0], "*.") {
		return ""
	}
	if h.HTTPS() {
		return "https://" + h.Names[0]
	}
	return "http://" + h.Names[0]
}

// toHTTPS leitet auf HTTPS um (Port aus Sicht der Besucher).
func (m *Module) toHTTPS(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if m.edge != nil {
		if p := m.edge.Config().Public(); p != 443 {
			host += ":" + strconv.Itoa(p)
		}
	}
	http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
}
