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
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/edge"
)

// Der Proxy eines Hosts: httputil.ReverseProxy (WebSockets, Streaming, HTTP/2 kommen von Go selbst), davor
// Exploit-Sperre, Asset-Cache, HSTS, Schleifenschutz und Zaehler.

const loopHeader = "X-Node64-Proxy"

// hostStats zaehlt seit dem Start des Moduls.
type hostStats struct {
	requests atomic.Int64
	errors   atomic.Int64 // 5xx und nicht erreichbar
	blocked  atomic.Int64 // Block Common Exploits
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

// inner: was ein Host tut (Proxy, Weiterleitung, 404).
func (m *Module) inner(h *Host, st *hostStats) http.Handler {
	switch h.Kind {
	case KindRedirect:
		return redirectHandler(h)
	case KindDead:
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { page(w, http.StatusNotFound) })
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

// proxyHandler baut den Reverse-Proxy eines Hosts.
func (m *Module) proxyHandler(h *Host, st *hostStats) http.Handler {
	target := &url.URL{Scheme: h.Scheme, Host: net.JoinHostPort(h.TargetHost, strconv.Itoa(h.TargetPort))}
	token := m.loopToken
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host // wie NPM: das Ziel sieht den Namen, unter dem der Besucher kam
			pr.SetXForwarded()       // nur die echte Gegenstelle; mitgeschickte X-Forwarded-* verwirft Rewrite
			if ip := peerIP(pr.In); ip.IsValid() {
				pr.Out.Header.Set("X-Real-IP", ip.String())
			}
			pr.Out.Header.Set(loopHeader, token)
		},
		Transport: m.transport(h.VerifyTarget),
		ErrorLog:  log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			st.errors.Add(1)
			if !errors.Is(err, context.Canceled) {
				m.log.Debug("target not reachable", "host", r.Host, "target", target.Host, "err", err)
			}
			page(w, http.StatusBadGateway)
		},
	}
	if h.CacheAssets {
		return m.cache.cached(h.ID, rp)
	}
	return rp
}

// handlerFor: was ein Host tut, mit Zaehlern, Schleifenschutz, Exploit-Sperre, WebSocket-Schalter und HSTS.
func (m *Module) handlerFor(h *Host, st *hostStats) http.Handler {
	next := m.inner(h, st)
	token := m.loopToken
	hsts := ""
	if h.HSTS {
		hsts = "max-age=63072000"
		if h.HSTSSubdomains {
			hsts += "; includeSubDomains"
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.requests.Add(1)
		if r.Header.Get(loopHeader) == token { // Ziel zeigt auf diesen Proxy selbst
			st.errors.Add(1)
			page(w, http.StatusLoopDetected)
			return
		}
		if h.BlockExploits && blocked(r) {
			st.blocked.Add(1)
			page(w, http.StatusForbidden)
			return
		}
		if !h.WebSockets && r.Header.Get("Upgrade") != "" {
			r.Header.Del("Upgrade")
			r.Header.Del("Connection")
		}
		if hsts != "" && r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", hsts)
		}
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status >= 500 && sw.status != http.StatusBadGateway { // 502 zaehlt der ErrorHandler schon
			st.errors.Add(1)
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
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
	return w.ResponseWriter.Write(b)
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
	errs := map[int64]string{}
	var active []*Host
	for _, h := range list {
		if h.Enabled {
			active = append(active, h)
		}
	}
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
		return edge.Route{Names: h.Names, Passthrough: net.JoinHostPort(h.TargetHost, strconv.Itoa(h.TargetPort)), Count: func() { st.requests.Add(1) },
			HTTP: http.HandlerFunc(m.toHTTPS)}
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
