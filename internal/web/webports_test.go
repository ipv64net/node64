package web

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPortSwitchURL(t *testing.T) {
	req := func(host string, local int, tlsOn bool) *http.Request {
		r := httptest.NewRequest("POST", "/settings/reach", nil)
		r.Host = host
		if tlsOn {
			r.TLS = &tls.ConnectionState{}
		}
		if local > 0 {
			r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.IPv4(192, 168, 1, 5), Port: local}))
		}
		return r
	}
	for _, c := range []struct {
		r                      *http.Request
		oldH, oldS, newH, newS int
		want                   string
	}{
		// ueber den Web-Port: gleicher Name, neuer Port
		{req("node.lan:8080", 8080, false), 8080, 0, 8090, 0, "http://node.lan:8090/settings#reach"},
		{req("192.168.1.5:8080", 8080, true), 8080, 0, 9000, 0, "https://192.168.1.5:9000/settings#reach"},
		{req("[fd00::5]:8080", 8080, false), 8080, 0, 8090, 0, "http://[fd00::5]:8090/settings#reach"},
		// Web-Port aus: auf den HTTPS-Port
		{req("node.lan:8080", 8080, false), 8080, 8443, 0, 8443, "https://node.lan:8443/settings#reach"},
		// ueber den HTTPS-Port, nur der Web-Port aendert sich: Adresse bleibt
		{req("node.lan:8443", 8443, true), 8080, 8443, 8090, 8443, "https://node.lan:8443/settings#reach"},
		{req("node.lan:8443", 8443, true), 8080, 8443, 8080, 9443, "https://node.lan:9443/settings#reach"},
		// HTTPS-Port aus: auf den Web-Port (spricht auch TLS)
		{req("node.lan:8443", 8443, true), 8080, 8443, 8080, 0, "https://node.lan:8080/settings#reach"},
		// ueber den gemeinsamen Eingang (anderer Port): Adresse bleibt
		{req("node64.example.ipv64.de", 443, true), 8080, 0, 8090, 0, "https://node64.example.ipv64.de/settings#reach"},
		// Weiterleitung von Docker (-p 9000:8080): Name bleibt, neuer Port
		{req("nas:9000", 8080, false), 8080, 0, 8090, 0, "http://nas:8090/settings#reach"},
	} {
		if got := portSwitchURL(c.r, c.oldH, c.oldS, c.newH, c.newS); got != c.want {
			t.Errorf("%s (lokal %v): %s, want %s", c.r.Host, c.r.Context().Value(http.LocalAddrContextKey), got, c.want)
		}
	}
}

func TestWebPorts(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	if h, s, set := WebPorts(ctx, a.store, 8080, 0); set || h != 8080 || s != 0 {
		t.Fatalf("ohne Einstellung: %d %d %v", h, s, set)
	}
	a.store.SetSetting(ctx, SettingHTTPSPort, "8443")
	if h, s, set := WebPorts(ctx, a.store, 8080, 0); !set || h != 8080 || s != 8443 {
		t.Fatalf("nur HTTPS: %d %d %v", h, s, set)
	}
}

// freeTCPPort: ein gerade freier Port.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestSettingsReachPorts(t *testing.T) {
	restarted := make(chan struct{}, 1)
	a := newTestAppDeps(t, func(d *Deps) {
		d.Cfg.EnvHTTPPort = 8080
		d.RestartInPlace = func() { restarted <- struct{}{} }
	})
	old := bridgeNet
	bridgeNet = func() bool { return true }
	t.Cleanup(func() { bridgeNet = old })
	loginAs(t, a, "admin", "sehr geheimes passwort")
	ctx := context.Background()

	_, body := a.get(t, "/settings")
	for _, want := range []string{`name="http_port"`, `value="8080"`, `name="https_port"`, `(-p)`} {
		if !strings.Contains(body, want) {
			t.Errorf("Karte Erreichbarkeit ohne %s", want)
		}
	}
	csrf := csrfOf(t, body)
	post := func(h, s string) (*http.Response, string) {
		return a.post(t, "/settings/reach", url.Values{"_csrf": {csrf}, "http_port": {h}, "https_port": {s}, "ui_cert": {"auto"}})
	}

	// ungueltig: nichts gespeichert, kein Neustart
	for _, bad := range [][2]string{{"0", ""}, {"0", "0"}, {"70000", ""}, {"abc", ""}} {
		resp, _ := post(bad[0], bad[1])
		if resp.StatusCode != http.StatusSeeOther || a.store.SettingOr(ctx, SettingHTTPPort, "") != "" || a.store.SettingOr(ctx, SettingHTTPSPort, "") != "" {
			t.Fatalf("%v: %d gespeichert", bad, resp.StatusCode)
		}
	}
	// unveraendert (wie die Umgebung): keine Einstellung, kein Neustart
	if resp, _ := post("8080", ""); resp.Header.Get("Location") != "/settings#reach" || a.store.SettingOr(ctx, SettingHTTPPort, "x") != "x" {
		t.Fatal("unveraendert gespeichert")
	}
	select {
	case <-restarted:
		t.Fatal("Neustart ohne Aenderung")
	default:
	}

	// neuer Port: gespeichert, Seite mit Weiterleitung, Neustart
	p := freeTCPPort(t)
	resp, body := post(strconv.Itoa(p), "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `id="port-switch"`) || a.store.SettingOr(ctx, SettingHTTPPort, "") != strconv.Itoa(p) {
		t.Fatalf("Wechsel: %d %s", resp.StatusCode, a.store.SettingOr(ctx, SettingHTTPPort, ""))
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "connect-src 'self' http://") {
		t.Errorf("CSP erlaubt die Abfrage des neuen Ports nicht: %s", csp)
	}
	select {
	case <-restarted:
	case <-time.After(5 * time.Second):
		t.Fatal("kein Neustart")
	}

	// belegter Port: nicht gespeichert
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	busy := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	if resp, _ := post(busy, ""); resp.StatusCode != http.StatusSeeOther || a.store.SettingOr(ctx, SettingHTTPPort, "") == busy {
		t.Fatal("belegter Port gespeichert")
	}
}

func TestRedirectHTTPS(t *testing.T) {
	s := &Server{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := s.redirectHTTPS(next)
	do := func(method, host, path, remote string, hdr ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r.Host, r.RemoteAddr = host, remote
		if len(hdr) == 2 {
			r.Header.Set(hdr[0], hdr[1])
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := do("GET", "node.lan:8080", "/settings", "192.0.2.7:5000"); w.Code != http.StatusTeapot {
		t.Fatalf("Schalter aus: %d", w.Code)
	}
	s.httpsRedirect.Store(true)
	if w := do("GET", "node.lan:8080", "/settings?x=1", "192.0.2.7:5000"); w.Code != http.StatusFound || w.Header().Get("Location") != "https://node.lan:8080/settings?x=1" {
		t.Fatalf("Umleitung: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := do("GET", "[fd00::5]:8080", "/", "[fd00::9]:5000"); w.Header().Get("Location") != "https://[fd00::5]:8080/" {
		t.Fatalf("IPv6: %s", w.Header().Get("Location"))
	}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"api":       do("GET", "node.lan:8080", "/api/health", "192.0.2.7:5000"),
		"status":    do("GET", "node.lan:8080", "/status/haus", "192.0.2.7:5000"),
		"agent":     do("GET", "node.lan:8080", "/monitor64/agent/install.sh", "192.0.2.7:5000"),
		"doh":       do("GET", "node.lan:8080", "/dns-query?dns=AAAB", "192.0.2.7:5000"),
		"loopback":  do("GET", "127.0.0.1:8080", "/settings", "127.0.0.1:5000"),
		"ohne Port": do("GET", "nas", "/settings", "192.0.2.7:5000"),
		"POST":      do("POST", "node.lan:8080", "/settings", "192.0.2.7:5000"),
		"Bearer":    do("GET", "node.lan:8080", "/settings", "192.0.2.7:5000", "Authorization", "Bearer x"),
	} {
		if w.Code != http.StatusTeapot {
			t.Errorf("%s: umgeleitet (%d)", name, w.Code)
		}
	}
}

// Gleicher Port in beiden Feldern: kein eigener HTTPS-Port (der Web-Port spricht HTTPS mit); Schalter Umleitung.
func TestSettingsReachSamePortAndRedirect(t *testing.T) {
	a := newTestAppDeps(t, func(d *Deps) {
		d.Cfg.EnvHTTPPort = 8080
		d.RestartInPlace = func() {}
	})
	loginAs(t, a, "admin", "sehr geheimes passwort")
	ctx := context.Background()
	_, body := a.get(t, "/settings")
	if !strings.Contains(body, `name="https_redirect"`) {
		t.Fatal("Schalter fehlt")
	}
	csrf := csrfOf(t, body)
	if !strings.Contains(body, `id="https_redirect" name="https_redirect" checked`) {
		t.Fatal("Schalter muss standardmaessig an sein")
	}
	// nur der Schalter (Ports unveraendert): gespeichert, kein Neustart; gleicher Port = kein eigener HTTPS-Port
	resp, _ := a.post(t, "/settings/reach", url.Values{"_csrf": {csrf}, "http_port": {"8080"}, "https_port": {"8080"}, "ui_cert": {"auto"}})
	if resp.Header.Get("Location") != "/settings#reach" || a.s.httpsRedirect.Load() || a.store.SettingOr(ctx, SettingHTTPSRedirect, "") != "0" {
		t.Fatalf("Schalter aus: %s %v", resp.Header.Get("Location"), a.s.httpsRedirect.Load())
	}
	if a.store.SettingOr(ctx, SettingHTTPSPort, "x") != "x" {
		t.Fatal("gleicher Port als eigener HTTPS-Port gespeichert")
	}
	resp, _ = a.post(t, "/settings/reach", url.Values{"_csrf": {csrf}, "http_port": {"8080"}, "https_port": {""}, "https_redirect": {"on"}, "ui_cert": {"auto"}})
	if !a.s.httpsRedirect.Load() || a.store.SettingOr(ctx, SettingHTTPSRedirect, "") != "1" {
		t.Fatal("Schalter an nicht gespeichert")
	}
	// neuer gleicher Port in beiden Feldern: Wechsel ohne eigenen HTTPS-Port
	p := strconv.Itoa(freeTCPPort(t))
	resp, _ = a.post(t, "/settings/reach", url.Values{"_csrf": {csrf}, "http_port": {p}, "https_port": {p}, "ui_cert": {"auto"}})
	if resp.StatusCode != http.StatusOK || a.store.SettingOr(ctx, SettingHTTPPort, "") != p || a.store.SettingOr(ctx, SettingHTTPSPort, "x") != "x" {
		t.Fatalf("gleicher Port: %d %s %s", resp.StatusCode, a.store.SettingOr(ctx, SettingHTTPPort, ""), a.store.SettingOr(ctx, SettingHTTPSPort, "x"))
	}
}

// Standard ist "umleiten"; hinter einem vertrauenswuerdigen Proxy mit X-Forwarded-Proto: https nicht.
func TestRedirectHTTPSDefaultAndProxy(t *testing.T) {
	a := newTestApp(t)
	if !a.s.httpsRedirect.Load() {
		t.Fatal("Standard muss umleiten")
	}
	a.s.Cfg.TrustProxyHeaders = true
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	r := httptest.NewRequest("GET", "/settings", nil)
	r.Host, r.RemoteAddr = "node.lan:8080", "192.0.2.7:5000"
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	a.s.redirectHTTPS(next).ServeHTTP(w, r)
	if w.Code != http.StatusTeapot {
		t.Fatalf("hinter HTTPS-Proxy umgeleitet: %d", w.Code)
	}
}
