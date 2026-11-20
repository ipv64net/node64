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
	for _, bad := range [][2]string{{"0", ""}, {"8443", "8443"}, {"70000", ""}, {"abc", ""}} {
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
