package cdnedge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestErrorPage(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://shop.example/", nil)
	r.Header.Set("Accept-Language", "de-DE,de;q=0.9,en;q=0.8")
	w := httptest.NewRecorder()
	termPage(w, r, http.StatusBadGateway, "shop.example", "Nicht erreichbar.", "Not reachable.")
	body := w.Body.String()
	for _, want := range []string{`lang="de"`, "502", "Gerade nicht erreichbar", "Nicht erreichbar.", "IPv64 CDN", `href="https://ipv64.net"`, `class="logo"`, "shop.example"} {
		if !strings.Contains(body, want) {
			t.Errorf("seite ohne %q", want)
		}
	}
	if w.Code != 502 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Language") != "de" {
		t.Fatalf("antwort: %d %v", w.Code, w.Header())
	}
	if strings.Contains(body, "<script") || strings.Contains(body, "<link") || strings.Contains(body, "src=") || strings.Contains(body, "url(") {
		t.Fatal("seite laedt fremde quellen")
	}
	w = httptest.NewRecorder()
	r.Header.Set("Accept-Language", "en-US")
	termPage(w, r, http.StatusForbidden, "<x>", "Kein Zugriff.", "No access.")
	if b := w.Body.String(); !strings.Contains(b, "Access denied") || !strings.Contains(b, "&lt;x&gt;") || strings.Contains(b, "<x>") {
		t.Fatalf("englisch/escaping: %s", b)
	}
}

// Modus 2/3: 5xx des Ziels wird fuer Browser zur Fehlerseite, APIs und Abschaltung per Header behalten die Antwort.
func TestOriginErrorPage(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = io.WriteString(w, "fine")
		case "/off":
			w.Header().Set("CDN64-Error-Page", "off")
			w.WriteHeader(500)
			_, _ = io.WriteString(w, "own page")
		case "/404":
			http.NotFound(w, r)
		default:
			w.Header().Set("Retry-After", "120")
			w.Header().Set("Set-Cookie", "a=b")
			w.WriteHeader(503)
			_, _ = io.WriteString(w, `{"error":"maintenance"}`)
		}
	}))
	defer origin.Close()
	u, _ := url.Parse(origin.URL)
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.ModifyResponse = originErrorPage
	front := httptest.NewServer(rp)
	defer front.Close()
	get := func(method, path, accept string) (*http.Response, string) {
		req, _ := http.NewRequest(method, front.URL+path, nil)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		req.Header.Set("Accept-Language", "de")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	browser := "text/html,application/xhtml+xml,*/*;q=0.8"
	resp, body := get("GET", "/down", browser)
	if resp.StatusCode != 503 || !strings.Contains(body, "IPv64 CDN") || strings.Contains(body, "maintenance") ||
		resp.Header.Get("Retry-After") != "120" || resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("browser 503: %d %v %s", resp.StatusCode, resp.Header, body)
	}
	if resp, body = get("GET", "/down", "application/json"); resp.StatusCode != 503 || body != `{"error":"maintenance"}` {
		t.Fatalf("api 503: %d %s", resp.StatusCode, body)
	}
	if resp, body = get("POST", "/down", browser); body != `{"error":"maintenance"}` {
		t.Fatalf("post 503: %d %s", resp.StatusCode, body)
	}
	if resp, body = get("GET", "/off", browser); resp.StatusCode != 500 || body != "own page" {
		t.Fatalf("abgeschaltet: %d %s", resp.StatusCode, body)
	}
	if resp, body = get("GET", "/404", browser); resp.StatusCode != 404 || strings.Contains(body, "IPv64 CDN") {
		t.Fatalf("404 bleibt: %d %s", resp.StatusCode, body)
	}
	if resp, body = get("GET", "/ok", browser); resp.StatusCode != 200 || body != "fine" {
		t.Fatalf("200: %d %s", resp.StatusCode, body)
	}
	if resp, body = get("HEAD", "/down", browser); resp.StatusCode != 503 || body != "" {
		t.Fatalf("head: %d %q", resp.StatusCode, body)
	}
}

// Modus 1 / Port 80: Seite direkt auf die rohe Verbindung, Sprache aus der Anfrage.
func TestRawPage(t *testing.T) {
	req := []byte("GET / HTTP/1.1\r\nHost: shop.example\r\nAccept-Language: de-CH, en;q=0.5\r\n\r\n")
	if got := rawHeader(req, "accept-language"); got != "de-CH, en;q=0.5" {
		t.Fatalf("rawHeader: %q", got)
	}
	if got := rawHeader([]byte("GET / HTTP/1.1\r\n\r\nAccept-Language: de\r\n"), "accept-language"); got != "" {
		t.Fatalf("rawHeader nach den Headern: %q", got)
	}
	var b bytes.Buffer
	rawPage(&b, req, http.StatusBadGateway, "shop.example", "weg", "gone")
	resp, err := http.ReadResponse(bufio.NewReader(&b), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 502 || !strings.Contains(string(body), "weg") || !resp.Close || resp.ContentLength != int64(len(body)) {
		t.Fatalf("raw: %d %v %s", resp.StatusCode, resp.Header, body)
	}
	b.Reset()
	rawPage(&b, []byte("HEAD / HTTP/1.1\r\n\r\n"), http.StatusServiceUnavailable, "x", "a", "b")
	if strings.Contains(b.String(), "<html") || !strings.HasPrefix(b.String(), "HTTP/1.1 503 Service Unavailable\r\n") {
		t.Fatalf("head raw: %s", b.String())
	}
}

// Aufruf des Servers selbst: Infoseite auf Port 80 (jeder Name ohne Kunde) und per HTTPS auf dem eigenen Namen
// (Browser ohne Tunnel-ALPN); der Tunnel ueber 443 bleibt (TestTunnelOn443).
func TestInfoPage(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	cfg := &Config{Name: "B", PublicHost: "edge.test", ListenHTTP: freeAddr(t), ListenHTTPS: freeAddr(t), TunnelListen: freeAddr(t),
		TLSCert: cf, TLSKey: kf, DataDir: t.TempDir()}
	startEdge(t, cfg, pool)
	get := func(c *http.Client, u, host string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		req.Host = host
		req.Header.Set("Accept-Language", "de")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	for _, host := range []string{"edge.test", "127.0.0.1", "unknown.example"} {
		code, body := get(http.DefaultClient, "http://"+cfg.ListenHTTP+"/", host)
		if code != 200 || !strings.Contains(body, "Server des IPv64 CDN") || !strings.Contains(body, "https://node64.de") || !strings.Contains(body, "edge.test") {
			t.Fatalf("http %s: %d %s", host, code, body)
		}
	}
	if code, body := get(http.DefaultClient, "http://"+cfg.ListenHTTP+"/wp-login.php", "edge.test"); code != 404 || !strings.Contains(body, "IPv64 CDN") {
		t.Fatalf("404: %d %s", code, body)
	}
	if code, body := get(http.DefaultClient, "http://"+cfg.ListenHTTP+"/health", "edge.test"); code != 200 || !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("health: %d %s", code, body)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "edge.test"}, ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, cfg.ListenHTTPS)
		}}
	defer tr.CloseIdleConnections()
	for i := 0; i < 100; i++ { // Port 443 oeffnet nach dem Tunnel
		if c, err := net.Dial("tcp", cfg.ListenHTTPS); err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	code, body := get(&http.Client{Transport: tr, Timeout: 10 * time.Second}, "https://edge.test/", "edge.test")
	if code != 200 || !strings.Contains(body, "Server des IPv64 CDN") {
		t.Fatalf("https: %d %s", code, body)
	}
}
