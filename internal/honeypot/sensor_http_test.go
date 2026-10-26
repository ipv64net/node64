package honeypot

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sensorGet(t *testing.T, cl *http.Client, method, u, ua string, body string, hdr map[string]string) (int, string, http.Header) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", ua)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func TestSensorHTTPBait(t *testing.T) {
	p := sensorFreePort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcHTTP, p, ""}}})
	cl := &http.Client{Timeout: 5 * time.Second}
	base := "http://" + sensorAddrOf(p)
	const browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"

	code, body, h := sensorGet(t, cl, "GET", base+"/wp-login.php", browser, "", nil)
	if code != 200 || !strings.Contains(body, `name="log"`) || !strings.Contains(body, `name="pwd"`) || !strings.HasPrefix(h.Get("Server"), "nginx/1.2") {
		t.Fatalf("Koeder: %d %q %v", code, body, h)
	}
	e := rec.wait(t, func(e Event) bool { return e.Path == "/wp-login.php" })
	if e.Kind != KindHTTPScan || e.Page != "wp-login" || e.Method != "GET" || e.UA != browser || e.Host != sensorAddrOf(p) {
		t.Fatalf("GET: %+v", e)
	}

	form := url.Values{"log": {"admin"}, "pwd": {"secret"}, "wp-submit": {"Log In"}}.Encode()
	code, body, _ = sensorGet(t, cl, "POST", base+"/wp-login.php", browser, form, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if code != 200 || !strings.Contains(body, "Invalid username or password") {
		t.Fatalf("POST: %d %q", code, body)
	}
	e = rec.wait(t, sensorKind(KindHTTPBrute))
	if e.Username != "admin" || e.Password != "secret" || e.Page != "wp-login" || !strings.HasPrefix(string(e.Payload), "log=admin") {
		t.Fatalf("Login: %+v", e)
	}

	code, _, _ = sensorGet(t, cl, "POST", base+"/phpmyadmin/index.php", browser, "pma_username=root&pma_password=toor&server=1", map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	e = rec.wait(t, func(e Event) bool { return e.Kind == KindHTTPBrute && e.Page == "phpmyadmin" })
	if code != 200 || e.Username != "root" || e.Password != "toor" {
		t.Fatalf("phpMyAdmin: %d %+v", code, e)
	}

	// Basic-Auth irgendwo
	req, _ := http.NewRequest("GET", base+"/cgi-bin/luci", nil)
	req.SetBasicAuth("admin", "1234")
	if resp, err := cl.Do(req); err == nil {
		resp.Body.Close()
	}
	rec.wait(t, func(e Event) bool { return e.Kind == KindHTTPBrute && e.Username == "admin" && e.Password == "1234" })

	code, _, _ = sensorGet(t, cl, "GET", base+"/.env", browser, "", nil)
	e = rec.wait(t, func(e Event) bool { return e.Path == "/.env" })
	if code != 403 || e.Kind != KindHTTPExploit || !strings.Contains(e.Detail, "path:/.env") {
		t.Fatalf(".env: %d %+v", code, e)
	}

	code, _, _ = sensorGet(t, cl, "GET", base+"/index.php?id=1%27%20or%20%271%27=%271", browser, "", nil)
	e = rec.wait(t, func(e Event) bool { return strings.HasPrefix(e.Path, "/index.php?id=") })
	if code != 404 || e.Kind != KindHTTPSQLi || e.Page != "" {
		t.Fatalf("SQLi: %d %+v", code, e)
	}

	code, _, _ = sensorGet(t, cl, "GET", base+"/robots.txt", browser, "", nil)
	e = rec.wait(t, func(e Event) bool { return e.Path == "/robots.txt" })
	if code != 404 || e.Kind != KindHTTPScan {
		t.Fatalf("robots: %d %+v", code, e)
	}

	sensorGet(t, cl, "GET", base+"/", "Mozilla/5.0 zgrab/0.x", "", nil)
	e = rec.wait(t, func(e Event) bool { return e.UA == "Mozilla/5.0 zgrab/0.x" })
	if e.Kind != KindBadUA || e.Detail != "ua:zgrab" || e.Page != "generic" {
		t.Fatalf("zgrab: %+v", e)
	}

	ua := "Expanse, a Palo Alto Networks company, searches across the global IPv4 space multiple times per day"
	sensorGet(t, cl, "GET", base+"/", ua, "", nil)
	e = rec.wait(t, func(e Event) bool { return e.UA == ua })
	if e.Kind != KindScannerResch || e.Detail != "research:paloalto-expanse" {
		t.Fatalf("Expanse: %+v", e)
	}
	if s.counters.Logins.Load() != 3 {
		t.Fatalf("Logins = %d", s.counters.Logins.Load())
	}
}

func TestSensorHTTPS(t *testing.T) {
	p := sensorFreePort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcHTTPS, p, "admin"}}})
	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	code, body, _ := sensorGet(t, cl, "GET", "https://localhost:"+strconv.Itoa(p)+"/", "curl/8.5.0", "", nil)
	if code != 200 || !strings.Contains(body, "<title>Administration</title>") {
		t.Fatalf("HTTPS: %d %q", code, body)
	}
	e := rec.wait(t, func(e Event) bool { return e.Kind == KindHTTPScan })
	if e.Service != SvcHTTPS || e.Page != "admin" || e.Host != "localhost:"+strconv.Itoa(p) {
		t.Fatalf("Ereignis: %+v", e)
	}
	for _, f := range []string{"tls-generic.crt", "tls-generic.key"} { // Zertifikat des Profils nginx
		if _, err := os.Stat(filepath.Join(s.dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	// Verbindung ohne Anfrage (TLS-Abbruch) = Probe
	c, err := tls.Dial("tcp", sensorAddrOf(p), &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}})
	if err == nil {
		c.Close()
	}
	rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Service == SvcHTTPS })
}

// Startseite der Falle: Gateway-Terminal mit echtem Formular (POST username/password), Fehlermeldung nach Versuch.
func TestDecoyGatewayPage(t *testing.T) {
	p := sensorPageHTML("generic", false)
	for _, s := range []string{"NODE-07 // Gateway", `<form method="post" action="/">`, `name="username"`, `name="password"`, `noindex`} {
		if !strings.Contains(p, s) {
			t.Errorf("page lacks %q", s)
		}
	}
	if strings.Contains(p, "{{FAILED}}") || strings.Contains(p, "ACCESS DENIED") || strings.Contains(p, "return false") {
		t.Error("placeholder, error or blocked form in fresh page")
	}
	if !strings.Contains(sensorPageHTML("generic", true), "ACCESS DENIED") {
		t.Error("no error after failed login")
	}
	if strings.Contains(sensorPageHTML("admin", false), "NODE-07") {
		t.Error("other decoys must stay neutral")
	}
}

// Startseite einstellbar: Gateway-Terminal (Standard) oder schlicht; gilt ab dem naechsten Apply.
func TestSensorStartPage(t *testing.T) {
	p := sensorFreePort(t)
	cfg := Config{Services: []Service{{SvcHTTP, p, ""}}}
	s, _ := sensorStart(t, cfg)
	cl := &http.Client{Timeout: 5 * time.Second}
	const browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"
	if _, body, _ := sensorGet(t, cl, "GET", "http://"+sensorAddrOf(p)+"/", browser, "", nil); !strings.Contains(body, "NODE-07") {
		t.Fatal("default start page is not the gateway terminal")
	}
	cfg.StartPage = StartNeutral
	s.Apply(context.Background(), cfg, nil)
	_, body, _ := sensorGet(t, cl, "GET", "http://"+sensorAddrOf(p)+"/", browser, "", nil)
	if strings.Contains(body, "NODE-07") || !strings.Contains(body, "<title>Sign in</title>") || !strings.Contains(body, `name="username"`) {
		t.Fatalf("plain start page: %s", body)
	}
	if !strings.Contains(sensorPlainHTML(true), "Invalid username or password") {
		t.Fatal("plain page without error after failed login")
	}
}
