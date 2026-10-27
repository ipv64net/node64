package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/firewall"
	"github.com/ipv64net/node64/internal/honeypot"
	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/metrics"
	"github.com/ipv64net/node64/internal/store"
)

func hpEnv(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestHoneypotModeFromEnv(t *testing.T) {
	hc, err := honeypotModeFromEnv(hpEnv(nil))
	if err != nil {
		t.Fatal(err)
	}
	if hc.Profile != "standard" || hc.Custom || !hc.Sensor.Scan || hc.Retention != 7*24*time.Hour || hc.InfoPort != 9064 || hc.InfoToken != "" {
		t.Fatalf("defaults: %+v", hc)
	}
	if len(hc.Sensor.Services) != len(honeypot.Profiles["standard"]) {
		t.Fatalf("standard services: %v", hc.Sensor.Services)
	}
	hc.Sensor.Services[0].Port = 1 // Kopie, das Profil bleibt unveraendert
	if honeypot.Profiles["standard"][0].Port == 1 {
		t.Fatal("profile aliased")
	}

	hc, err = honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_HONEYPOT_PROFILE": "Minimal", "NODE64_HONEYPOT_SCAN": "0",
		"NODE64_HONEYPOT_RETENTION": "48h", "NODE64_HONEYPOT_INFO_PORT": "0", "NODE64_IPV64_KEY": " abcdefgh12345678 "}))
	if err != nil {
		t.Fatal(err)
	}
	if hc.Profile != "minimal" || hc.Sensor.Scan || hc.Retention != 48*time.Hour || hc.InfoPort != 0 || hc.IPv64Key != "abcdefgh12345678" || len(hc.Sensor.Services) != 2 {
		t.Fatalf("minimal: %+v", hc)
	}
	// Meldung an ipv64: an mit Key (Standard), aus mit NODE64_HONEYPOT_REPORT=0 oder ohne Key
	if !hc.Report {
		t.Fatal("report must be on with a key")
	}
	if hc, err = honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_IPV64_KEY": "abcdefgh12345678", "NODE64_HONEYPOT_REPORT": "0",
		"NODE64_IPV64_API": "http://127.0.0.1:1/api/v2"})); err != nil || hc.Report || hc.APIBase != "http://127.0.0.1:1/api/v2" {
		t.Fatalf("report=0: %+v %v", hc, err)
	}
	if hc, err = honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_HONEYPOT_REPORT": "1"})); err != nil || hc.Report {
		t.Fatalf("report without key: %+v %v", hc, err)
	}
	// Standort fuer die Live-Karte: Laendercode (auch Kleinstaaten als fester Punkt), sonst Fehler
	if hc, err = honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_HONEYPOT_COUNTRY": "sg"})); err != nil || hc.Country != "SG" {
		t.Fatalf("country: %+v %v", hc, err)
	}
	if _, err = honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_HONEYPOT_COUNTRY": "XY"})); err == nil {
		t.Fatal("unknown country must fail")
	}

	hc, err = honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_HONEYPOT_SERVICES": "ssh:22, ssh:2222,http:80,https:443:wp-login,TCP:3389,",
		"NODE64_HONEYPOT_RETENTION": "3d"}))
	if err != nil {
		t.Fatal(err)
	}
	want := []honeypot.Service{{Service: "ssh", Port: 22}, {Service: "ssh", Port: 2222}, {Service: "http", Port: 80},
		{Service: "https", Port: 443, Page: "wp-login"}, {Service: "tcp", Port: 3389}}
	if !hc.Custom || hc.Retention != 72*time.Hour || len(hc.Sensor.Services) != len(want) {
		t.Fatalf("services: %+v", hc)
	}
	for i := range want {
		if hc.Sensor.Services[i] != want[i] {
			t.Fatalf("service %d: %+v, want %+v", i, hc.Sensor.Services[i], want[i])
		}
	}

	bad := []map[string]string{
		{"NODE64_HONEYPOT_PROFILE": "huge"},
		{"NODE64_HONEYPOT_SERVICES": "gopher:70"},
		{"NODE64_HONEYPOT_SERVICES": "ssh"},
		{"NODE64_HONEYPOT_SERVICES": "ssh:0"},
		{"NODE64_HONEYPOT_SERVICES": "ssh:22,http:22"},
		{"NODE64_HONEYPOT_SERVICES": "ssh:22:wp-login"},
		{"NODE64_HONEYPOT_SERVICES": "http:80:unknown"},
		{"NODE64_HONEYPOT_SERVICES": " , "},
		{"NODE64_HONEYPOT_SCAN": "maybe"},
		{"NODE64_HONEYPOT_RETENTION": "10m"},
		{"NODE64_HONEYPOT_RETENTION": "x"},
		{"NODE64_HONEYPOT_RETENTION": "400d"},
		{"NODE64_HONEYPOT_INFO_PORT": "70000"},
		{"NODE64_HONEYPOT_SERVICES": "tcp:9064"}, // Info-Port ist auch Fallen-Port
		{"NODE64_HONEYPOT_INFO_TOKEN": "short"},
		{"NODE64_HONEYPOT_REPORT": "maybe"},
		{"NODE64_IPV64_KEY": "abc"}, // Meldung an, Key ungueltig
	}
	for _, m := range bad {
		if _, err := honeypotModeFromEnv(hpEnv(m)); err == nil {
			t.Errorf("%v: expected error", m)
		}
	}
}

func TestRunModeUnknown(t *testing.T) {
	if err := runMode(&config.Config{}, "router"); err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

// fakeSensor fuer den Info-Server.
type fakeSensor struct {
	status []honeypot.ServiceStatus
	c      honeypot.Counters
}

func (f *fakeSensor) Status() []honeypot.ServiceStatus { return f.status }
func (f *fakeSensor) Counters() *honeypot.Counters     { return &f.c }

func newTestHPInfo(t *testing.T, token string) (*hpInfo, *fakeSensor) {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	core, _ := store.CoreMigrations()
	if err := st.Migrate(ctx, "core", core); err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx, honeypot.Name, honeypot.Migrations()); err != nil {
		t.Fatal(err)
	}
	hs := honeypot.NewStore(st, log)
	sink := hs.Sink()
	sink(honeypot.Event{Service: honeypot.SvcSSH, Port: 22, Kind: honeypot.KindSSHBrute, Src: netip.MustParseAddr("192.0.2.7"), Username: "root", Password: "<b>x</b>"})
	sink(honeypot.Event{Service: honeypot.SvcHTTP, Port: 80, Kind: honeypot.KindHTTPScan, Src: netip.MustParseAddr("198.51.100.3"), Method: "GET", Path: "/.env", UA: "evil‮bot"})
	if err := hs.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	fs := &fakeSensor{status: []honeypot.ServiceStatus{{Service: "ssh", Port: 22, Listen: true, Conns: 5}, {Service: "http", Port: 80, Error: "permission denied"}}}
	fs.c.Logins.Store(3)
	hc := &hpModeConfig{Profile: "minimal", InfoPort: 9064, InfoToken: token, Sensor: honeypot.Config{Services: honeypot.Profiles["minimal"], Scan: true}}
	rep := honeypot.NewReporter(honeypot.ReporterConfig{Store: hs, Mode: "headless", Version: "1.2.3", Log: log,
		API:      func(context.Context) (*ipv64api.Client, string) { return nil, "" },
		Enabled:  func(context.Context) bool { return false },
		SensorID: func(context.Context) (string, error) { return honeypot.SensorIDFromFile(dir) },
		State:    honeypot.FileReportState(dir)})
	return newHPInfo(hc, fs, hs, st, rep, "1.2.3"), fs
}

func hpDo(h http.Handler, method, target, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHPInfoAccess(t *testing.T) {
	h, _ := newTestHPInfo(t, "")
	for _, remote := range []string{"127.0.0.1:1", "[::1]:1", "192.168.1.5:5555", "10.1.2.3:1", "172.16.0.9:1", "100.64.3.4:1",
		"[fd00::1]:1", "[fe80::1%eth0]:1", "169.254.1.1:1", "[::ffff:192.168.1.1]:1"} {
		if w := hpDo(h, "GET", "/health", remote, nil); w.Code != http.StatusOK {
			t.Errorf("%s: %d", remote, w.Code)
		}
	}
	for _, remote := range []string{"203.0.113.5:1234", "[2001:db8::1]:1", "100.128.0.1:1", "garbage"} {
		if w := hpDo(h, "GET", "/", remote, map[string]string{"X-Forwarded-For": "192.168.1.1", "X-Real-IP": "127.0.0.1"}); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", remote, w.Code)
		}
	}
	// ohne eingestelltes Token hilft auch ein Token nicht
	if w := hpDo(h, "GET", "/?token=", "203.0.113.5:1", map[string]string{"Authorization": "Bearer "}); w.Code != http.StatusForbidden {
		t.Errorf("empty token: %d", w.Code)
	}

	tok := "0123456789abcdef-secret"
	h, _ = newTestHPInfo(t, tok)
	pub := "203.0.113.5:1234"
	if w := hpDo(h, "GET", "/metrics", pub, nil); w.Code != http.StatusForbidden {
		t.Errorf("public without token: %d", w.Code)
	}
	if w := hpDo(h, "GET", "/metrics?token=wrong", pub, nil); w.Code != http.StatusForbidden {
		t.Errorf("public wrong token: %d", w.Code)
	}
	if w := hpDo(h, "GET", "/metrics?token="+tok, pub, nil); w.Code != http.StatusOK {
		t.Errorf("public ?token: %d", w.Code)
	}
	if w := hpDo(h, "GET", "/", pub, map[string]string{"Authorization": "Bearer " + tok}); w.Code != http.StatusOK {
		t.Errorf("public bearer: %d", w.Code)
	}
	if w := hpDo(h, "GET", "/health", "192.168.0.2:1", nil); w.Code != http.StatusOK {
		t.Errorf("private with token configured: %d", w.Code)
	}
	if w := hpDo(h, "POST", "/", "127.0.0.1:1", nil); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST: %d", w.Code)
	}
	if w := hpDo(h, "GET", "/api/health", "127.0.0.1:1", nil); w.Code != http.StatusNotFound {
		t.Errorf("unknown path: %d", w.Code)
	}
}

func TestHPInfoPage(t *testing.T) {
	h, _ := newTestHPInfo(t, "")
	w := hpDo(h, "GET", "/", "127.0.0.1:1", map[string]string{"Accept-Language": "de-DE,de;q=0.9,en;q=0.8"})
	if w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	body := w.Body.String()
	for _, s := range []string{`lang="de"`, "Honeypot64", "1.2.3", "Treffer 24 h", "192.0.2.7", "root:&lt;b&gt;x&lt;/b&gt;", "/.env", "evil·bot",
		"ssh:bruteforce", "permission denied", "Meldung an ipv64", "kein NODE64_IPV64_KEY"} {
		if !strings.Contains(body, s) {
			t.Errorf("page lacks %q", s)
		}
	}
	if strings.Contains(body, "<b>x</b>") || strings.Contains(body, "<script") || strings.Contains(body, "<form") {
		t.Error("page not escaped or has script/form")
	}
	hd := w.Header()
	for k, v := range map[string]string{"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY"} {
		if hd.Get(k) != v {
			t.Errorf("%s = %q", k, hd.Get(k))
		}
	}
	// die CSP erlaubt genau das eingebettete CSS
	i, j := strings.Index(body, "<style>"), strings.Index(body, "</style>")
	sum := sha256.Sum256([]byte(body[i+len("<style>") : j]))
	if !strings.Contains(hd.Get("Content-Security-Policy"), "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") ||
		!strings.Contains(hd.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Errorf("CSP %q does not match the style block", hd.Get("Content-Security-Policy"))
	}
	if w := hpDo(h, "GET", "/", "127.0.0.1:1", map[string]string{"Accept-Language": "fr, en-US"}); !strings.Contains(w.Body.String(), "Hits 24 h") {
		t.Error("english page expected")
	}
	if w := hpDo(h, "HEAD", "/", "127.0.0.1:1", nil); w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Errorf("HEAD: %d %d", w.Code, w.Body.Len())
	}
}

func TestHPInfoMetricsHealth(t *testing.T) {
	h, fs := newTestHPInfo(t, "")
	w := hpDo(h, "GET", "/metrics", "127.0.0.1:1", nil)
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("metrics: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	body := w.Body.String()
	for _, s := range []string{`node64_honeypot_connections_total{service="ssh",port="22"} 5`, `node64_honeypot_listen_errors{port="80"} 1`,
		"node64_honeypot_up 1", "node64_honeypot_unique_sources 2", "node64_honeypot_report_last_success_timestamp 0", "node64_honeypot_report_errors_total 0",
		`node64_honeypot_info{version="1.2.3",profile="minimal"} 1`} {
		if !strings.Contains(body, s) {
			t.Errorf("metrics lack %q\n%s", s, body)
		}
	}
	if w := hpDo(h, "GET", "/health", "127.0.0.1:1", nil); w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "ok" {
		t.Errorf("health: %d %q", w.Code, w.Body.String())
	}
	fs.status = []honeypot.ServiceStatus{{Service: "ssh", Port: 22, Error: "address in use"}}
	if w := hpDo(h, "GET", "/health", "127.0.0.1:1", nil); w.Code != http.StatusServiceUnavailable {
		t.Errorf("health without open service: %d", w.Code)
	}
}

func TestHPHelpers(t *testing.T) {
	for in, want := range map[string]string{"": "en", "de": "de", "en-GB,de": "en", "fr;q=1, de-AT;q=0.5": "de", "*": "en"} {
		if got := hpLang(in); got != want {
			t.Errorf("hpLang(%q) = %q, want %q", in, got, want)
		}
	}
	if got := hpUptime(26*time.Hour + 3*time.Minute + 10*time.Second); got != "1 d 2 h 3 min" {
		t.Errorf("uptime %q", got)
	}
	if got := hpShort(strings.Repeat("ä", 200)); len([]rune(got)) != 121 {
		t.Errorf("short %d", len([]rune(got)))
	}
}

func hpFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestHoneypotRunStartStop(t *testing.T) {
	dir := t.TempDir()
	trap, infoPort := hpFreePort(t), hpFreePort(t)
	hc, err := honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_HONEYPOT_SERVICES": "tcp:" + strconv.Itoa(trap),
		"NODE64_HONEYPOT_INFO_PORT": strconv.Itoa(infoPort), "NODE64_HONEYPOT_SCAN": "0"}))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DataDir: dir, BindAddr: "127.0.0.1"}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- honeypotRun(ctx, cfg, hc, log, func(info string) { ready <- info }) }()
	var info string
	select {
	case info = <-ready:
	case err := <-done:
		t.Fatalf("run ended early: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("run did not become ready")
	}
	if info == "" {
		t.Fatal("info server not started")
	}
	resp, err := http.Get("http://" + info + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), "node64_honeypot_") {
		t.Fatalf("metrics: %d %s", resp.StatusCode, b)
	}
	// /health: 200, sobald der Sensor den Fallen-Port offen hat
	resp, err = http.Get("http://" + info + "/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(trap)), time.Second); err == nil {
		c.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("health with open trap port: %d", resp.StatusCode)
		}
	} else if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("health without open trap port: %d", resp.StatusCode)
	}
	for _, p := range []string{"node64.db", honeypot.Name} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Errorf("%s missing: %v", p, err)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("run did not stop")
	}
	if _, err := net.DialTimeout("tcp", info, time.Second); err == nil {
		t.Error("info port still open after stop")
	}
}

// TestHoneypotRunReport: mit Key ist die Meldung an (Sensor-Kennung und Startpunkt als Datei, Zustand auf Info-Seite
// und in /metrics); mit NODE64_HONEYPOT_REPORT=0 aus, der Startpunkt wird verworfen (nichts nachholen).
func TestHoneypotRunReport(t *testing.T) {
	var hits atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(http.StatusAccepted) }))
	defer api.Close()
	dir := t.TempDir()
	run := func(env map[string]string) (page, metrics string) {
		t.Helper()
		env["NODE64_HONEYPOT_SERVICES"] = "tcp:" + strconv.Itoa(hpFreePort(t))
		env["NODE64_HONEYPOT_INFO_PORT"] = strconv.Itoa(hpFreePort(t))
		env["NODE64_IPV64_API"] = api.URL + "/api/v2"
		hc, err := honeypotModeFromEnv(hpEnv(env))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ready := make(chan string, 1)
		done := make(chan error, 1)
		go func() {
			done <- honeypotRun(ctx, &config.Config{DataDir: dir, BindAddr: "127.0.0.1"}, hc, slog.New(slog.NewTextHandler(io.Discard, nil)), func(info string) { ready <- info })
		}()
		var info string
		select {
		case info = <-ready:
		case err := <-done:
			t.Fatalf("run ended early: %v", err)
		case <-time.After(20 * time.Second):
			t.Fatal("run did not become ready")
		}
		get := func(path string) string {
			req, _ := http.NewRequest(http.MethodGet, "http://"+info+path, nil)
			req.Header.Set("Accept-Language", "de")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return string(b)
		}
		page, metrics = get("/"), get("/metrics")
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		return page, metrics
	}
	page, metrics := run(map[string]string{"NODE64_IPV64_KEY": "abcdefgh12345678"})
	idb, err := os.ReadFile(filepath.Join(dir, honeypot.Name, "sensor_id"))
	id := strings.TrimSpace(string(idb))
	if err != nil || len(id) != 36 {
		t.Fatalf("sensor id: %q %v", idb, err)
	}
	st, _ := honeypot.FileReportState(filepath.Join(dir, honeypot.Name)).Load(context.Background())
	if st.LastEnd.IsZero() || time.Since(st.LastEnd) > time.Minute {
		t.Fatalf("start of the first period: %+v", st)
	}
	if !strings.Contains(page, `<span class="ok">an</span>`) || !strings.Contains(page, id) || !strings.Contains(page, "noch keine") {
		t.Fatalf("info page lacks report state:\n%s", page)
	}
	if !strings.Contains(metrics, "node64_honeypot_report_errors_total 0") || !strings.Contains(metrics, "node64_honeypot_report_sources_total 0") {
		t.Fatalf("metrics:\n%s", metrics)
	}
	page, _ = run(map[string]string{"NODE64_IPV64_KEY": "abcdefgh12345678", "NODE64_HONEYPOT_REPORT": "0"})
	if !strings.Contains(page, "aus (NODE64_HONEYPOT_REPORT=0)") {
		t.Fatalf("info page report off:\n%s", page)
	}
	if st, _ = honeypot.FileReportState(filepath.Join(dir, honeypot.Name)).Load(context.Background()); !st.LastEnd.IsZero() {
		t.Fatalf("last_end must be dropped while reporting is off: %+v", st)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("no report expected within the first minute, got %d", n)
	}
}

// TestHoneypotModeLogsFromEnv: Log-Sensor und Syslog nur aus NODE64_HONEYPOT_LOGS/_SYSLOG_*; Profile schalten ihn
// nicht ein (H5).
func TestHoneypotModeLogsFromEnv(t *testing.T) {
	for _, p := range []string{"minimal", "standard", "full"} {
		hc, err := honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_HONEYPOT_PROFILE": p}))
		if err != nil || len(hc.Sensor.Log.Files) != 0 || hc.Sensor.Log.SyslogPort != 0 {
			t.Fatalf("profile %s must not enable the log sensor: %+v %v", p, hc.Sensor.Log, err)
		}
	}
	hc, err := honeypotModeFromEnv(hpEnv(map[string]string{
		"NODE64_HONEYPOT_LOGS":         " /host/log/auth.log=syslog, /host/log/nginx/*access.log=NGINX,/var/log/x/../mail.log ,",
		"NODE64_HONEYPOT_SYSLOG_PORT":  "514",
		"NODE64_HONEYPOT_SYSLOG_ALLOW": "192.168.1.1, 10.0.0.0/8 fd00::/8",
	}))
	if err == nil {
		t.Fatal(".. in a path must be rejected")
	}
	hc, err = honeypotModeFromEnv(hpEnv(map[string]string{
		"NODE64_HONEYPOT_LOGS":         " /host/log/auth.log=syslog, /host/log/nginx/*access.log=NGINX,/var/log/mail.log ,",
		"NODE64_HONEYPOT_SYSLOG_PORT":  "514",
		"NODE64_HONEYPOT_SYSLOG_ALLOW": "192.168.1.1, 10.0.0.0/8 fd00::/8",
	}))
	if err != nil {
		t.Fatal(err)
	}
	lc := hc.Sensor.Log
	want := []honeypot.LogFile{{Path: "/host/log/auth.log", Format: "syslog"}, {Path: "/host/log/nginx/*access.log", Format: "nginx"}, {Path: "/var/log/mail.log"}}
	if len(lc.Files) != len(want) || lc.SyslogPort != 514 || strings.Join(lc.SyslogAllow, " ") != "192.168.1.1/32 10.0.0.0/8 fd00::/8" {
		t.Fatalf("logs: %+v", lc)
	}
	for i := range want {
		if lc.Files[i] != want[i] {
			t.Fatalf("file %d: %+v, want %+v", i, lc.Files[i], want[i])
		}
	}
	bad := []map[string]string{
		{"NODE64_HONEYPOT_LOGS": "auth.log"},               // nicht absolut
		{"NODE64_HONEYPOT_LOGS": "/etc/shadow"},            // ausserhalb der Wurzeln
		{"NODE64_HONEYPOT_LOGS": "/data/node64.db"},        // ausserhalb der Wurzeln
		{"NODE64_HONEYPOT_LOGS": "/host/log/a.log=exotic"}, // Format unbekannt
		{"NODE64_HONEYPOT_LOGS": "/host/log/a.log,/host/log/a.log"},
		{"NODE64_HONEYPOT_SYSLOG_PORT": "70000"},
		{"NODE64_HONEYPOT_SYSLOG_PORT": "x"},
		{"NODE64_HONEYPOT_SYSLOG_PORT": "22"},   // Fallen-Port (Profil standard)
		{"NODE64_HONEYPOT_SYSLOG_PORT": "9064"}, // Info-Port
		{"NODE64_HONEYPOT_SYSLOG_ALLOW": "192.168.1.300"},
	}
	for _, m := range bad {
		if _, err := honeypotModeFromEnv(hpEnv(m)); err == nil {
			t.Errorf("%v: expected error", m)
		}
	}
	var many []string
	for i := 0; i <= honeypot.LogMaxFiles; i++ {
		many = append(many, "/host/log/f"+strconv.Itoa(i)+".log")
	}
	if _, err := honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_HONEYPOT_LOGS": strings.Join(many, ",")})); err == nil {
		t.Error("too many files accepted")
	}
}

// fakeLogs fuer den Info-Server.
type fakeLogs struct{ st honeypot.LogStatus }

func (f *fakeLogs) Status() honeypot.LogStatus { return f.st }

func TestHPInfoLogs(t *testing.T) {
	h, _ := newTestHPInfo(t, "")
	// ohne Log-Sensor: Abschnitt zeigt "aus"
	w := hpDo(h, "GET", "/", "127.0.0.1:1", map[string]string{"Accept-Language": "de"})
	if body := w.Body.String(); !strings.Contains(body, "Log-Sensor und Syslog") || !strings.Contains(body, "aus (NODE64_HONEYPOT_SYSLOG_PORT)") {
		t.Fatalf("page without logs:\n%s", body)
	}
	h.logs = &fakeLogs{st: honeypot.LogStatus{Files: []honeypot.LogFileStatus{{Path: "/host/log/auth.log", Format: "syslog", OK: true, Lines: 12},
		{Path: "/host/log/secure", Error: "open /host/log/secure: permission denied"}},
		Syslog: &honeypot.SyslogStatus{Port: 514, UDP: true, TCP: true, Messages: 7, Denied: 2}, Lines: 19}}
	body := hpDo(h, "GET", "/", "127.0.0.1:1", map[string]string{"Accept-Language": "de"}).Body.String()
	for _, s := range []string{"/host/log/auth.log", "wird gelesen", "permission denied", "--group-add 4", "Port 514 UDP TCP", "Nachrichten: 7", "abgewiesen: 2",
		"nur IP, Art, Dienst, Port, Anzahl und Regel"} {
		if !strings.Contains(body, s) {
			t.Errorf("page lacks %q", s)
		}
	}
	body = hpDo(h, "GET", "/metrics", "127.0.0.1:1", nil).Body.String()
	for _, s := range []string{"node64_honeypot_log_lines_total 12", `node64_honeypot_log_file_ok{path="/host/log/auth.log"} 1`,
		`node64_honeypot_log_file_ok{path="/host/log/secure"} 0`, "node64_honeypot_syslog_messages_total 7", "node64_honeypot_syslog_denied_total 2"} {
		if !strings.Contains(body, s) {
			t.Errorf("metrics lack %q\n%s", s, body)
		}
	}
}

func TestHoneypotModeFirewallFromEnv(t *testing.T) {
	hc, err := honeypotModeFromEnv(hpEnv(nil))
	if err != nil || hc.Firewall != nil {
		t.Fatal("firewall on by default", err)
	}
	if hc, err = honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_FIREWALL": "off"})); err != nil || hc.Firewall != nil {
		t.Fatal("off", err)
	}
	tok := "abcdefghijklmnopqrstuvwxyz012345"
	hc, err = honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_FIREWALL": "NFTables", "NODE64_FIREWALL_LISTS": "v64, v64_ssh, spamhaus_drop",
		"NODE64_FIREWALL_ALLOW": "203.0.113.0/24,2001:db8::1", "NODE64_FIREWALL_KEEP": "1", "NODE64_IPV64_LIST_TOKEN": tok}))
	if err != nil {
		t.Fatal(err)
	}
	fc := hc.Firewall
	if fc == nil || fc.Mode != "nftables" || len(fc.Lists) != 2 || fc.Lists[1] != "spamhaus_drop" || len(fc.Allow) != 2 || !fc.Keep || fc.Token != tok {
		t.Fatalf("%+v", fc)
	}
	if hc, err = honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_FIREWALL": "nftables"})); err != nil || hc.Firewall.Lists[0] != "v64" || hc.Firewall.Keep {
		t.Fatalf("defaults: %+v %v", hc.Firewall, err)
	}
	for _, env := range []map[string]string{
		{"NODE64_FIREWALL": "iptables"},
		{"NODE64_FIREWALL": "nftables", "NODE64_FIREWALL_ALLOW": "10.0.0.0/33"},
		{"NODE64_FIREWALL": "nftables", "NODE64_FIREWALL_LISTS": "v64,../x"},
		{"NODE64_FIREWALL": "nftables", "NODE64_FIREWALL_KEEP": "maybe"},
		{"NODE64_IPV64_LIST_TOKEN": "short"},
	} {
		if _, err := honeypotModeFromEnv(hpEnv(env)); err == nil {
			t.Errorf("%v accepted", env)
		}
	}
}

// fakeFW fuer den Info-Server.
type fakeFW struct{ st firewall.Status }

func (f *fakeFW) Status() firewall.Status { return f.st }
func (f *fakeFW) WriteMetrics(w *metrics.Writer) {
	w.Gauge("node64_firewall_entries", "test", float64(f.st.V4), "family", "ipv4")
}

func TestHPInfoFirewall(t *testing.T) {
	h, _ := newTestHPInfo(t, "")
	body := hpDo(h, "GET", "/", "127.0.0.1:1", map[string]string{"Accept-Language": "de"}).Body.String()
	if !strings.Contains(body, "Firewall-Helfer") || !strings.Contains(body, "aus (NODE64_FIREWALL)") {
		t.Fatalf("page without firewall:\n%s", body)
	}
	h.fw = &fakeFW{st: firewall.Status{Mode: "nftables", Active: true, V4: 12, V6: 3, Addresses4: 40, Updated: time.Now(), Changed: time.Now(), Allow: 2,
		Lists: []firewall.ListStatus{{ID: "v64", Edition: "live", Entries: 15}, {ID: "v64_ssh", Edition: "daily", LiveDenied: true, Entries: 4}}}}
	body = hpDo(h, "GET", "/", "127.0.0.1:1", map[string]string{"Accept-Language": "de"}).Body.String()
	for _, s := range []string{"nftables inet node64", "IPv4 12 (40 Adressen) · IPv6 3", "live · 15", "Token ohne Berechtigung", "Tagesstand (ohne NODE64_IPV64_LIST_TOKEN)",
		"beim Beenden gelöscht"} {
		if !strings.Contains(body, s) {
			t.Errorf("page lacks %q", s)
		}
	}
	if body := hpDo(h, "GET", "/metrics", "127.0.0.1:1", nil).Body.String(); !strings.Contains(body, `node64_firewall_entries{family="ipv4"} 12`) {
		t.Errorf("metrics lack firewall:\n%s", body)
	}
}

func TestStartHPFirewallOff(t *testing.T) {
	fw, err := startHPFirewall(context.Background(), &hpModeConfig{}, t.TempDir(), slog.New(slog.DiscardHandler))
	if fw != nil || err != nil {
		t.Fatal(fw, err)
	}
}
