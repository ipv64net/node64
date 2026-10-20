package honeypot

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/metrics"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/ports"
	"github.com/ipv64net/node64/internal/store"
	nodesync "github.com/ipv64net/node64/internal/sync"
	"github.com/ipv64net/node64/internal/web"
)

// modFakeSensor oeffnet echte TCP-Ports auf 127.0.0.1 (ohne Protokoll), damit an/aus pruefbar ist.
type modFakeSensor struct {
	mu       sync.Mutex
	check    func(string, int) error
	lns      map[int]net.Listener
	status   []ServiceStatus
	counters Counters
}

func (f *modFakeSensor) SetPortCheck(c func(string, int) error) { f.check = c }

func (f *modFakeSensor) Apply(_ context.Context, cfg Config, _ Sink) []ServiceStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	want := map[int]bool{}
	for _, s := range cfg.Services {
		want[s.Port] = true
	}
	for p, ln := range f.lns {
		if !want[p] {
			ln.Close()
			delete(f.lns, p)
		}
	}
	f.status = nil
	for _, s := range cfg.Services {
		st := ServiceStatus{Service: s.Service, Port: s.Port}
		if f.lns[s.Port] == nil {
			if f.check != nil {
				if err := f.check(s.Service, s.Port); err != nil {
					st.Error = err.Error()
					f.status = append(f.status, st)
					continue
				}
			}
			ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(s.Port))
			if err != nil {
				st.Error = err.Error()
				f.status = append(f.status, st)
				continue
			}
			f.lns[s.Port] = ln
		}
		st.Listen = true
		f.status = append(f.status, st)
	}
	return append([]ServiceStatus(nil), f.status...)
}

func (f *modFakeSensor) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for p, ln := range f.lns {
		ln.Close()
		delete(f.lns, p)
	}
	f.status = nil
}

func (f *modFakeSensor) Status() []ServiceStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ServiceStatus(nil), f.status...)
}

func (f *modFakeSensor) Counters() *Counters { return &f.counters }

func modCore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(context.Background(), filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	cm, _ := store.CoreMigrations()
	if err := core.Migrate(context.Background(), "core", cm); err != nil {
		t.Fatal(err)
	}
	return core, dir
}

// modTest legt das Modul mit Fake-Sensor und einer Port-Verwaltung an (Teil "web" belegt webPort aktiv,
// "edge" hat 80 eingestellt, aber nicht offen).
func modTest(t *testing.T, webPort int) (*Module, *ports.Registry) {
	t.Helper()
	core, dir := modCore(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := New(core, log, dir, "test")
	if err := core.Migrate(context.Background(), Name, m.Migrations()); err != nil {
		t.Fatal(err)
	}
	m.newSensor = func(*slog.Logger, string) sensorAPI { return &modFakeSensor{lns: map[int]net.Listener{}} }
	reg := ports.New()
	reg.Provide("web", func(context.Context) []ports.Claim {
		return []ports.Claim{{Purpose: "HTTP", Proto: ports.TCP, Port: webPort, Active: true}}
	})
	reg.Provide("edge", func(context.Context) []ports.Claim {
		return []ports.Claim{{Purpose: "HTTP", Proto: ports.TCP, Port: 80}}
	})
	reg.Provide(Name, m.Claims)
	m.SetPorts(reg)
	m.g = testGuards(nil)
	t.Cleanup(func() { _ = m.Stop(context.Background()) })
	return m, reg
}

type auditEntry struct{ action, target, details string }

func testGuards(audit *[]auditEntry) module.Guards {
	pass := func(h http.Handler) http.Handler { return h }
	return module.Guards{Enabled: pass, Auth: pass,
		T:     func(_ *http.Request, key string, _ ...any) string { return key },
		Actor: func(*http.Request) string { return "tester" },
		Audit: func(_ *http.Request, action, target, details string) {
			if audit != nil {
				*audit = append(*audit, auditEntry{action, target, details})
			}
		},
		Flash: func(http.ResponseWriter, *http.Request, string, string) {},
	}
}

func modFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func portOpen(port int) bool {
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func TestModuleOnOffOpensAndClosesPorts(t *testing.T) {
	m, reg := modTest(t, modFreePort(t))
	ctx := context.Background()
	p1, p2 := modFreePort(t), modFreePort(t)
	if _, err := m.SaveConfig(ctx, ModuleConfig{Profile: ProfileCustom, Config: Config{Services: []Service{{Service: SvcSSH, Port: p1}, {Service: SvcTCP, Port: p2}}}}); err != nil {
		t.Fatal(err)
	}
	// aus: nichts offen, kein Sensor, keine Ports in der Verwaltung
	if m.running() != nil || portOpen(p1) || portOpen(p2) || len(m.Claims(ctx)) != 0 {
		t.Fatal("module off must not open anything")
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !portOpen(p1) || !portOpen(p2) {
		t.Fatalf("ports not open: %+v", m.Status())
	}
	cl := m.Claims(ctx)
	if len(cl) != 2 || !cl[0].Active || cl[0].Owner != Name {
		t.Fatalf("claims: %+v", cl)
	}
	// ein anderer Teil sieht die Ports als belegt
	if err := reg.Check(ctx, "cdn64", []ports.Claim{{Proto: ports.TCP, Port: p1}}); err == nil {
		t.Fatal("port of the honeypot must be a conflict for others")
	}
	// Einstellung im Betrieb aendern: p2 faellt weg
	if _, err := m.SaveConfig(ctx, ModuleConfig{Profile: ProfileCustom, Config: Config{Services: []Service{{Service: SvcSSH, Port: p1}}}}); err != nil {
		t.Fatal(err)
	}
	if !portOpen(p1) || portOpen(p2) {
		t.Fatal("apply must close removed services")
	}
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if portOpen(p1) || m.running() != nil || len(m.Claims(ctx)) != 0 {
		t.Fatal("stop must close everything")
	}
	// Stop zweimal und Start/Stop erneut gehen
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil || !portOpen(p1) {
		t.Fatalf("restart: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	webPort := modFreePort(t)
	m, _ := modTest(t, webPort)
	ctx := context.Background()

	// Standard: Profil standard, 7 Tage
	c := m.loadConfig(ctx)
	if c.Profile != ProfileStandard || c.RetentionDays != 7 || c.MaxEvents != DefaultMaxRows || c.NotifyNew {
		t.Fatalf("defaults: %+v", c)
	}
	// eigene Auswahl mit belegtem Port (Oberflaeche) -> Fehler am Feld services
	_, err := m.SaveConfig(ctx, ModuleConfig{Profile: ProfileCustom, Config: Config{Services: []Service{{Service: SvcSSH, Port: webPort}}}})
	fe, ok := err.(FieldErrors)
	if !ok || !strings.Contains(fe["services"], "honeypot.err.port_used|"+strconv.Itoa(webPort)+"|web") {
		t.Fatalf("port conflict: %v", err)
	}
	if m.loadConfig(ctx).Profile != ProfileStandard {
		t.Fatal("invalid settings must not be saved")
	}
	// weitere Fehler
	bad := ModuleConfig{Profile: ProfileCustom, RetentionDays: 500, MaxEvents: 10, Config: Config{MaxConnsPerIP: -1,
		Services: []Service{{Service: "ftp", Port: 21}, {Service: SvcSSH, Port: 0}, {Service: SvcTCP, Port: 9999}, {Service: SvcSSH, Port: 9999}, {Service: SvcTCP, Port: 9998, Page: "admin"}}}}
	_, err = m.SaveConfig(ctx, bad)
	fe, _ = err.(FieldErrors)
	for _, k := range []string{"retention_days", "max_events", "max_conns_per_ip", "services"} {
		if fe[k] == "" {
			t.Errorf("expected error for %s: %v", k, err)
		}
	}
	for _, s := range []string{"honeypot.err.service|ftp", "honeypot.err.port|0", "honeypot.err.port_twice|9999", "honeypot.err.page|admin"} {
		if !strings.Contains(fe["services"], s) {
			t.Errorf("missing %q in %q", s, fe["services"])
		}
	}
	if _, err := m.SaveConfig(ctx, ModuleConfig{Profile: "huge"}); err == nil {
		t.Fatal("unknown profile accepted")
	}
	if _, err := m.SaveConfig(ctx, ModuleConfig{Profile: ProfileCustom}); err == nil {
		t.Fatal("custom without services accepted")
	}
	// Port 80 hat der Eingang nur eingestellt (nicht offen): erlaubt, aber mit Hinweis
	p := modFreePort(t)
	if _, err := m.SaveConfig(ctx, ModuleConfig{Profile: ProfileCustom, Config: Config{Services: []Service{{Service: SvcHTTP, Port: 80, Page: "wp-login"}, {Service: SvcTCP, Port: p}}}}); err != nil {
		t.Fatal(err)
	}
	svcs, warns := m.resolve(ctx, m.loadConfig(ctx))
	if len(svcs) != 2 || len(warns) != 1 || warns[0].Port != 80 || warns[0].Owner != "edge" || warns[0].Skipped {
		t.Fatalf("resolve custom: %+v %+v", svcs, warns)
	}
	// Profil: Ports, die ein anderer Teil offen hat, fallen weg (mit Hinweis)
	// (hier hat die Oberflaeche 8080 offen, der Eingang 80 nur eingestellt)
	m2, _ := modTest(t, 8080)
	svcs, warns = m2.resolve(ctx, ModuleConfig{Profile: ProfileStandard})
	if len(svcs) != len(Profiles[ProfileStandard])-1 || len(warns) != 2 {
		t.Fatalf("resolve profile: %+v %+v", svcs, warns)
	}
	for _, w := range warns {
		if (w.Port == 8080) != w.Skipped || (w.Port != 8080 && w.Port != 80) {
			t.Fatalf("resolve profile warning: %+v", w)
		}
	}
	// Grenzwerte gehen an den Speicher
	if _, err := m.SaveConfig(ctx, ModuleConfig{Profile: ProfileCustom, RetentionDays: 3, MaxEvents: 5000, Config: Config{Services: []Service{{Service: SvcTCP, Port: p}}}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if time.Duration(m.st.retention.Load()) != 3*24*time.Hour || m.st.maxRows.Load() != 5000 {
		t.Fatal("limits not applied to the store")
	}
}

func TestExportImport(t *testing.T) {
	m, _ := modTest(t, modFreePort(t))
	ctx := context.Background()
	p := modFreePort(t)
	want := ModuleConfig{Profile: ProfileCustom, RetentionDays: 14, MaxEvents: 10000, NotifyNew: true, Config: Config{Scan: true, MaxConnsPerIP: 4,
		Services: []Service{{Service: SvcHTTPS, Port: p, Page: "admin"}}}}
	if _, err := m.SaveConfig(ctx, want); err != nil {
		t.Fatal(err)
	}
	data, err := m.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(data)
	if !strings.Contains(string(raw), `"services":[{"service":"https","port":`+strconv.Itoa(p)+`,"page":"admin"}]`) || !strings.Contains(string(raw), `"notify_new":true`) {
		t.Fatalf("export: %s", raw)
	}
	m2, _ := modTest(t, p) // auf der neuen Node belegt die Oberflaeche genau diesen Port
	if n, err := m2.Import(ctx, raw); n != 1 || err == nil {
		t.Fatalf("import with conflict: %d %v", n, err)
	}
	if c := m2.loadConfig(ctx); c.Profile != ProfileMinimal || c.RetentionDays != 14 || !c.NotifyNew {
		t.Fatalf("import must keep the rest: %+v", c)
	}
	m3, _ := modTest(t, modFreePort(t))
	if n, err := m3.Import(ctx, raw); n != 1 || err != nil {
		t.Fatalf("import: %d %v", n, err)
	}
	if c := m3.loadConfig(ctx); c.Profile != ProfileCustom || len(c.Services) != 1 || c.MaxConnsPerIP != 4 {
		t.Fatalf("import: %+v", c)
	}
}

func modEvents(m *Module) {
	now := time.Now()
	m.sink(Event{Time: now, Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: netip.MustParseAddr("192.0.2.10"), SrcPort: 40000, Username: "root", Password: "toor"})
	m.sink(Event{Time: now, Service: SvcHTTP, Port: 80, Kind: KindHTTPScan, Src: netip.MustParseAddr("198.51.100.7"), Method: "GET", Path: "/.env", UA: "zgrab"})
	m.sink(Event{Time: now, Service: SvcTCP, Port: 3389, Kind: KindProbe, Src: netip.MustParseAddr("192.0.2.10"), Payload: []byte("\x03\x00\x00<script>")})
}

func TestAPI(t *testing.T) {
	m, _ := modTest(t, modFreePort(t))
	var audit []auditEntry
	m.g = testGuards(&audit)
	mux := http.NewServeMux()
	m.apiRoutes(mux, m.g)
	ctx := context.Background()
	if _, err := m.SaveConfig(ctx, ModuleConfig{Profile: ProfileCustom, Config: Config{Services: []Service{{Service: SvcSSH, Port: modFreePort(t)}}}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	modEvents(m)
	do := func(method, path, body string) (int, string) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	code, body := do("GET", "/api/honeypot/status", "")
	var st StatusInfo
	if err := json.Unmarshal([]byte(body), &st); code != 200 || err != nil || !st.Running || st.Profile != ProfileCustom || len(st.Services) != 1 || st.Version != version {
		t.Fatalf("status: %d %s", code, body)
	}
	code, body = do("GET", "/api/honeypot/stats?since=7d", "")
	var stats Stats
	if err := json.Unmarshal([]byte(body), &stats); code != 200 || err != nil || stats.Events != 3 || stats.Sources != 2 || stats.Logins != 1 {
		t.Fatalf("stats: %d %s", code, body)
	}
	if code, _ := do("GET", "/api/honeypot/stats?since=forever", ""); code != 400 {
		t.Fatalf("bad since: %d", code)
	}
	code, body = do("GET", "/api/honeypot/events?limit=2", "")
	var evs []EventView
	if err := json.Unmarshal([]byte(body), &evs); code != 200 || err != nil || len(evs) != 2 || evs[0].PayloadHex != "030000"+"3c7363726970743e" ||
		evs[0].PayloadText != `\x03\x00\x00<script>` {
		t.Fatalf("events: %d %s", code, body)
	}
	// Konfiguration: Teilaenderung, Audit
	p := modFreePort(t)
	code, body = do("PUT", "/api/honeypot/config", `{"profile":"custom","services":[{"service":"telnet","port":`+strconv.Itoa(p)+`}],"notify_new":true}`)
	if code != 200 || !strings.Contains(body, `"notify_new":true`) || !strings.Contains(body, `"retention_days":7`) {
		t.Fatalf("put config: %d %s", code, body)
	}
	if len(audit) != 1 || audit[0].action != "honeypot.config" || !strings.Contains(audit[0].details, "telnet/"+strconv.Itoa(p)) {
		t.Fatalf("audit: %+v", audit)
	}
	if !portOpen(p) {
		t.Fatal("PUT config must apply at once")
	}
	code, body = do("PUT", "/api/honeypot/config", `{"profile":"custom","services":[{"service":"ssh","port":70000}]}`)
	if code != 400 || !strings.Contains(body, `"fields"`) || !strings.Contains(body, "honeypot.err.port") {
		t.Fatalf("put invalid: %d %s", code, body)
	}
	if code, _ := do("PUT", "/api/honeypot/config", `{`); code != 400 {
		t.Fatalf("put broken json: %d", code)
	}
	code, body = do("GET", "/api/honeypot/config", "")
	if code != 200 || !strings.Contains(body, `"service":"telnet"`) {
		t.Fatalf("get config: %d %s", code, body)
	}
	// Daten loeschen
	code, body = do("DELETE", "/api/honeypot/events", "")
	if code != 200 || !strings.Contains(body, `"deleted":3`) || audit[len(audit)-1].action != "honeypot.clear" {
		t.Fatalf("clear: %d %s", code, body)
	}
}

func TestMetricsOutput(t *testing.T) {
	m, _ := modTest(t, modFreePort(t))
	ctx := context.Background()
	w := metrics.New()
	m.Metrics(ctx, w)
	var b strings.Builder
	_, _ = w.WriteTo(&b)
	if !strings.Contains(b.String(), "node64_honeypot_up 0") || strings.Contains(b.String(), "connections_total") {
		t.Fatalf("off: %s", b.String())
	}
	p := modFreePort(t)
	if _, err := m.SaveConfig(ctx, ModuleConfig{Profile: ProfileCustom, Config: Config{Services: []Service{{Service: SvcSSH, Port: p}}}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	modEvents(m)
	if err := m.st.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	w = metrics.New()
	m.Metrics(ctx, w)
	b.Reset()
	_, _ = w.WriteTo(&b)
	out := b.String()
	for _, s := range []string{"node64_honeypot_up 1", `node64_honeypot_connections_total{service="ssh",port="` + strconv.Itoa(p) + `"} 0`,
		`node64_honeypot_listen_errors{port="` + strconv.Itoa(p) + `"} 0`, `node64_honeypot_logins_total{service="ssh"}`,
		`node64_honeypot_events_total{kind="generic:probe",source="honeypot"}`, "node64_honeypot_unique_sources 2",
		"node64_honeypot_buffer_events 0", "node64_honeypot_dropped_total 0", "# TYPE node64_honeypot_connections_total counter"} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q in\n%s", s, out)
		}
	}
	if strings.Contains(out, "report_") {
		t.Error("report metrics belong to H2")
	}
	// ohne Sensor und Speicher (Modus ohne Oberflaeche beim Start)
	w = metrics.New()
	WriteMetrics(w, nil, nil, ctx)
	b.Reset()
	if _, err := w.WriteTo(&b); err != nil || !strings.Contains(b.String(), "node64_honeypot_services 0") {
		t.Fatalf("nil: %v %s", err, b.String())
	}
}

func TestNotifyNewSources(t *testing.T) {
	m, _ := modTest(t, modFreePort(t))
	ctx := context.Background()
	var got []notify.Alert
	m.SetNotifier(func(a notify.Alert) { got = append(got, a) })
	since := time.Now().Add(-time.Minute)
	modEvents(m)
	time.Sleep(20 * time.Millisecond) // Uhr unter Windows grob: Stichzeit sicher nach den Ereignissen
	// aus (Standard): keine Meldung
	if m.notifyNew(ctx, since); len(got) != 0 {
		t.Fatal("notification must be off by default")
	}
	c := m.loadConfig(ctx)
	c.NotifyNew = true
	if _, err := m.SaveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	next := m.notifyNew(ctx, since)
	if len(got) != 1 || got[0].Kind != KindNotifyNew || !strings.HasPrefix(got[0].Message, "2 IPs: 192.0.2.10, 198.51.100.7") || !got[0].Check.Local {
		t.Fatalf("alert: %+v", got)
	}
	// dieselben IPs spaeter wieder: nicht neu
	m.sink(Event{Time: time.Now().Add(time.Second), Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: netip.MustParseAddr("192.0.2.10")})
	if m.notifyNew(ctx, next); len(got) != 1 {
		t.Fatalf("known source notified again: %+v", got)
	}
}

func TestRealSensorOpensPorts(t *testing.T) {
	core, dir := modCore(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := New(core, log, dir, "test")
	if err := core.Migrate(context.Background(), Name, m.Migrations()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(context.Background()) })
	ctx := context.Background()
	p := modFreePort(t)
	if _, err := m.SaveConfig(ctx, ModuleConfig{Profile: ProfileCustom, Config: Config{Services: []Service{{Service: SvcTCP, Port: p}}}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	st := m.Status()
	if len(st) == 0 {
		t.Skip("sensor is still a placeholder")
	}
	if !st[0].Listen || !portOpen(p) {
		t.Fatalf("real sensor: %+v", st)
	}
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if ln, err := net.Listen("tcp", ":"+strconv.Itoa(p)); err != nil {
		t.Fatalf("port still in use after stop: %v", err)
	} else {
		ln.Close()
	}
}

var (
	csrfRe    = regexp.MustCompile(`name="_csrf" value="([^"]+)"`)
	tplKeyRe  = regexp.MustCompile(`\.T "([a-z0-9_.]+)"`)
	codeKeyRe = regexp.MustCompile(`"(honeypot\.[a-z0-9_.]+)["|]`)
)

// TestPagesRender rendert die Seiten im echten Layout der Oberflaeche (ohne Template-Fehler) und prueft, dass jeder
// benutzte i18n-Schluessel in den Sprachdateien oder (bis zur Uebernahme) in docs/tmp-honeypot-i18n-modul.json steht.
func TestPagesRender(t *testing.T) {
	st, dir := modCore(t)
	logger := logging.New("error", "text", io.Discard)
	bundle, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	m := New(st, logger.Slog(), dir, "test")
	m.newSensor = func(*slog.Logger, string) sensorAPI { return &modFakeSensor{lns: map[int]net.Listener{}} }
	reg := module.NewRegistry(st, logger.Slog())
	reg.Register(m)
	t.Cleanup(reg.StopAll)
	s, err := web.New(web.Deps{Cfg: &config.Config{DataDir: dir, HTTPPort: 8080, LogLevel: "error"}, Store: st, Log: logger, I18n: bundle, Modules: reg,
		Sync: nodesync.NoOp{}, Version: "test", StartedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(path string) (int, string) {
		resp, err := client.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	post := func(path string, form url.Values) (int, string) {
		resp, err := client.PostForm(srv.URL+path, form)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	_, body := get("/setup")
	csrf := csrfRe.FindStringSubmatch(body)
	if csrf == nil {
		t.Fatal("no csrf")
	}
	if code, _ := post("/setup", url.Values{"_csrf": {csrf[1]}, "lang": {"de"}, "username": {"admin"}, "password": {"sehr geheimes passwort"},
		"password2": {"sehr geheimes passwort"}, "timezone": {"Europe/Berlin"}, "node_name": {"pi"}}); code != http.StatusSeeOther {
		t.Fatalf("setup: %d", code)
	}
	// aus: 404
	if code, _ := get("/honeypot"); code != http.StatusNotFound {
		t.Fatalf("module off: %d", code)
	}
	if _, err := m.SaveConfig(context.Background(), ModuleConfig{Profile: ProfileCustom, Config: Config{Services: []Service{{Service: SvcSSH, Port: modFreePort(t)}}}}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Enable(context.Background(), Name); err != nil {
		t.Fatal(err)
	}
	modEvents(m)
	for _, path := range []string{"/honeypot", "/honeypot?range=7d", "/honeypot/settings"} {
		code, body := get(path)
		if code != 200 || !strings.Contains(body, "/docs/honeypot/#sicherheit") {
			t.Fatalf("%s: %d\n%s", path, code, body)
		}
		if path == "/honeypot" && (!strings.Contains(body, `id="top-credentials"`) || !strings.Contains(body, "root") || !strings.Contains(body, `&lt;script&gt;`)) {
			t.Fatalf("overview content missing:\n%s", body)
		}
	}
	// Formular: Port-Konflikt am Feld (Port 8080 hat hier niemand; 0 ist ungueltig)
	_, body = get("/honeypot/settings")
	csrf = csrfRe.FindStringSubmatch(body)
	code, body := post("/honeypot/settings", url.Values{"_csrf": {csrf[1]}, "profile": {"custom"}, "services": {"ssh 0"}, "retention_days": {"7"}, "max_events": {"200000"}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "is-invalid") {
		t.Fatalf("invalid form: %d", code)
	}
	p := modFreePort(t)
	code, _ = post("/honeypot/settings", url.Values{"_csrf": {csrf[1]}, "profile": {"custom"}, "services": {"tcp " + strconv.Itoa(p)}, "scan": {"1"}, "retention_days": {"7"}, "max_events": {"200000"}})
	if code != http.StatusSeeOther || !portOpen(p) {
		t.Fatalf("save form: %d", code)
	}

	// i18n-Schluessel: Templates und Go-Dateien des Moduls
	keys := map[string]bool{"nav.honeypot": true, "notify.subject." + string(KindNotifyNew): true, "audit.actions.honeypot_config": true, "audit.actions.honeypot_clear": true}
	files, _ := filepath.Glob("templates/pages/*.html")
	gofiles, _ := filepath.Glob("*.go")
	for _, f := range append(files, gofiles...) {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		re := codeKeyRe
		if strings.HasSuffix(f, ".html") {
			re = tplKeyRe
		}
		for _, mm := range re.FindAllStringSubmatch(string(b), -1) {
			if !strings.HasSuffix(mm[1], ".") && mm[1] != setConfig && mm[1] != "honeypot.clear" {
				keys[mm[1]] = true
			}
		}
	}
	for _, p := range []string{ProfileMinimal, ProfileStandard, ProfileFull, ProfileCustom} {
		keys["honeypot.profile."+p] = true
	}
	tmp := map[string]map[string]string{}
	if b, err := os.ReadFile(filepath.Join("..", "..", "docs", "tmp-honeypot-i18n-modul.json")); err == nil {
		if err := json.Unmarshal(b, &tmp); err != nil {
			t.Fatalf("tmp i18n: %v", err)
		}
	}
	for k := range keys {
		for _, lang := range []string{"de", "en"} {
			if bundle.T(lang, k) == k && tmp[lang][k] == "" {
				t.Errorf("%s: missing i18n key %s", lang, k)
			}
		}
	}
}
