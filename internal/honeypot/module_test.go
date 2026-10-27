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
	m.newLogs = func(*slog.Logger) logSensorAPI { return &modFakeLogs{} }
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

	// Standard: nur ueber PROXY64 (keine eigenen Ports), 7 Tage
	c := m.loadConfig(ctx)
	if c.Profile != ProfileProxy || c.RetentionDays != 7 || c.MaxEvents != DefaultMaxRows || c.NotifyNew {
		t.Fatalf("defaults: %+v", c)
	}
	// eigene Auswahl mit belegtem Port (Oberflaeche) -> Fehler am Feld services
	_, err := m.SaveConfig(ctx, ModuleConfig{Profile: ProfileCustom, Config: Config{Services: []Service{{Service: SvcSSH, Port: webPort}}}})
	fe, ok := err.(FieldErrors)
	if !ok || !strings.Contains(fe["services"], "honeypot.err.port_used|"+strconv.Itoa(webPort)+"|web") {
		t.Fatalf("port conflict: %v", err)
	}
	if m.loadConfig(ctx).Profile != ProfileProxy {
		t.Fatal("invalid settings must not be saved")
	}
	// weitere Fehler
	bad := ModuleConfig{Profile: ProfileCustom, RetentionDays: 500, MaxEvents: 10, Config: Config{MaxConnsPerIP: -1,
		Services: []Service{{Service: "gopher", Port: 70}, {Service: SvcSSH, Port: 0}, {Service: SvcTCP, Port: 9999}, {Service: SvcSSH, Port: 9999}, {Service: SvcTCP, Port: 9998, Page: "admin"}}}}
	_, err = m.SaveConfig(ctx, bad)
	fe, _ = err.(FieldErrors)
	for _, k := range []string{"retention_days", "max_events", "max_conns_per_ip", "services"} {
		if fe[k] == "" {
			t.Errorf("expected error for %s: %v", k, err)
		}
	}
	for _, s := range []string{"honeypot.err.service|gopher", "honeypot.err.port|0", "honeypot.err.port_twice|9999", "honeypot.err.page|admin"} {
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
		evs[0].PayloadText != `\x03\x00\x00<script>` || evs[0].Source != SrcHoneypot || !strings.Contains(body, `"source":"honeypot"`) {
		t.Fatalf("events: %d %s", code, body)
	}
	// Filter nach Quelle (H5); Zustand des Log-Sensors im Status
	if code, body := do("GET", "/api/honeypot/events?source=log", ""); code != 200 || strings.TrimSpace(body) != "[]" {
		t.Fatalf("events source=log: %d %s", code, body)
	}
	if code, _ := do("GET", "/api/honeypot/events?source=bogus", ""); code != 400 {
		t.Fatalf("events bad source: %d", code)
	}
	if !strings.Contains(stats.BySource[0].Key, SrcHoneypot) || st.Logs.Files == nil {
		t.Fatalf("by_source / logs: %+v %+v", stats.BySource, st.Logs)
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
	for _, s := range []string{"node64_honeypot_report_last_success_timestamp 0", "node64_honeypot_report_errors_total 0", "node64_honeypot_report_sources_total 0"} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q in\n%s", s, out)
		}
	}
	// ohne Sensor und Speicher (Modus ohne Oberflaeche beim Start)
	w = metrics.New()
	WriteMetrics(w, nil, nil, nil, ctx)
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
		if path == "/honeypot" && (!strings.Contains(body, `id="top-countries"`) || !strings.Contains(body, `id="targets-services"`) ||
			!strings.Contains(body, `id="targets-kinds"`) || !strings.Contains(body, "bg-danger") || strings.Contains(body, "\U0001F1E9\U0001F1EA")) {
			t.Fatalf("overview without country data:\n%s", body)
		}
		if path == "/honeypot" && (!strings.Contains(body, `id="hp-map"`) || strings.Contains(body, `<svg class="hp-map"`)) {
			t.Fatalf("map without country data must show a note only:\n%s", body)
		}
	}
	// mit Laenderdaten: Flaggen an IPs (Ereignisse, Top-Quellen) und Rangliste nach Land
	fakeCountries(t, map[string]string{"192.0.2.0/24": "DE", "198.51.100.0/24": "US"})
	if code, body := get("/honeypot"); code != 200 || strings.Count(body, "\U0001F1E9\U0001F1EA") < 3 || !strings.Contains(body, "\U0001F1FA\U0001F1F8") ||
		!strings.Contains(body, "Deutschland") || !strings.Contains(body, `progress-bar bg-primary`) {
		t.Fatalf("overview with country data: %d\n%s", code, body)
	}
	// Laenderkarte: Laender mit Angriffen verlinkt und eingefaerbt, Legende; Filter der Ereignisliste nach Land
	if code, body := get("/honeypot?range=7d&source=honeypot"); code != 200 || !strings.Contains(body, `<svg class="hp-map"`) ||
		!strings.Contains(body, `href="/honeypot?country=DE&amp;range=7d&amp;source=honeypot#events"`) || !strings.Contains(body, `class="hp-m5"`) ||
		!strings.Contains(body, `class="hp-m0"`) || !strings.Contains(body, `class="hp-sw hp-m5"`) || !strings.Contains(body, "<title>\U0001F1E9\U0001F1EA Deutschland: ") {
		t.Fatalf("map: %d\n%s", code, body)
	}
	if code, body := get("/honeypot?country=us"); code != 200 || !strings.Contains(body, `class="hp-m1 hp-sel"`) || !strings.Contains(body, `href="/honeypot?country=US&amp;source=log"`) ||
		!strings.Contains(body[strings.Index(body, `id="events"`):], `id="events-country"`) || !strings.Contains(body[strings.Index(body, `id="events"`):], "198.51.100.7") ||
		strings.Contains(body[strings.Index(body, `id="events"`):], "192.0.2.10") {
		t.Fatalf("country filter: %d\n%s", code, body)
	}
	if code, body := get("/honeypot?country=1x"); code != 200 || strings.Contains(body, `id="events-country"`) {
		t.Fatalf("invalid country filter: %d", code)
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
	// Log-Sensor: Vorschlag per Knopf (nicht gespeichert), ungueltiger Pfad am Feld, gueltig gespeichert (H5)
	form := url.Values{"_csrf": {csrf[1]}, "profile": {"custom"}, "services": {"tcp " + strconv.Itoa(p)}, "retention_days": {"7"}, "max_events": {"200000"},
		"log_path": {"/host/log/nginx/access.log", ""}, "log_format": {"nginx", ""}, "syslog_port": {""}, "syslog_allow": {""}}
	form.Set("log_suggest", "0")
	code, body = post("/honeypot/settings", form)
	if code != 200 || !strings.Contains(body, `value="/host/log/auth.log"`) || !strings.Contains(body, `value="/host/log/nginx/access.log"`) {
		t.Fatalf("suggest: %d", code)
	}
	if l := m.loadConfig(context.Background()).Log; len(l.Files) != 0 {
		t.Fatalf("suggestion must not be saved: %+v", l)
	}
	form.Del("log_suggest")
	form["log_path"] = []string{"/etc/passwd"}
	form["log_format"] = []string{""}
	if code, body = post("/honeypot/settings", form); code != http.StatusUnprocessableEntity || !strings.Contains(body, `value="/etc/passwd"`) {
		t.Fatalf("invalid log path: %d", code)
	}
	form["log_path"] = []string{"/host/log/auth.log", "/host/log/nginx/access.log", ""}
	form["log_format"] = []string{"syslog", "nginx", ""}
	form.Set("syslog_allow", "192.168.1.0/24\n10.0.0.1")
	if code, _ = post("/honeypot/settings", form); code != http.StatusSeeOther {
		t.Fatalf("save logs: %d", code)
	}
	if l := m.loadConfig(context.Background()).Log; len(l.Files) != 2 || l.Files[1].Format != "nginx" || strings.Join(l.SyslogAllow, ",") != "192.168.1.0/24,10.0.0.1/32" {
		t.Fatalf("saved logs: %+v", l)
	}
	// Entfernen per Knopf: Zeile weg und gleich gespeichert
	if code, _ = post("/honeypot/settings", url.Values{"_csrf": {csrf[1]}, "ui_mode": {"expert"}}); code != http.StatusSeeOther {
		t.Fatalf("expert mode: %d", code)
	}
	if _, body = get("/honeypot/settings"); !strings.Contains(body, `name="log_remove" value="/host/log/auth.log"`) {
		t.Fatal("remove button missing")
	}
	form.Set("log_remove", "/host/log/auth.log")
	if code, _ = post("/honeypot/settings", form); code != http.StatusSeeOther {
		t.Fatalf("remove log: %d", code)
	}
	form.Del("log_remove")
	if l := m.loadConfig(context.Background()).Log; len(l.Files) != 1 || l.Files[0].Path != "/host/log/nginx/access.log" {
		t.Fatalf("removed logs: %+v", l)
	}
	for _, path := range []string{"/honeypot/settings", "/honeypot?source=log", "/honeypot?source=bogus&range=7d"} {
		if code, body := get(path); code != 200 || !strings.Contains(body, "logs") {
			t.Fatalf("%s: %d", path, code)
		}
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
			if !strings.HasSuffix(mm[1], ".") && mm[1] != setConfig && mm[1] != setSensorID && mm[1] != setReportState && mm[1] != "honeypot.clear" {
				keys[mm[1]] = true
			}
		}
	}
	for _, p := range []string{ProfileMinimal, ProfileStandard, ProfileFull, ProfileCustom} {
		keys["honeypot.profile."+p] = true
	}
	for _, s := range []string{SrcHoneypot, SrcLog, SrcSyslog} {
		keys["honeypot.origin."+s] = true
	}
	tmp := map[string]map[string]string{"de": {}, "en": {}}
	frags, _ := filepath.Glob(filepath.Join("..", "..", "docs", "tmp-*i18n*.json")) // Fragmente bis zur Uebernahme
	for _, name := range frags {
		if b, err := os.ReadFile(name); err == nil {
			var x map[string]map[string]string
			if err := json.Unmarshal(b, &x); err != nil {
				t.Fatalf("tmp i18n %s: %v", name, err)
			}
			for lang, m := range x {
				for k, v := range m {
					if tmp[lang] == nil {
						tmp[lang] = map[string]string{}
					}
					tmp[lang][k] = v
				}
			}
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

// Eingeschaltet, aber nie eingestellt: nichts oeffnen (auch nicht das Standardprofil), bis die Auswahl gespeichert ist.
func TestModuleUnconfiguredOpensNothing(t *testing.T) {
	m, _ := modTest(t, modFreePort(t))
	ctx := context.Background()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer m.Stop(ctx) //nolint:errcheck
	if st := m.Status(); len(st) != 0 || len(m.Claims(ctx)) != 0 {
		t.Fatalf("unconfigured module must not open services: %+v", st)
	}
	p := modFreePort(t)
	if _, err := m.SaveConfig(ctx, ModuleConfig{Profile: ProfileCustom, Config: Config{Services: []Service{{Service: SvcTCP, Port: p}}}}); err != nil {
		t.Fatal(err)
	}
	if !portOpen(p) {
		t.Fatalf("after saving the port must be open: %+v", m.Status())
	}
}

// modFakeLogs ersetzt den Log-Sensor: merkt sich die Einstellung, meldet Dateien als gelesen und Syslog als offen.
type modFakeLogs struct {
	mu      sync.Mutex
	cfg     LogConfig
	applies int
	stopped bool
	sink    Sink
}

func (f *modFakeLogs) Apply(_ context.Context, cfg LogConfig, sink Sink) LogStatus {
	f.mu.Lock()
	f.cfg, f.sink = cfg, sink
	f.applies++
	f.mu.Unlock()
	return f.Status()
}

func (f *modFakeLogs) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped, f.cfg = true, LogConfig{}
}

func (f *modFakeLogs) Status() LogStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := LogStatus{Files: []LogFileStatus{}}
	for _, x := range f.cfg.Files {
		fs := LogFileStatus{Path: x.Path, Format: x.Format, OK: !strings.Contains(x.Path, "secure"), Lines: 3}
		if !fs.OK {
			fs.Error = "open " + x.Path + ": permission denied"
		}
		st.Files = append(st.Files, fs)
	}
	if f.cfg.SyslogPort > 0 {
		st.Syslog = &SyslogStatus{Port: f.cfg.SyslogPort, UDP: true, TCP: true, Messages: 5, Denied: 1}
	}
	return st
}

func modLogs(t *testing.T, m *Module) *modFakeLogs {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.logs.(*modFakeLogs)
	if !ok {
		t.Fatal("no fake log sensor (module off?)")
	}
	return f
}

// TestModuleLogConfig: Pruefung der Log-Einstellung (Pfade, Wurzeln, Formate, Anzahl, Syslog-Port gegen andere Teile
// und eigene Fallen, erlaubte Absender) (H5).
func TestModuleLogConfig(t *testing.T) {
	webPort := modFreePort(t)
	m, reg := modTest(t, webPort)
	ctx := context.Background()
	reg.Provide("dns64", func(context.Context) []ports.Claim {
		return []ports.Claim{{Purpose: "DNS", Proto: ports.UDP, Port: 5353, Active: true}}
	})
	p := modFreePort(t)
	base := func(l LogConfig) ModuleConfig {
		return ModuleConfig{Profile: ProfileCustom, Config: Config{Services: []Service{{Service: SvcTCP, Port: p}}, Log: l}}
	}
	cases := []struct {
		log   LogConfig
		field string
		want  string
	}{
		{LogConfig{Files: []LogFile{{Path: "auth.log"}}}, "log_files", "honeypot.err.log_path|auth.log"},
		{LogConfig{Files: []LogFile{{Path: "/host/log/../../etc/shadow"}}}, "log_files", "honeypot.err.log_path|"},
		{LogConfig{Files: []LogFile{{Path: "/etc/shadow"}}}, "log_files", "honeypot.err.log_root|/etc/shadow"},
		{LogConfig{Files: []LogFile{{Path: "/data/node64.db"}}}, "log_files", "honeypot.err.log_root|"},
		{LogConfig{Files: []LogFile{{Path: "/host/log"}}}, "log_files", "honeypot.err.log_root|"},
		{LogConfig{Files: []LogFile{{Path: "/host/log/[x"}}}, "log_files", "honeypot.err.log_path|"},
		{LogConfig{Files: []LogFile{{Path: "/host/log/a.log", Format: "exotic"}}}, "log_files", "honeypot.err.log_format|exotic"},
		{LogConfig{Files: []LogFile{{Path: "/host/log/a.log"}, {Path: "/host/log//a.log"}}}, "log_files", "honeypot.err.log_twice|/host/log/a.log"},
		{LogConfig{SyslogPort: 70000}, "syslog_port", "honeypot.err.syslog_port"},
		{LogConfig{SyslogPort: p}, "syslog_port", "honeypot.err.syslog_trap|" + strconv.Itoa(p)},
		{LogConfig{SyslogPort: webPort}, "syslog_port", "honeypot.err.port_used|" + strconv.Itoa(webPort) + "/tcp|web"},
		{LogConfig{SyslogPort: 5353}, "syslog_port", "honeypot.err.port_used|5353/udp|dns64"},
		{LogConfig{SyslogAllow: []string{"10.0.0.0/33"}}, "syslog_allow", "honeypot.err.syslog_allow|10.0.0.0/33"},
	}
	for _, c := range cases {
		_, err := m.SaveConfig(ctx, base(c.log))
		fe, _ := err.(FieldErrors)
		if !strings.Contains(fe[c.field], c.want) {
			t.Errorf("%+v: want %q in %s, got %v", c.log, c.want, c.field, err)
		}
	}
	var many []LogFile
	for i := 0; i <= LogMaxFiles; i++ {
		many = append(many, LogFile{Path: "/host/log/f" + strconv.Itoa(i) + ".log"})
	}
	if _, err := m.SaveConfig(ctx, base(LogConfig{Files: many})); err == nil || !strings.Contains(err.Error(), "honeypot.err.log_many") {
		t.Errorf("too many files: %v", err)
	}
	// beim Profil zaehlen dessen Ports als eigene Fallen
	if _, err := m.SaveConfig(ctx, ModuleConfig{Profile: ProfileMinimal, Config: Config{Log: LogConfig{SyslogPort: 22}}}); err == nil {
		t.Error("syslog port on a trap port of the profile accepted")
	}
	// gueltig: normalisiert gespeichert
	sp := modFreePort(t)
	saved, err := m.SaveConfig(ctx, base(LogConfig{Files: []LogFile{{Path: " /host/log/auth.log ", Format: "SYSLOG"}, {Path: ""}, {Path: "/var/log/nginx/*.log", Format: "auto"},
		{Path: "/data/logs/app/vaultwarden.log", Format: "vaultwarden"}}, SyslogPort: sp, SyslogAllow: []string{" 192.168.1.1 ", "10.1.2.3/8", "", "::ffff:10.0.0.0/104"}}))
	if err != nil {
		t.Fatal(err)
	}
	l := m.loadConfig(ctx).Log
	if len(l.Files) != 3 || l.Files[0] != (LogFile{Path: "/host/log/auth.log", Format: "syslog"}) || l.Files[1] != (LogFile{Path: "/var/log/nginx/*.log"}) ||
		l.SyslogPort != sp || strings.Join(l.SyslogAllow, " ") != "192.168.1.1/32 10.0.0.0/8" || saved.Log.SyslogPort != sp {
		t.Fatalf("normalized: %+v", l)
	}
	if !strings.Contains(configDetails(saved), "logs=3 syslog="+strconv.Itoa(sp)) {
		t.Errorf("audit details: %s", configDetails(saved))
	}
}

// TestModuleLogSensor: Log-Sensor startet mit dem Modul (gleiche Sink), nichts vor dem ersten Speichern, Syslog als
// Claim (UDP und TCP), Zustand in API und Prometheus, Stop beendet ihn, Export/Import mit Log (H5).
func TestModuleLogSensor(t *testing.T) {
	m, reg := modTest(t, modFreePort(t))
	ctx := context.Background()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	f := modLogs(t, m)
	if f.applies != 1 || len(f.cfg.Files) != 0 || f.cfg.SyslogPort != 0 {
		t.Fatalf("unconfigured: nothing may open: %+v", f.cfg)
	}
	sp := modFreePort(t)
	c := ModuleConfig{Profile: ProfileCustom, Config: Config{Services: []Service{{Service: SvcTCP, Port: modFreePort(t)}},
		Log: LogConfig{Files: []LogFile{{Path: "/host/log/auth.log", Format: "syslog"}, {Path: "/host/log/secure"}}, SyslogPort: sp}}}
	if _, err := m.SaveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	if f.applies != 2 || len(f.cfg.Files) != 2 || f.cfg.SyslogPort != sp || f.sink == nil {
		t.Fatalf("applied: %+v", f.cfg)
	}
	// Ereignis ueber die Sink des Log-Sensors landet im Speicher (mit Quelle, ohne Inhalte) und in den Zaehlern
	f.sink(Event{Service: SvcSSH, Port: 22, Kind: KindSSHBrute, Src: netip.MustParseAddr("192.0.2.77"), Source: SrcLog, Rule: "sshd/bruteforce@1", Username: "x"})
	_ = m.st.Flush(ctx)
	if list, err := m.st.RecentBy(ctx, 5, SrcLog); err != nil || len(list) != 1 || list[0].Username != "" || list[0].Rule != "sshd/bruteforce@1" {
		t.Fatalf("log event: %v %+v", err, list)
	}
	// Syslog als Claim fuer UDP und TCP; ein anderer Teil sieht den Port belegt
	var udp, tcp bool
	for _, cl := range m.Claims(ctx) {
		if cl.Port == sp && cl.Active {
			udp = udp || cl.Proto == ports.UDP
			tcp = tcp || cl.Proto == ports.TCP
		}
	}
	if !udp || !tcp {
		t.Fatalf("syslog claims: %+v", m.Claims(ctx))
	}
	if err := reg.Check(ctx, "dns64", []ports.Claim{{Proto: ports.UDP, Port: sp}}); err == nil {
		t.Fatal("syslog port must be reported as used")
	}
	// Zustand in API und Prometheus
	ls := m.LogStatus()
	if len(ls.Files) != 2 || ls.Syslog == nil || ls.Syslog.Port != sp {
		t.Fatalf("status: %+v", ls)
	}
	w := metrics.New()
	m.Metrics(ctx, w)
	var b strings.Builder
	_, _ = w.WriteTo(&b)
	for _, s := range []string{"node64_honeypot_log_lines_total 6", `node64_honeypot_log_file_ok{path="/host/log/auth.log"} 1`,
		`node64_honeypot_log_file_ok{path="/host/log/secure"} 0`, "node64_honeypot_syslog_messages_total 5", "node64_honeypot_syslog_denied_total 1",
		`node64_honeypot_events_total{kind="ssh:bruteforce",source="log"}`} {
		if !strings.Contains(b.String(), s) {
			t.Errorf("metrics lack %q\n%s", s, b.String())
		}
	}
	// Syslog-Port inzwischen von einem anderen Teil belegt: nicht oeffnen, Fehler im Zustand, Claim nur eingestellt (mit Fehler)
	reg.Provide("cdn64", func(context.Context) []ports.Claim {
		return []ports.Claim{{Purpose: "Stream", Proto: ports.UDP, Port: sp, Active: true}}
	})
	m.apply(ctx)
	if f.cfg.SyslogPort != 0 || m.LogStatus().Syslog == nil || m.LogStatus().Syslog.Error == "" {
		t.Fatalf("syslog port taken: %+v %+v", f.cfg, m.LogStatus().Syslog)
	}
	for _, cl := range m.Claims(ctx) {
		if cl.Port == sp && (cl.Active || cl.Error == "") {
			t.Fatalf("a syslog port that is not open is only set, with the error: %+v", cl)
		}
	}
	// Export enthaelt die Log-Einstellung; Import auf einer Node, auf der der Syslog-Port belegt ist: Syslog aus, Rest bleibt
	data, _ := m.Export(ctx)
	raw, _ := json.Marshal(data)
	if !strings.Contains(string(raw), `"log":{"files":[{"path":"/host/log/auth.log","format":"syslog"},{"path":"/host/log/secure"}],"syslog_port":`+strconv.Itoa(sp)) {
		t.Fatalf("export: %s", raw)
	}
	m2, reg2 := modTest(t, modFreePort(t))
	reg2.Provide("dns64", func(context.Context) []ports.Claim {
		return []ports.Claim{{Purpose: "DNS", Proto: ports.TCP, Port: sp, Active: true}}
	})
	if n, err := m2.Import(ctx, raw); n != 1 || err == nil || !strings.Contains(err.Error(), "syslog_port") {
		t.Fatalf("import with syslog conflict: %d %v", n, err)
	}
	if l := m2.loadConfig(ctx).Log; l.SyslogPort != 0 || len(l.Files) != 2 {
		t.Fatalf("import must keep the files: %+v", l)
	}
	// Stop beendet den Log-Sensor
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.stopped || len(m.LogStatus().Files) != 0 {
		t.Fatal("log sensor not stopped")
	}
}
