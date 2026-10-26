package honeypot

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
	nodesync "github.com/ipv64net/node64/internal/sync"
	"github.com/ipv64net/node64/internal/web"
)

// loginTest: Modul mit eigener Uhr, Sink und Benachrichtigung; Ueberwachung an wie nach dem Start.
func loginTest(t *testing.T, c LoginConfig) (*Module, *sensorRec, *[]notify.Alert, *time.Time) {
	t.Helper()
	m, _ := modTest(t, modFreePort(t))
	rec := &sensorRec{}
	m.sink = rec.sink
	var mu sync.Mutex
	var alerts []notify.Alert
	m.SetNotifier(func(a notify.Alert) { mu.Lock(); alerts = append(alerts, a); mu.Unlock() })
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	m.login.now = func() time.Time { return now }
	m.login.cfg.Store(&c)
	return m, rec, &alerts, &now
}

func TestLoginRuleThreshold(t *testing.T) {
	m, rec, alerts, now := loginTest(t, LoginConfig{})
	src := netip.MustParseAddr("93.184.215.14")
	fail := func(n int, ip netip.Addr) {
		for range n {
			m.LoginFailed(ip, 8443, true)
		}
	}
	fail(4, src)
	if len(rec.all()) != 0 {
		t.Fatal("event below threshold")
	}
	fail(1, src) // 5. Fehlversuch in 10 min: genau ein Ereignis
	ev := rec.all()
	if len(ev) != 1 {
		t.Fatalf("events: %+v", ev)
	}
	e := ev[0]
	if e.Source != SrcLog || e.Rule != "node64/login@1" || e.Kind != KindHTTPBrute || e.Service != SvcHTTPS || e.Port != 8443 || e.Src != src ||
		e.Username != "" || e.Password != "" || e.Path != "" || e.UA != "" || len(e.Payload) != 0 || !strings.HasPrefix(e.Detail, LoginRuleID) {
		t.Fatalf("event: %+v", e)
	}
	if !bridgeBlockKind(e) { // Sofort-Sperre ueber PROXY64 (wenn dort eingeschaltet)
		t.Fatal("no instant block kind")
	}
	fail(20, src) // im selben Fenster kein weiteres Ereignis
	if len(rec.all()) != 1 {
		t.Fatalf("second event in window: %d", len(rec.all()))
	}
	if len(*alerts) != 1 || (*alerts)[0].Kind != notify.KindHoneypotLogin || !strings.Contains((*alerts)[0].Message, "93.184.215.14") || (*alerts)[0].Check.Name != "Node64" {
		t.Fatalf("alerts: %+v", *alerts)
	}
	// Fenster abgelaufen: neu zaehlen
	*now = now.Add(11 * time.Minute)
	fail(4, src)
	if len(rec.all()) != 1 {
		t.Fatal("event before threshold in new window")
	}
	fail(1, src)
	if len(rec.all()) != 2 {
		t.Fatalf("no event in new window: %d", len(rec.all()))
	}
	// weitere IPs binnen 10 min nach der letzten Benachrichtigung: zurueckgehalten, dann mitgezaehlt
	other := netip.MustParseAddr("2a01:4f8::10")
	*now = now.Add(time.Minute)
	fail(5, other)
	if len(rec.all()) != 3 || len(*alerts) != 2 {
		t.Fatalf("events %d alerts %d", len(rec.all()), len(*alerts))
	}
	*now = now.Add(time.Minute)
	fail(5, netip.MustParseAddr("93.184.215.15"))
	if len(*alerts) != 2 {
		t.Fatalf("notification not throttled: %d", len(*alerts))
	}
	*now = now.Add(10 * time.Minute)
	fail(5, netip.MustParseAddr("93.184.215.16"))
	if len(*alerts) != 3 || !strings.Contains((*alerts)[2].Message, "(+2)") || (*alerts)[2].EventID == (*alerts)[1].EventID {
		t.Fatalf("held back: %+v", *alerts)
	}
	if m.login.events.Load() != 5 || m.login.fails.Load() != 45 {
		t.Fatalf("counters: %d %d", m.login.events.Load(), m.login.fails.Load())
	}
}

// Private, Loopback- und reservierte Adressen nur zaehlen, nie ein Ereignis; aus bzw. Modul aus: nichts.
func TestLoginRuleLocalAndOff(t *testing.T) {
	m, rec, alerts, _ := loginTest(t, LoginConfig{})
	for _, ip := range []string{"192.168.1.5", "127.0.0.1", "::1", "10.0.0.8", "fd00::5", "100.64.1.1", "::ffff:192.168.1.5"} {
		for range 10 {
			m.LoginFailed(netip.MustParseAddr(ip), 8080, false)
		}
	}
	if len(rec.all()) != 0 || len(*alerts) != 0 || m.login.local.Load() != 70 || m.login.fails.Load() != 0 {
		t.Fatalf("local: %d events, local %d", len(rec.all()), m.login.local.Load())
	}
	m.LoginFailed(netip.Addr{}, 8080, false)
	m.login.cfg.Store(&LoginConfig{Off: true})
	for range 10 {
		m.LoginFailed(netip.MustParseAddr("93.184.215.14"), 8080, false)
	}
	m.login.cfg.Store(nil) // Modul aus
	for range 10 {
		m.LoginFailed(netip.MustParseAddr("93.184.215.14"), 8080, false)
	}
	if len(rec.all()) != 0 || m.login.fails.Load() != 0 {
		t.Fatalf("off: %d events", len(rec.all()))
	}
}

// Eigene Schwelle und Fenster, ohne Benachrichtigung; Ereignis landet im Speicher und im Bericht an ipv64.
func TestLoginRuleCustomAndReport(t *testing.T) {
	m, _, alerts, now := loginTest(t, LoginConfig{Threshold: 3, Window: 1, NoNotify: true})
	m.sink = CountEvents(m.st.Sink())
	src := netip.MustParseAddr("93.184.215.14")
	m.LoginFailed(src, 8080, false)
	m.LoginFailed(src, 8080, false)
	*now = now.Add(2 * time.Minute) // Fenster 1 min abgelaufen
	m.LoginFailed(src, 8080, false)
	m.LoginFailed(src, 8080, false)
	if m.login.events.Load() != 0 {
		t.Fatal("event across windows")
	}
	m.LoginFailed(src, 8080, false)
	if m.login.events.Load() != 1 || len(*alerts) != 0 {
		t.Fatalf("events %d alerts %d", m.login.events.Load(), len(*alerts))
	}
	ctx := context.Background()
	if err := m.st.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := storeCountRule(ctx, m.st, LoginRuleTag(), time.Now().Add(-time.Hour)); err != nil || n != 1 {
		t.Fatalf("stored: %d %v", n, err)
	}
	rep, err := m.st.BuildReport(ctx, time.Now().Add(-time.Hour), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Sources) != 1 || rep.Sources[0].Rule != "node64/login@1" || rep.Sources[0].Source != SrcLog || rep.Sources[0].Service != SvcHTTP ||
		rep.Sources[0].IP != "93.184.215.14" || rep.Sources[0].Port != 8080 {
		t.Fatalf("report: %+v", rep.Sources)
	}
	if len(rep.Samples.Credentials) != 0 {
		t.Fatalf("credentials in report: %+v", rep.Samples.Credentials)
	}
	v := m.loginOverview(ctx, LoginConfig{Threshold: 3, Window: 1})
	if v.Day != 1 || v.Week != 1 || v.Threshold != 3 || v.Window != 1 || v.Events != 1 {
		t.Fatalf("overview: %+v", v)
	}
}

func TestLoginConfigValidate(t *testing.T) {
	m, _ := modTest(t, modFreePort(t))
	c := DefaultConfig()
	c.Profile = ProfileMinimal
	for _, lc := range []LoginConfig{{Threshold: 1}, {Threshold: 101}, {Window: -1}, {Window: 1441}} {
		c.Login = lc
		_, err := m.SaveConfig(context.Background(), c)
		var fe FieldErrors
		if !errors.As(err, &fe) || (fe["login_threshold"] == "" && fe["login_window"] == "") {
			t.Errorf("%+v: %v", lc, err)
		}
	}
	c.Login = LoginConfig{Threshold: 10, Window: 30, NoNotify: true}
	if _, err := m.SaveConfig(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if got := m.loadConfig(context.Background()).Login; got != c.Login {
		t.Fatalf("saved: %+v", got)
	}
	// Standard: an, 5 in 10 Minuten
	if thr, win := (LoginConfig{}).limits(); thr != 5 || win != 10*time.Minute {
		t.Fatalf("defaults: %d %v", thr, win)
	}
	// Start uebernimmt die Einstellung, Stop schaltet ab
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p := m.login.cfg.Load(); p == nil || p.Threshold != 10 {
		t.Fatalf("after start: %+v", p)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.login.cfg.Load() != nil {
		t.Fatal("still watching after stop")
	}
}

// Seiten mit Zertifikatsverwaltung und Ueberwachung der Anmeldung im echten Layout: Auswahl, Anlegen, Zeile in der
// Uebersicht, angefragter Name (SNI) in der Ereignisliste; Formular speichert Zertifikat, Ports und Schwellen.
func TestDecoyPagesRender(t *testing.T) {
	st, dir := modCore(t)
	logger := logging.New("error", "text", io.Discard)
	bundle, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	m := New(st, logger.Slog(), dir, "test")
	m.newSensor = func(*slog.Logger, string) sensorAPI { return &modFakeSensor{lns: map[int]net.Listener{}} }
	m.certs = &fakeCerts{domains: []string{"decoy.example"}, dns: true,
		list: []*certs.Cert{{ID: 5, Names: []string{"mail.decoy.example"}, Status: certs.StatusValid, NotAfter: time.Now().Add(48 * time.Hour)}}}
	reg := module.NewRegistry(st, logger.Slog())
	reg.Register(m)
	t.Cleanup(reg.StopAll)
	s, err := web.New(web.Deps{Cfg: &config.Config{DataDir: dir, HTTPPort: 8080, LogLevel: "error"}, Store: st, Log: logger, I18n: bundle, Modules: reg,
		Sync: nodesync.NoOp{}, Version: "test", StartedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	s.SetLoginWatcher(m)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do := func(path string, form url.Values) (int, string) {
		var resp *http.Response
		var err error
		if form == nil {
			resp, err = client.Get(srv.URL + path)
		} else {
			resp, err = client.PostForm(srv.URL+path, form)
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	_, body := do("/setup", nil)
	csrf := csrfRe.FindStringSubmatch(body)
	if code, _ := do("/setup", url.Values{"_csrf": {csrf[1]}, "lang": {"de"}, "username": {"admin"}, "password": {"sehr geheimes passwort"},
		"password2": {"sehr geheimes passwort"}, "timezone": {"Europe/Berlin"}, "node_name": {"pi"}}); code != http.StatusSeeOther {
		t.Fatalf("setup: %d", code)
	}
	if _, err := m.SaveConfig(context.Background(), ModuleConfig{Profile: ProfileCustom, Expert: true, Config: Config{Services: []Service{{Service: SvcHTTPS, Port: modFreePort(t)}}, CertID: 5}}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Enable(context.Background(), Name); err != nil {
		t.Fatal(err)
	}
	m.sink(Event{Time: time.Now(), Service: SvcIMAPS, Port: 993, Kind: KindMailBrute, Src: netip.MustParseAddr("192.0.2.10"), Username: "a", Password: "b", Host: "mail.decoy.example"})
	code, body := do("/honeypot/settings", nil)
	if code != 200 {
		t.Fatalf("settings: %d", code)
	}
	for _, want := range []string{`id="zertifikat"`, `name="cert_id"`, `<option value="5" selected>`, `name="cert_ports"`, `id="cert-create"`, `action="/honeypot/cert"`,
		`<option value="decoy.example">`, `name="login_threshold"`, `name="login_watch" value="1" checked`, `id="anmeldung"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("settings: %q missing", want)
		}
	}
	code, body = do("/honeypot", nil)
	if code != 200 || !strings.Contains(body, `id="login-line"`) || !strings.Contains(body, "mail.decoy.example") {
		t.Fatalf("overview: %d", code)
	}
	csrf = csrfRe.FindStringSubmatch(body)
	v := url.Values{"_csrf": {csrf[1]}, "profile": {"custom"}, "services": {"https " + strconv.Itoa(modFreePort(t))}, "retention_days": {"7"}, "max_events": {"200000"},
		"cert_form": {"1"}, "cert_id": {"5"}, "cert_ports": {"8006, 10000"}, "login_form": {"1"}, "login_threshold": {"8"}, "login_window": {"15"}}
	if code, _ = do("/honeypot/settings", v); code != http.StatusSeeOther {
		t.Fatalf("save: %d", code)
	}
	c := m.loadConfig(context.Background())
	if c.CertID != 5 || !slices.Equal(c.CertPorts, []int{8006, 10000}) || c.Login != (LoginConfig{Off: true, NoNotify: true, Threshold: 8, Window: 15}) {
		t.Fatalf("saved: %+v %+v", c.Config, c.Login)
	}
	v.Set("login_threshold", "1")
	if code, body = do("/honeypot/settings", v); code != http.StatusUnprocessableEntity || !strings.Contains(body, `id="login_threshold" name="login_threshold" min="2" max="100" value="1"`) {
		t.Fatalf("invalid threshold: %d", code)
	}
}
