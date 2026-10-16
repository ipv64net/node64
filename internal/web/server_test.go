package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/store"
	nodesync "github.com/ipv64net/node64/internal/sync"
)

var csrfRe = regexp.MustCompile(`name="_csrf" value="([^"]+)"`)

type testApp struct {
	srv      *httptest.Server
	client   *http.Client
	store    *store.Store
	s        *Server
	registry *module.Registry
}

func newTestApp(t *testing.T) *testApp { return newTestAppWith(t) }

func newTestAppWith(t *testing.T, mods ...module.Module) *testApp {
	return newTestAppDeps(t, nil, mods...)
}

// newTestAppDeps: wie newTestAppWith, adjust ergaenzt die Abhaengigkeiten vor New (z. B. Certs).
func newTestAppDeps(t *testing.T, adjust func(*Deps), mods ...module.Module) *testApp {
	t.Helper()
	dir := t.TempDir()
	logger := logging.New("debug", "text", io.Discard)
	st, err := store.Open(context.Background(), filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), logger.Slog())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	core, _ := store.CoreMigrations()
	if err := st.Migrate(context.Background(), "core", core); err != nil {
		t.Fatal(err)
	}
	bundle, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	reg := module.NewRegistry(st, logger.Slog())
	reg.Register(module.Placeholder{I: module.Info{Name: "dyndns", TitleKey: "nav.dyndns", Icon: "bi-globe", Path: "/dyndns"}})
	for _, m := range mods {
		reg.Register(m)
	}
	cfg := &config.Config{DataDir: dir, HTTPPort: 8080, LogLevel: "info"}
	d := Deps{Cfg: cfg, Store: st, Log: logger, I18n: bundle, Modules: reg, Sync: nodesync.NoOp{}, Version: "test", StartedAt: time.Now()}
	if adjust != nil {
		adjust(&d)
	}
	s, err := New(d)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &testApp{srv: srv, client: client, store: st, s: s, registry: reg}
}

func (a *testApp) get(t *testing.T, path string) (*http.Response, string) {
	t.Helper()
	resp, err := a.client.Get(a.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func (a *testApp) post(t *testing.T, path string, form url.Values) (*http.Response, string) {
	t.Helper()
	resp, err := a.client.PostForm(a.srv.URL+path, form)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func csrfOf(t *testing.T, body string) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no csrf token in page")
	}
	return m[1]
}

func TestSetupLoginSettingsFlow(t *testing.T) {
	a := newTestApp(t)

	// Ohne Benutzer fuehrt alles zum Setup
	resp, _ := a.get(t, "/")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/setup" {
		t.Fatalf("expected redirect to /setup, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, body := a.get(t, "/setup")
	if resp.StatusCode != 200 || !strings.Contains(body, `name="node_name"`) {
		t.Fatalf("setup page: %d", resp.StatusCode)
	}
	csrf := csrfOf(t, body)

	// Ohne CSRF-Token: 403
	resp, _ = a.post(t, "/setup", url.Values{"username": {"admin"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("csrf: expected 403, got %d", resp.StatusCode)
	}
	// Zu kurzes Passwort: 422 mit Fehlermarkierung
	resp, body = a.post(t, "/setup", url.Values{"_csrf": {csrf}, "lang": {"de"}, "username": {"admin"}, "password": {"short"}, "password2": {"short"}, "timezone": {"Europe/Berlin"}, "node_name": {"pi"}})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "is-invalid") {
		t.Fatalf("validation: expected 422, got %d", resp.StatusCode)
	}
	// Erfolgreiches Setup meldet direkt an
	resp, _ = a.post(t, "/setup", url.Values{"_csrf": {csrf}, "lang": {"de"}, "username": {"admin"}, "password": {"sehr geheimes passwort"}, "password2": {"sehr geheimes passwort"}, "timezone": {"Europe/Berlin"}, "node_name": {"Pi im Keller"}, "location": {"Zuhause"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("setup: expected redirect to /, got %d", resp.StatusCode)
	}
	resp, body = a.get(t, "/")
	if resp.StatusCode != 200 || !strings.Contains(body, "Pi im Keller") || !strings.Contains(body, "Dashboard") {
		t.Fatalf("dashboard after setup: %d", resp.StatusCode)
	}
	// Setup ist danach gesperrt
	resp, _ = a.get(t, "/setup")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("setup should redirect once done, got %d", resp.StatusCode)
	}

	// Einstellungen: Agent-Name aendern
	resp, body = a.get(t, "/settings")
	csrf = csrfOf(t, body)
	resp, _ = a.post(t, "/settings/node", url.Values{"_csrf": {csrf}, "node_name": {"Neuer Name"}, "location": {"Büro"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("settings/node: %d", resp.StatusCode)
	}
	if v := a.store.SettingOr(context.Background(), SettingNodeName, ""); v != "Neuer Name" {
		t.Fatalf("node name not saved: %q", v)
	}
	// Sprache auf Englisch
	resp, _ = a.post(t, "/settings/user", url.Values{"_csrf": {csrf}, "lang": {"en"}, "timezone": {"UTC"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("settings/user: %d", resp.StatusCode)
	}
	_, body = a.get(t, "/settings")
	if !strings.Contains(body, "Settings") || strings.Contains(body, "Einstellungen") {
		t.Fatal("language switch to English did not apply")
	}
	// Platzhalter-Modul kann nicht aktiviert werden
	resp, _ = a.post(t, "/settings/modules", url.Values{"_csrf": {csrf}, "module": {"dyndns"}, "action": {"enable"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("settings/modules: %d", resp.StatusCode)
	}
	if on, _ := a.store.ModuleEnabled(context.Background(), "dyndns"); on {
		t.Fatal("placeholder module must stay disabled")
	}
	// Passwort aendern, dann abmelden und neu anmelden
	resp, _ = a.post(t, "/settings/password", url.Values{"_csrf": {csrf}, "current": {"sehr geheimes passwort"}, "password": {"noch geheimer 123"}, "password2": {"noch geheimer 123"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("settings/password: %d", resp.StatusCode)
	}
	resp, _ = a.post(t, "/logout", url.Values{"_csrf": {csrf}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	resp, _ = a.get(t, "/settings")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Fatalf("after logout expected redirect to /login, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	_, body = a.get(t, "/login")
	csrf = csrfOf(t, body)
	resp, _ = a.post(t, "/login", url.Values{"_csrf": {csrf}, "username": {"admin"}, "password": {"sehr geheimes passwort"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old password must fail, got %d", resp.StatusCode)
	}
	resp, _ = a.post(t, "/login", url.Values{"_csrf": {csrf}, "username": {"admin"}, "password": {"noch geheimer 123"}, "next": {"/audit"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/audit" {
		t.Fatalf("login: expected redirect to /audit, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, body = a.get(t, "/audit")
	if resp.StatusCode != 200 || !strings.Contains(body, "settings.password") || !strings.Contains(body, "login.failed") {
		t.Fatalf("audit log incomplete: %d", resp.StatusCode)
	}
	resp, body = a.get(t, "/logs")
	if resp.StatusCode != 200 || !strings.Contains(body, "login failed") {
		t.Fatalf("logs page: %d", resp.StatusCode)
	}
	resp, body = a.get(t, "/api/health")
	if resp.StatusCode != 200 || !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("health: %d %s", resp.StatusCode, body)
	}
	resp, _ = a.get(t, "/does-not-exist")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("404 expected, got %d", resp.StatusCode)
	}
}

func TestLoginRateLimit(t *testing.T) {
	a := newTestApp(t)
	hash, _ := HashPassword("sehr geheimes passwort")
	if _, err := a.store.CreateUser(context.Background(), "admin", hash, "en", "UTC"); err != nil {
		t.Fatal(err)
	}
	_, body := a.get(t, "/login")
	csrf := csrfOf(t, body)
	var last int
	for i := 0; i < 7; i++ {
		resp, _ := a.post(t, "/login", url.Values{"_csrf": {csrf}, "username": {"admin"}, "password": {"wrong"}})
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after repeated failures, got %d", last)
	}
}

func TestSecurityHeadersAndStatic(t *testing.T) {
	a := newTestApp(t)
	resp, _ := a.get(t, "/login")
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}
	resp, body := a.get(t, "/static/css/node64.css")
	if resp.StatusCode != 200 || !strings.Contains(body, "ipv64") {
		t.Fatalf("static css: %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Cache-Control"), "max-age") {
		t.Error("static files should be cacheable")
	}
}

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}
