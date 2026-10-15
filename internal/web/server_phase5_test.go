package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
	"github.com/ipv64net/node64/internal/totp"
)

// pingModule ist ein Modul mit einer geschuetzten API-Route fuer Tests.
type pingModule struct{}

func (pingModule) Info() module.Info {
	return module.Info{Name: "ping", TitleKey: "nav.dashboard", Path: "/ping", Available: true}
}
func (pingModule) Migrations() []store.Migration { return nil }
func (pingModule) Start(context.Context) error   { return nil }
func (pingModule) Stop(context.Context) error    { return nil }
func (pingModule) Routes(mux *http.ServeMux, g module.Guards) {
	mux.Handle("GET /api/ping", g.Enabled(g.Auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pong " + currentUser(r).Username))
	}))))
}

func withNotify(t *testing.T, a *testApp) {
	t.Helper()
	ms, _ := notify.Migrations()
	if err := a.store.Migrate(context.Background(), "notify", ms); err != nil {
		t.Fatal(err)
	}
}

// loginAs legt einen Benutzer an und meldet den Client an.
func loginAs(t *testing.T, a *testApp, name, pw string) *store.User {
	t.Helper()
	hash, _ := HashPassword(pw)
	u, err := a.store.CreateUser(context.Background(), name, hash, "de", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	_, body := a.get(t, "/login")
	csrf := csrfOf(t, body)
	resp, _ := a.post(t, "/login", url.Values{"_csrf": {csrf}, "username": {name}, "password": {pw}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	return u
}

func TestAPIKeyAuth(t *testing.T) {
	a := newTestAppWith(t, pingModule{})
	ctx := context.Background()
	_ = a.store.SetModuleEnabled(ctx, "ping", true)
	a.registry.StartEnabled(ctx)
	hash, _ := HashPassword("sehr geheimes passwort")
	u, _ := a.store.CreateUser(ctx, "admin", hash, "de", "UTC")
	key, _, err := a.store.NewAPIKey(ctx, u.ID, "script")
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := a.get(t, "/api/ping")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no auth: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", a.srv.URL+"/api/ping", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err = a.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "pong admin" {
		t.Fatalf("api key: %d %s", resp.StatusCode, b)
	}
	req.Header.Set("Authorization", "Bearer node64_wrong")
	resp, _ = a.client.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong key: %d", resp.StatusCode)
	}
	keys, _ := a.store.APIKeys(ctx, u.ID)
	if len(keys) != 1 || keys[0].LastUsedAt.IsZero() {
		t.Fatalf("last used not set: %+v", keys)
	}
}

func TestTwoFactorFlow(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	hash, _ := HashPassword("sehr geheimes passwort")
	u, _ := a.store.CreateUser(ctx, "admin", hash, "de", "UTC")
	secret := totp.NewSecret()
	codes, hashes := totp.NewRecoveryCodes(3)
	_ = a.store.SetUserTOTP(ctx, u.ID, secret, strings.Join(hashes, ","))

	_, body := a.get(t, "/login")
	csrf := csrfOf(t, body)
	resp, _ := a.post(t, "/login", url.Values{"_csrf": {csrf}, "username": {"admin"}, "password": {"sehr geheimes passwort"}, "next": {"/audit"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login/totp") {
		t.Fatalf("expected redirect to totp, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = a.get(t, "/settings")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login/totp") {
		t.Fatalf("pending session must not reach pages: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, body = a.get(t, "/login/totp")
	if resp.StatusCode != 200 {
		t.Fatalf("totp page: %d", resp.StatusCode)
	}
	csrf = csrfOf(t, body)
	resp, _ = a.post(t, "/login/totp", url.Values{"_csrf": {csrf}, "code": {"000000"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", resp.StatusCode)
	}
	code, _ := totp.Code(secret, time.Now())
	resp, _ = a.post(t, "/login/totp", url.Values{"_csrf": {csrf}, "code": {code}, "next": {"/audit"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/audit" {
		t.Fatalf("valid code: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ = a.get(t, "/settings"); resp.StatusCode != 200 {
		t.Fatalf("after 2fa: %d", resp.StatusCode)
	}
	// Abmelden, mit Wiederherstellungscode anmelden
	_, body = a.get(t, "/settings")
	resp, _ = a.post(t, "/logout", url.Values{"_csrf": {csrfOf(t, body)}})
	_, body = a.get(t, "/login")
	csrf = csrfOf(t, body)
	a.post(t, "/login", url.Values{"_csrf": {csrf}, "username": {"admin"}, "password": {"sehr geheimes passwort"}})
	_, body = a.get(t, "/login/totp")
	csrf = csrfOf(t, body)
	resp, _ = a.post(t, "/login/totp", url.Values{"_csrf": {csrf}, "code": {codes[0]}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("recovery code: %d", resp.StatusCode)
	}
	rec, _ := a.store.UserTOTPRecovery(ctx, u.ID)
	if len(strings.Split(rec, ",")) != 2 {
		t.Fatalf("recovery code must be consumed: %q", rec)
	}
}

func TestBackupExportImport(t *testing.T) {
	a := newTestApp(t)
	withNotify(t, a)
	ctx := context.Background()
	box, _ := secrets.Load(filepath.Join(t.TempDir(), "k"))
	nf := notify.NewStore(a.store, box)
	a.s.Notify = nf
	ch := &notify.Channel{Type: notify.TypeTelegram, Name: "tg", Config: map[string]string{"bot_token": "123:SECRET", "chat_id": "7"}, Enabled: true, Default: true, NotifyDown: true, NotifyUp: true}
	_ = ch.Validate()
	if err := nf.Insert(ctx, ch); err != nil {
		t.Fatal(err)
	}
	_ = a.store.SetSetting(ctx, SettingNodeName, "Pi")
	loginAs(t, a, "admin", "sehr geheimes passwort")
	_, body := a.get(t, "/settings")
	csrf := csrfOf(t, body)

	// Backup ist eine SQLite-Datei
	resp, body := a.get(t, "/settings/backup")
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "SQLite format 3") {
		t.Fatalf("backup: %d %q", resp.StatusCode, body[:min(len(body), 20)])
	}
	// Export ohne Geheimnisse
	resp, body = a.post(t, "/settings/export", url.Values{"_csrf": {csrf}, "secrets": {"none"}})
	if resp.StatusCode != 200 || strings.Contains(body, "123:SECRET") || !strings.Contains(body, `"node64-config"`) {
		t.Fatalf("export none: %d", resp.StatusCode)
	}
	// Export mit Passwort: Geheimnis verschluesselt enthalten
	resp, body = a.post(t, "/settings/export", url.Values{"_csrf": {csrf}, "secrets": {"password"}, "password": {"export-passwort"}})
	if resp.StatusCode != 200 || strings.Contains(body, "123:SECRET") || !strings.Contains(body, "enc:v1:") {
		t.Fatalf("export password: %d", resp.StatusCode)
	}
	var cf configFile
	if err := json.Unmarshal([]byte(body), &cf); err != nil || cf.Settings[SettingNodeName] != "Pi" || len(cf.Channels) != 1 {
		t.Fatalf("export content: %v %+v", err, cf)
	}
	// Import in eine frische Instanz
	b := newTestApp(t)
	withNotify(t, b)
	box2, _ := secrets.Load(filepath.Join(t.TempDir(), "k2"))
	nf2 := notify.NewStore(b.store, box2)
	b.s.Notify = nf2
	loginAs(t, b, "admin", "sehr geheimes passwort")
	_, page := b.get(t, "/settings")
	csrf2 := csrfOf(t, page)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("_csrf", csrf2)
	mw.WriteField("password", "export-passwort")
	fw, _ := mw.CreateFormFile("file", "config.json")
	fw.Write([]byte(body))
	mw.Close()
	req, _ := http.NewRequest("POST", b.srv.URL+"/settings/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("import: %d", resp.StatusCode)
	}
	chans, _ := nf2.Channels(ctx)
	if len(chans) != 1 || chans[0].Config["bot_token"] != "123:SECRET" || !chans[0].Default {
		t.Fatalf("imported channel: %+v", chans)
	}
	if v := b.store.SettingOr(ctx, SettingNodeName, ""); v != "Pi" {
		t.Fatalf("imported setting: %q", v)
	}
	// Ohne Passwort: Fehler, nichts importiert
	buf.Reset()
	mw = multipart.NewWriter(&buf)
	mw.WriteField("_csrf", csrf2)
	fw, _ = mw.CreateFormFile("file", "config.json")
	fw.Write([]byte(body))
	mw.Close()
	req, _ = http.NewRequest("POST", b.srv.URL+"/settings/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, _ = b.client.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("import without password: %d", resp.StatusCode)
	}
	resp, page = b.get(t, "/settings")
	if !strings.Contains(page, "Passwort") {
		t.Fatal("expected password-needed flash")
	}
}

// Die API-Keys verwaltet die Seite "API", nicht mehr die Einstellungen; der neue Key steht nur in der Antwort.
func TestAPIKeysOnAPIPage(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	u := loginAs(t, a, "admin", "sehr geheimes passwort")
	_, body := a.get(t, "/settings")
	if strings.Contains(body, `action="/settings/api-keys"`) {
		t.Fatal("api key card still in settings")
	}
	resp, body := a.get(t, "/api/docs")
	if resp.StatusCode != 200 || !strings.Contains(body, `id="keys"`) {
		t.Fatalf("api page: %d", resp.StatusCode)
	}
	resp, body = a.post(t, "/settings/api-keys", url.Values{"_csrf": {csrfOf(t, body)}, "name": {"skript"}})
	if resp.StatusCode != 200 || !strings.Contains(body, `id="new-api-key" value="node64_`) || !strings.Contains(body, "skript") {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	keys, _ := a.store.APIKeys(ctx, u.ID)
	if len(keys) != 1 {
		t.Fatalf("keys: %+v", keys)
	}
	_, body = a.get(t, "/api/docs")
	if strings.Contains(body, `id="new-api-key"`) {
		t.Fatal("key shown again")
	}
	resp, _ = a.post(t, "/settings/api-keys/"+strconv.FormatInt(keys[0].ID, 10)+"/delete", url.Values{"_csrf": {csrfOf(t, body)}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/api/docs#keys" {
		t.Fatalf("delete: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if keys, _ = a.store.APIKeys(ctx, u.ID); len(keys) != 0 {
		t.Fatalf("not deleted: %+v", keys)
	}
}
