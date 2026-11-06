package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/selfupdate"
	"github.com/ipv64net/node64/internal/store"
)

// apiCall ruft die lokale API mit einem API-Key auf und liefert Status und dekodierte Antwort.
func apiCall(t *testing.T, a *testApp, key, method, path string, body any) (int, any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, a.srv.URL+path, rd)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := a.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func apiKeyUser(t *testing.T, a *testApp, name string) (*store.User, string) {
	t.Helper()
	ctx := context.Background()
	hash, _ := HashPassword("sehr geheimes passwort")
	u, err := a.store.CreateUser(ctx, name, hash, "de", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := a.store.NewAPIKey(ctx, u.ID, "script")
	if err != nil {
		t.Fatal(err)
	}
	return u, key
}

// Update-Einstellungen per API: Betriebsart, Kanal (auto = eigene Wahl zuruecknehmen) und Zeitfenster.
func TestAPIUpdateSettings(t *testing.T) {
	a := newTestAppDeps(t, func(d *Deps) { d.Updater = selfupdate.New(t.TempDir(), "1.0.0") })
	_, key := apiKeyUser(t, a, "admin")
	ctx := context.Background()
	st, out := apiCall(t, a, key, "PUT", "/api/update/settings", map[string]any{"mode": "auto", "channel": "preview", "window": "02:00-04:00"})
	m, _ := out.(map[string]any)
	if st != 200 || m["Mode"] != "auto" || m["Channel"] != "preview" || m["Chosen"] != true || m["Window"] != "02:00-04:00" {
		t.Fatalf("put: %d %v", st, out)
	}
	if a.store.SettingOr(ctx, selfupdate.SetChannel, "") != "preview" {
		t.Fatal("channel not stored")
	}
	if st, out = apiCall(t, a, key, "PUT", "/api/update/settings", map[string]any{"channel": "auto"}); st != 200 || out.(map[string]any)["Chosen"] != false {
		t.Fatalf("auto: %d %v", st, out)
	}
	if v, ok, _ := a.store.Setting(ctx, selfupdate.SetChannel); ok || v != "" {
		t.Fatalf("empty channel stored: %q", v)
	}
	if out.(map[string]any)["Mode"] != "auto" {
		t.Fatal("missing field changed the mode")
	}
	for _, bad := range []map[string]any{{"mode": "sometimes"}, {"channel": ""}, {"window": "morgens"}} {
		if st, _ := apiCall(t, a, key, "PUT", "/api/update/settings", bad); st != http.StatusUnprocessableEntity {
			t.Fatalf("%v: %d", bad, st)
		}
	}
}

// MCP per API: Schalter, Schluessel anlegen (nur einmal sichtbar), auflisten, widerrufen.
func TestAPIMCP(t *testing.T) {
	a := newTestApp(t)
	_, key := apiKeyUser(t, a, "admin")
	if st, out := apiCall(t, a, key, "PUT", "/api/mcp", map[string]any{"enabled": true}); st != 200 || out.(map[string]any)["enabled"] != true {
		t.Fatalf("enable: %d %v", st, out)
	}
	if st, _ := apiCall(t, a, key, "POST", "/api/mcp/keys", map[string]any{"name": "KI", "areas": []string{"node", "gibtsnicht"}}); st != http.StatusUnprocessableEntity {
		t.Fatalf("unknown area: %d", st)
	}
	st, out := apiCall(t, a, key, "POST", "/api/mcp/keys", map[string]any{"name": "KI", "areas": []string{"node", "audit"}})
	k, _ := out.(map[string]any)
	if st != 201 || !strings.HasPrefix(k["key"].(string), store.MCPKeyPrefix) || len(k["areas"].([]any)) != 2 {
		t.Fatalf("create: %d %v", st, out)
	}
	_, out = apiCall(t, a, key, "GET", "/api/mcp", nil)
	keys := out.(map[string]any)["keys"].([]any)
	if len(keys) != 1 || keys[0].(map[string]any)["key"] != nil {
		t.Fatalf("list: %v", out)
	}
	id := int64(k["id"].(float64))
	if st, _ := apiCall(t, a, key, "DELETE", "/api/mcp/keys/"+itoa(id), nil); st != 204 {
		t.Fatalf("revoke: %d", st)
	}
	if st, _ := apiCall(t, a, key, "DELETE", "/api/mcp/keys/"+itoa(id), nil); st != 404 {
		t.Fatalf("revoke twice: %d", st)
	}
}

// Benutzer per API: Liste ohne Geheimnisse, eigene Sprache, anderen loeschen (den eigenen nie).
func TestAPIUsers(t *testing.T) {
	a := newTestApp(t)
	me, key := apiKeyUser(t, a, "admin")
	other, _ := apiKeyUser(t, a, "gast")
	st, out := apiCall(t, a, key, "GET", "/api/users", nil)
	list, _ := out.([]any)
	if st != 200 || len(list) != 2 {
		t.Fatalf("list: %d %v", st, out)
	}
	for _, x := range list {
		if _, ok := x.(map[string]any)["password_hash"]; ok {
			t.Fatal("hash in output")
		}
	}
	if st, out = apiCall(t, a, key, "PUT", "/api/users/me", map[string]any{"lang": "en"}); st != 200 || out.(map[string]any)["lang"] != "en" || out.(map[string]any)["timezone"] != "UTC" {
		t.Fatalf("me: %d %v", st, out)
	}
	if st, _ = apiCall(t, a, key, "PUT", "/api/users/me", map[string]any{"lang": "xx"}); st != http.StatusUnprocessableEntity {
		t.Fatalf("bad lang: %d", st)
	}
	if st, _ = apiCall(t, a, key, "DELETE", "/api/users/"+itoa(me.ID), nil); st != http.StatusConflict {
		t.Fatalf("delete self: %d", st)
	}
	if st, _ = apiCall(t, a, key, "DELETE", "/api/users/"+itoa(other.ID), nil); st != 204 {
		t.Fatalf("delete other: %d", st)
	}
	if st, _ = apiCall(t, a, key, "DELETE", "/api/users/"+itoa(other.ID), nil); st != 404 {
		t.Fatalf("delete twice: %d", st)
	}
}

// E-Mail/SMS bei ipv64 per API: anlegen, bestaetigen (falscher Code 422), aendern, Test, loeschen.
func TestAPIIPv64Channels(t *testing.T) {
	ctx := context.Background()
	fake := &fakeHC2Channels{next: 4, chans: map[int64]map[string]any{}}
	api := httptest.NewServer(fake)
	defer api.Close()
	box, _ := secrets.Load(filepath.Join(t.TempDir(), "k"))
	a := newTestAppDeps(t, func(d *Deps) {
		ms, _ := notify.Migrations()
		if err := d.Store.Migrate(ctx, "notify", ms); err != nil {
			t.Fatal(err)
		}
		d.Notify = notify.NewStore(d.Store, box)
		d.IPv64 = ipv64api.NewKey(d.Store, nil, ipv64api.NewClient(api.URL, "test"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	})
	_, key := apiKeyUser(t, a, "admin")
	if st, _ := apiCall(t, a, key, "GET", "/api/ipv64/channels", nil); st != http.StatusConflict {
		t.Fatalf("without key: %d", st)
	}
	_ = a.store.SetSetting(ctx, ipv64api.SetKey, "notifytestkey0123456789abcdef")
	if st, _ := apiCall(t, a, key, "POST", "/api/ipv64/channels", map[string]any{"type": "telegram", "name": "x"}); st != http.StatusUnprocessableEntity {
		t.Fatalf("wrong type: %d", st)
	}
	if st, _ := apiCall(t, a, key, "POST", "/api/ipv64/channels", map[string]any{"type": "ipv64_sms", "name": "Handy", "config": map[string]string{"bot": "x"}}); st != http.StatusUnprocessableEntity {
		t.Fatalf("unknown field: %d", st)
	}
	st, out := apiCall(t, a, key, "POST", "/api/ipv64/channels", map[string]any{"type": "ipv64_sms", "name": "Handy", "lang": "de", "config": map[string]string{"number": "+49 177 1234567"}})
	if st != 201 || out.(map[string]any)["id"] != float64(5) || out.(map[string]any)["verified"] != false {
		t.Fatalf("create: %d %v", st, out)
	}
	if st, _ = apiCall(t, a, key, "POST", "/api/ipv64/channels/5/verify/send", nil); st != http.StatusAccepted {
		t.Fatalf("send: %d", st)
	}
	if st, _ = apiCall(t, a, key, "POST", "/api/ipv64/channels/5/verify", map[string]string{"code": "000000"}); st != http.StatusUnprocessableEntity {
		t.Fatalf("wrong code: %d", st)
	}
	if st, out = apiCall(t, a, key, "POST", "/api/ipv64/channels/5/verify", map[string]string{"code": "123456"}); st != 200 || out.(map[string]any)["verified"] != true {
		t.Fatalf("verify: %d %v", st, out)
	}
	if st, out = apiCall(t, a, key, "PUT", "/api/ipv64/channels/5", map[string]any{"enabled": false}); st != 200 || out.(map[string]any)["enabled"] != false {
		t.Fatalf("update: %d %v", st, out)
	}
	if st, _ = apiCall(t, a, key, "POST", "/api/ipv64/channels/5/test", nil); st != 200 {
		t.Fatalf("test: %d", st)
	}
	if st, out = apiCall(t, a, key, "GET", "/api/ipv64/channels", nil); st != 200 || len(out.([]any)) != 1 {
		t.Fatalf("list: %d %v", st, out)
	}
	if st, _ = apiCall(t, a, key, "DELETE", "/api/ipv64/channels/5", nil); st != 204 {
		t.Fatalf("delete: %d", st)
	}
	if st, _ = apiCall(t, a, key, "GET", "/api/ipv64/channels/5", nil); st != 404 {
		t.Fatalf("gone: %d", st)
	}
}

// Verknuepfen per Code: ohne Linker 503, Abbrechen und Status mit NoOp-Sync.
func TestAPILinkCode(t *testing.T) {
	a := newTestApp(t)
	_, key := apiKeyUser(t, a, "admin")
	if st, _ := apiCall(t, a, key, "POST", "/api/link/start", nil); st != http.StatusServiceUnavailable {
		t.Fatalf("start without linker: %d", st)
	}
	if st, out := apiCall(t, a, key, "GET", "/api/link/status", nil); st != 200 || out.(map[string]any)["linked"] != false {
		t.Fatalf("status: %d %v", st, out)
	}
	if st, _ := apiCall(t, a, key, "POST", "/api/link/cancel", nil); st != http.StatusServiceUnavailable {
		t.Fatalf("cancel without linker: %d", st)
	}
}
