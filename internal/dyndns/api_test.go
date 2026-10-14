package dyndns

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/module"
)

func apiServer(t *testing.T, m *Module) *httptest.Server {
	t.Helper()
	pass := func(h http.Handler) http.Handler { return h }
	mux := http.NewServeMux()
	m.Routes(mux, module.Guards{Enabled: pass, Auth: pass, Actor: func(*http.Request) string { return "test" }})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func call(t *testing.T, method, url string, body any) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, rd)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAPI(t *testing.T) {
	m, _ := newTargetModule(t, true)
	srv := apiServer(t, m)
	in := map[string]any{"domain": "home.ipv64.net", "host": "nas", "token_kind": "record", "token": tokA, "mode4": "auto", "mode6": "off"}
	code, body := call(t, "POST", srv.URL+"/api/dyndns/targets", in)
	if code != 201 || strings.Contains(body, tokA) || !strings.Contains(body, `"token_hint":"…AAAA"`) || !strings.Contains(body, `"fqdn":"nas.home.ipv64.net"`) {
		t.Fatalf("create: %d %s", code, body)
	}
	if code, _ := call(t, "POST", srv.URL+"/api/dyndns/targets", in); code != 409 {
		t.Fatalf("duplicate: %d", code)
	}
	bad := map[string]any{"domain": "home.ipv64.net", "host": "x", "token": "short", "mode4": "auto"}
	if code, body := call(t, "POST", srv.URL+"/api/dyndns/targets", bad); code != 422 || !strings.Contains(body, "token") {
		t.Fatalf("invalid: %d %s", code, body)
	}
	if code, body := call(t, "GET", srv.URL+"/api/dyndns/targets", nil); code != 200 || strings.Contains(body, tokA) || !strings.Contains(body, `"status":"new"`) {
		t.Fatalf("list: %d %s", code, body)
	}
	off := false
	upd := map[string]any{"mode4": "auto", "mode6": "suffix", "suffix6": "::1:2:3:4", "enabled": off}
	if code, body := call(t, "PUT", srv.URL+"/api/dyndns/targets/1", upd); code != 200 || !strings.Contains(body, `"enabled":false`) || !strings.Contains(body, `"suffix6":"::1:2:3:4"`) {
		t.Fatalf("update: %d %s", code, body)
	}
	if got, _ := m.Target(context.Background(), 1); got.Token != tokA {
		t.Fatal("token must stay when not given")
	}
	if code, _ := call(t, "GET", srv.URL+"/api/dyndns/targets/99", nil); code != 404 {
		t.Fatalf("missing: %d", code)
	}
	if code, body := call(t, "GET", srv.URL+"/api/dyndns/history?type=checks", nil); code != 200 || !strings.Contains(body, `"type":"checks"`) {
		t.Fatalf("history: %d %s", code, body)
	}
	if code, body := call(t, "GET", srv.URL+"/api/dyndns/status", nil); code != 200 || !strings.Contains(body, `"total":1`) {
		t.Fatalf("status: %d %s", code, body)
	}

	// Export ohne Tokens, Import holt sie ueber den API-Key neu
	exp, err := m.Export(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(exp)
	if strings.Contains(string(raw), tokA) || strings.Contains(string(raw), "token_hint") {
		t.Fatalf("export leaks token: %s", raw)
	}
	if code, _ := call(t, "DELETE", srv.URL+"/api/dyndns/targets/1", nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if n, err := m.Import(context.Background(), raw); err == nil || n != 0 {
		t.Fatalf("import without key must explain: %d %v", n, err)
	}
	api := fakeIPv64(t)
	defer api.Close()
	core := m.core
	m.SetKey(ipv64api.NewKey(core, m.box, ipv64api.NewClient(api.URL, "test"), slog.New(slog.NewTextHandler(io.Discard, nil))))
	if _, err := m.key.Set(context.Background(), testKey); err != nil {
		t.Fatal(err)
	}
	// nas.home.ipv64.net gibt es im Fake-Account, der Token kommt von dort
	n, err := m.Import(context.Background(), raw)
	list, _ := m.Targets(context.Background())
	if err != nil || len(list) != 1 || list[0].Token != tokSuf || list[0].Mode6 != Mode6Suffix {
		t.Fatalf("import: n=%d err=%v list=%+v", n, err, list)
	}
}

// Review 2026-10-14: Einstellungen, Auswahl aus dem Account und Token neu holen per API.
func TestAPIAccountAndSettings(t *testing.T) {
	m, core := newTargetModule(t, true)
	srv := apiServer(t, m)
	if code, body := call(t, "GET", srv.URL+"/api/dyndns/settings", nil); code != 200 || !strings.Contains(body, `"interval_minutes":5`) {
		t.Fatalf("settings get: %d %s", code, body)
	}
	if code, _ := call(t, "PUT", srv.URL+"/api/dyndns/settings", map[string]any{"interval_minutes": 7}); code != 422 {
		t.Fatalf("invalid interval must be rejected: %d", code)
	}
	if code, body := call(t, "PUT", srv.URL+"/api/dyndns/settings", map[string]any{"interval_minutes": 10, "notify_ip": false}); code != 200 || !strings.Contains(body, `"interval_minutes":10`) || !strings.Contains(body, `"notify_ip":false`) || !strings.Contains(body, `"keep_checks_days":30`) {
		t.Fatalf("settings put: %d %s", code, body)
	}
	if code, _ := call(t, "GET", srv.URL+"/api/dyndns/account/names", nil); code != 409 {
		t.Fatalf("names without key: %d", code)
	}
	api := fakeIPv64(t)
	defer api.Close()
	m.SetKey(ipv64api.NewKey(core, m.box, ipv64api.NewClient(api.URL, "test"), slog.New(slog.NewTextHandler(io.Discard, nil))))
	if _, err := m.key.Set(context.Background(), testKey); err != nil {
		t.Fatal(err)
	}
	code, body := call(t, "GET", srv.URL+"/api/dyndns/account/names", nil)
	if code != 200 || strings.Contains(body, tokA) || !strings.Contains(body, `"key":"home.ipv64.net|nas"`) || !strings.Contains(body, `"default_mode6":"prefix"`) {
		t.Fatalf("names: %d %s", code, body)
	}
	code, body = call(t, "POST", srv.URL+"/api/dyndns/targets/from-account", []map[string]string{{"key": "home.ipv64.net|", "mode4": "auto", "mode6": "off"}, {"key": "home.ipv64.net|web"}})
	if code != 201 || strings.Contains(body, tokA) || !strings.Contains(body, `"fqdn":"home.ipv64.net"`) || !strings.Contains(body, `"mode6":"off"`) {
		t.Fatalf("from-account: %d %s", code, body)
	}
	list, _ := m.Targets(context.Background())
	if len(list) != 1 || list[0].Token != tokA {
		t.Fatalf("targets: %+v", list)
	}
	_, _ = core.Writer().Exec(`UPDATE dyn_targets SET token = ?, paused = 'badauth' WHERE id = ?`, m.seal(tokOther), list[0].ID)
	code, body = call(t, "POST", srv.URL+"/api/dyndns/targets/"+strconv.FormatInt(list[0].ID, 10)+"/token", nil)
	if got, _ := m.Target(context.Background(), list[0].ID); code != 200 || got.Token != tokA || got.Paused != "" {
		t.Fatalf("token refresh: %d %s %+v", code, body, got)
	}
}
