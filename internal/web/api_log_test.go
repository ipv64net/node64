package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// API-Log: aus schreibt nichts; "keys" nur Anfragen per API-Key, "all" auch die der Oberflaeche; unabhaengig von der
// Log-Stufe, Geheimnisse in der Query maskiert, Schalter gespeichert.
func TestAPILog(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	u := loginAs(t, a, "admin", "sehr geheimes passwort")
	key, _, err := a.store.NewAPIKey(ctx, u.ID, "script")
	if err != nil {
		t.Fatal(err)
	}
	a.s.Log.SetLevel(slog.LevelError, 0) // das API-Log gilt trotzdem
	call := func(method, path, body string) int {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, a.srv.URL+path, rd)
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := a.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	logged := func(want string) bool {
		for _, l := range a.s.Log.Lines(200) {
			if strings.Contains(l, "api request") && strings.Contains(l, want) {
				return true
			}
		}
		return false
	}

	call("GET", "/api/logging?n=1", "")
	if logged("/api/logging") {
		t.Fatal("logged although off")
	}
	if code := call("PUT", "/api/logging", `{"api_log":"bogus"}`); code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid mode: %d", code)
	}
	if code := call("PUT", "/api/logging", `{"api_log":"keys"}`); code != 200 || a.store.SettingOr(ctx, settingAPILog, "") != "keys" {
		t.Fatalf("set keys: %d", code)
	}
	call("GET", "/api/logging?token=geheim123&n=5", "")
	if !logged("path=/api/logging") || !logged("status=200") || !logged("key_name=script") || !logged("user=admin") {
		t.Fatalf("key request not logged: %v", a.s.Log.Lines(5))
	}
	for _, l := range a.s.Log.Lines(200) {
		if strings.Contains(l, "geheim123") {
			t.Fatalf("secret in log: %s", l)
		}
	}
	// Oberflaeche (Sitzung) im Modus "keys" nicht, im Modus "all" schon
	a.get(t, "/api/status")
	if logged("path=/api/status") {
		t.Fatal("session request logged in keys mode")
	}
	_, body := a.get(t, "/settings")
	if !strings.Contains(body, `<option value="keys" selected>`) {
		t.Fatal("settings: mode not shown")
	}
	resp, _ := a.post(t, "/settings/api-log", url.Values{"_csrf": {csrfOf(t, body)}, "api_log": {"all"}})
	if resp.StatusCode != http.StatusSeeOther || a.s.APILogMode() != "all" {
		t.Fatalf("form: %d %s", resp.StatusCode, a.s.APILogMode())
	}
	a.get(t, "/api/status")
	if !logged("path=/api/status") {
		t.Fatal("session request not logged in all mode")
	}
	// Seiten ausserhalb von /api/ nie
	a.get(t, "/settings")
	if logged("path=/settings") {
		t.Fatal("non-api request logged")
	}
}
