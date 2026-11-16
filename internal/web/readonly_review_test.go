package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/mcp"
	"github.com/ipv64net/node64/internal/store"
)

// Befunde aus dem Code-Review zur Rolle „Nur lesen“.

// Die eigene Zeitzone darf jeder setzen, die Zeitzone der Node (gilt fuer alle, geht in den Cluster) nur ein
// Administrator - in der Oberflaeche und ueber PUT /api/users/me.
func TestReadOnlyNodeTimezone(t *testing.T) {
	a, admin, reader := roleApp(t)
	ctx := context.Background()
	_ = a.store.SetSetting(ctx, SettingNodeTimezone, "Europe/Berlin")
	_, csrf := sessionOf(t, a)
	if _, body := a.get(t, "/settings"); strings.Contains(body, "Zeitzone der Node") {
		t.Fatal("Hinweis Node-Zeitzone bei Nur lesen")
	}
	if resp, _ := a.post(t, "/settings/user", url.Values{"_csrf": {csrf}, "lang": {"de"}, "timezone": {"America/New_York"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("settings/user: %d", resp.StatusCode)
	}
	if u, _ := a.store.UserByID(ctx, reader.ID); u.Timezone != "America/New_York" {
		t.Fatalf("eigene Zeitzone: %q", u.Timezone)
	}
	if tz := a.store.SettingOr(ctx, SettingNodeTimezone, ""); tz != "Europe/Berlin" {
		t.Fatalf("Nur lesen setzt Node-Zeitzone (Formular): %q", tz)
	}
	rkey, _, _ := a.store.NewAPIKey(ctx, reader.ID, "lesen")
	if st, out := apiCall(t, a, rkey, "PUT", "/api/users/me", map[string]any{"timezone": "Asia/Tokyo"}); st != 200 || out.(map[string]any)["timezone"] != "Asia/Tokyo" {
		t.Fatalf("api me: %d %v", st, out)
	}
	if tz := a.store.SettingOr(ctx, SettingNodeTimezone, ""); tz != "Europe/Berlin" {
		t.Fatalf("Nur lesen setzt Node-Zeitzone (API): %q", tz)
	}
	akey, _, _ := a.store.NewAPIKey(ctx, admin.ID, "admin")
	if st, _ := apiCall(t, a, akey, "PUT", "/api/users/me", map[string]any{"timezone": "Asia/Tokyo"}); st != 200 {
		t.Fatalf("admin api me: %d", st)
	}
	if tz := a.store.SettingOr(ctx, SettingNodeTimezone, ""); tz != "Asia/Tokyo" {
		t.Fatalf("Administrator setzt Node-Zeitzone: %q", tz)
	}
	a.client.Jar, _ = cookiejar.New(nil)
	if resp := login(t, a, "admin", "sehr geheimes passwort"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login admin: %d", resp.StatusCode)
	}
	if _, body := a.get(t, "/settings/account"); !strings.Contains(body, "Zeitzone der Node") {
		t.Fatal("Hinweis Node-Zeitzone fehlt beim Administrator")
	}
}

// Sync-Konflikte: die beiden Fassungen (Check-Parameter, Kanal-Konfiguration) nur fuer Administratoren; die Liste
// (Name, Art, Zeit, Grund) sieht auch „Nur lesen“.
func TestReadOnlyConflictPayloads(t *testing.T) {
	ctx := context.Background()
	var hc *healthchecks.Module
	a := newTestAppDeps(t, func(d *Deps) {
		hc = healthchecks.New(d.Store, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, "test")
		if err := d.Store.Migrate(ctx, "healthchecks", hc.Migrations()); err != nil {
			t.Fatal(err)
		}
		d.HC = hc
	})
	admin := loginAs(t, a, "admin", "sehr geheimes passwort")
	if err := hc.ConflictAdd(ctx, healthchecks.Conflict{Entity: "check", EntityID: "tokA", LocalOp: "upsert",
		LocalPayload: `{"name":"Webseite","params":{"basic_password":"S3cretBasicPW"}}`, ServerPayload: `{"name":"Webseite","params":{"headers":{"Authorization":"Bearer sk-live-XYZ"}}}`,
		ServerRevision: 3, Error: "limit"}); err != nil {
		t.Fatal(err)
	}
	reader := createUser(t, a, "leser", store.RoleRead)
	a.client.Jar, _ = cookiejar.New(nil)
	if resp := login(t, a, "leser", "sehr geheimes passwort"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login leser: %d", resp.StatusCode)
	}
	resp, body := a.get(t, "/link")
	if resp.StatusCode != 200 || !strings.Contains(body, "Webseite") || !strings.Contains(body, "Beide Fassungen sieht nur ein Administrator") {
		t.Fatalf("link: %d", resp.StatusCode)
	}
	for _, secret := range []string{"S3cretBasicPW", "sk-live-XYZ"} {
		if strings.Contains(body, secret) {
			t.Fatalf("Nur lesen sieht %q auf /link", secret)
		}
	}
	rkey, _, _ := a.store.NewAPIKey(ctx, reader.ID, "lesen")
	st, out := apiCall(t, a, rkey, "GET", "/api/link/conflicts", nil)
	list, _ := out.([]any)
	if st != 200 || len(list) != 1 {
		t.Fatalf("reader conflicts: %d %v", st, out)
	}
	c := list[0].(map[string]any)
	if c["name"] != "Webseite" || c["local"] != nil || c["server"] != nil {
		t.Fatalf("Nur lesen sieht Fassungen: %v", c)
	}
	akey, _, _ := a.store.NewAPIKey(ctx, admin.ID, "admin")
	_, out = apiCall(t, a, akey, "GET", "/api/link/conflicts", nil)
	list, _ = out.([]any)
	if len(list) != 1 || list[0].(map[string]any)["local"] == nil || list[0].(map[string]any)["server"] == nil {
		t.Fatalf("Administrator ohne Fassungen: %v", out)
	}
}

// Rolle und MCP-Schluessel liegen unter getrennten Schluesseln im Kontext.
func TestCtxRoleMCPKeyDistinct(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxRole, store.RoleRead)
	ctx = context.WithValue(ctx, ctxMCPKey, mcp.Identity{UserID: 7})
	if r, ok := ctx.Value(ctxRole).(string); !ok || r != store.RoleRead {
		t.Fatalf("ctxRole ueberschrieben: %v", ctx.Value(ctxRole))
	}
	if id, ok := ctx.Value(ctxMCPKey).(mcp.Identity); !ok || id.UserID != 7 {
		t.Fatalf("ctxMCPKey: %v", ctx.Value(ctxMCPKey))
	}
}
