package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
)

// Home Assistant: Formular, Speichern (Zertifikat pruefen abschaltbar, ID verschluesselt) und Test-Knopf.
func TestHomeAssistantChannelForm(t *testing.T) {
	ctx := context.Background()
	box, _ := secrets.Load(filepath.Join(t.TempDir(), "k"))
	var nf *notify.Store
	a := newTestAppDeps(t, func(d *Deps) { // Routen der Benachrichtigungen gibt es nur mit Store
		ms, _ := notify.Migrations()
		if err := d.Store.Migrate(ctx, "notify", ms); err != nil {
			t.Fatal(err)
		}
		nf = notify.NewStore(d.Store, box)
		d.Notify = nf
		d.Dispatcher = notify.NewDispatcher(nf, notify.Senders("test"), d.I18n, func(_, def string) string { return def }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	})
	var gotPath, gotKind string
	ha := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		gotPath, gotKind = r.URL.Path, b["kind"].(string)
	}))
	defer ha.Close()
	loginAs(t, a, "admin", "sehr geheimes passwort")

	resp, body := a.get(t, "/notifications/new?type=homeassistant")
	if resp.StatusCode != 200 || !strings.Contains(body, `name="cfg_webhook_id"`) || !strings.Contains(body, `type="password" id="cfg_webhook_id"`) ||
		!strings.Contains(body, "bi-house-gear") || !strings.Contains(body, "/docs/notifications/#home-assistant") ||
		!strings.Contains(body, `name="cfg_verify_tls" id="cfg_verify_tls" checked`) {
		t.Fatalf("form: %d", resp.StatusCode)
	}
	csrf := csrfOf(t, body)
	form := url.Values{"_csrf": {csrf}, "type": {"homeassistant"}, "name": {"HA"}, "lang": {"de"}, "enabled": {"on"}, "notify_down": {"on"},
		"cfg_url": {ha.URL}, "cfg_webhook_id": {"bad id"}}
	form.Set("cfg_verify_tls", "on")
	if resp, body = a.post(t, "/notifications/new", form); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, `id="cfg_verify_tls" checked`) {
		t.Fatalf("bad id: %d", resp.StatusCode) // Haken bleibt nach dem Fehler gesetzt
	}
	form.Del("cfg_verify_tls")
	form.Set("cfg_webhook_id", "node64-xyz")
	if resp, _ = a.post(t, "/notifications/new", form); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save: %d", resp.StatusCode)
	}
	list, _ := nf.Channels(ctx)
	if len(list) != 1 || list[0].Type != notify.TypeHomeAssistant || list[0].Config["verify_tls"] != "false" || list[0].Config["webhook_id"] != "node64-xyz" {
		t.Fatalf("stored: %+v", list)
	}
	if resp, _ = a.post(t, "/notifications/"+strconv.FormatInt(list[0].ID, 10)+"/test", url.Values{"_csrf": {csrf}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("test: %d", resp.StatusCode)
	}
	if gotPath != "/api/webhook/node64-xyz" || gotKind != "test" {
		t.Fatalf("test sent: %q %q", gotPath, gotKind)
	}
}
