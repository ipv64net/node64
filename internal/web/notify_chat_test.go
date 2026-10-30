package web

import (
	"context"
	"io"
	"log/slog"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
)

// Slack, Teams und Matrix: Formular mit Anleitung, Matrix-Raum wird geprueft, Token verschluesselt gespeichert.
func TestChatChannelForms(t *testing.T) {
	ctx := context.Background()
	box, _ := secrets.Load(filepath.Join(t.TempDir(), "k"))
	var nf *notify.Store
	a := newTestAppDeps(t, func(d *Deps) {
		ms, _ := notify.Migrations()
		if err := d.Store.Migrate(ctx, "notify", ms); err != nil {
			t.Fatal(err)
		}
		nf = notify.NewStore(d.Store, box)
		d.Notify = nf
		d.Dispatcher = notify.NewDispatcher(nf, notify.Senders("test"), d.I18n, func(_, def string) string { return def }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	})
	loginAs(t, a, "admin", "sehr geheimes passwort")
	for typ, want := range map[string]string{"slack": "/docs/notifications/#slack", "teams": "/docs/notifications/#teams", "matrix": "/docs/notifications/#matrix"} {
		resp, body := a.get(t, "/notifications/new?type="+typ)
		if resp.StatusCode != 200 || !strings.Contains(body, want) || strings.Contains(body, "nf.") {
			t.Fatalf("%s form: %d", typ, resp.StatusCode)
		}
	}
	_, body := a.get(t, "/notifications/new?type=matrix")
	if !strings.Contains(body, `name="cfg_room"`) || !strings.Contains(body, `type="password" id="cfg_token"`) || !strings.Contains(body, "https://matrix.org") {
		t.Fatal("matrix fields")
	}
	csrf := csrfOf(t, body)
	form := url.Values{"_csrf": {csrf}, "type": {"matrix"}, "name": {"Matrix"}, "lang": {"de"}, "enabled": {"on"}, "notify_down": {"on"},
		"cfg_server": {"https://matrix.example.org/"}, "cfg_token": {"syt_geheim"}, "cfg_room": {"alarme"}}
	if resp, _ := a.post(t, "/notifications/new", form); resp.StatusCode != 422 {
		t.Fatalf("bad room: %d", resp.StatusCode)
	}
	form.Set("cfg_room", "#alarme:example.org")
	if resp, _ := a.post(t, "/notifications/new", form); resp.StatusCode != 303 {
		t.Fatalf("save: %d", resp.StatusCode)
	}
	list, _ := nf.Channels(ctx)
	if len(list) != 1 || list[0].Config["server"] != "https://matrix.example.org" || list[0].Config["token"] != "syt_geheim" {
		t.Fatalf("stored: %+v", list)
	}
}

// SecNtfy: Formular mit Anleitung und Schalter fuer kritische Alarme, Geraete-Token geprueft und verschluesselt gespeichert.
func TestSecNtfyChannelForm(t *testing.T) {
	ctx := context.Background()
	box, _ := secrets.Load(filepath.Join(t.TempDir(), "k"))
	var nf *notify.Store
	a := newTestAppDeps(t, func(d *Deps) {
		ms, _ := notify.Migrations()
		if err := d.Store.Migrate(ctx, "notify", ms); err != nil {
			t.Fatal(err)
		}
		nf = notify.NewStore(d.Store, box)
		d.Notify = nf
		d.Dispatcher = notify.NewDispatcher(nf, notify.Senders("test"), d.I18n, func(_, def string) string { return def }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	})
	loginAs(t, a, "admin", "sehr geheimes passwort")
	_, list := a.get(t, "/notifications")
	if !strings.Contains(list, "type=app") || strings.Contains(list, "type=secntfy") {
		t.Fatal("type not offered")
	}
	resp, body := a.get(t, "/notifications/new?type=app")
	if resp.StatusCode != 200 || !strings.Contains(body, "/docs/notifications/#ipv64-app") || strings.Contains(body, "nf.") || !strings.Contains(body, `type="password" id="cfg_device_key"`) ||
		!strings.Contains(body, `name="cfg_critical"`) || strings.Contains(body, "cfg_server") || !strings.Contains(body, "IPv64 App") {
		t.Fatalf("form: %d", resp.StatusCode)
	}
	form := url.Values{"_csrf": {csrfOf(t, body)}, "type": {"app"}, "name": {"Handy"}, "lang": {"de"}, "enabled": {"on"}, "notify_down": {"on"},
		"cfg_device_key": {"geheim"}, "cfg_critical": {"on"}}
	if resp, _ := a.post(t, "/notifications/new", form); resp.StatusCode != 422 {
		t.Fatalf("bad token: %d", resp.StatusCode)
	}
	form.Set("cfg_device_key", "NTFY-DEVICE-abc123")
	if resp, _ := a.post(t, "/notifications/new", form); resp.StatusCode != 303 {
		t.Fatalf("save: %d", resp.StatusCode)
	}
	chs, _ := nf.Channels(ctx)
	if len(chs) != 1 || chs[0].Type != notify.TypeApp || chs[0].Config["device_key"] != "NTFY-DEVICE-abc123" || chs[0].Config["critical"] != "true" {
		t.Fatalf("stored: %+v", chs)
	}
}
