package web

import (
	"context"
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
)

// Mit API-Key (ohne Verknuepfung): keine "nach Verknuepfung"-Eintraege, sondern Link auf ipv64.net und die
// bestaetigten E-Mail-/SMS-Kanaele des Accounts (nur lesen). iGotify ist kein eigener Menuepunkt mehr.
func TestNotificationsWithAPIKey(t *testing.T) {
	ctx := context.Background()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hc2/channels" {
			_, _ = io.WriteString(w, `{"data":[{"id":5,"type":"ipv64_sms","name":"Handy Dennis","enabled":true,"default":true,"verified":true,"lang":"de"},
				{"id":6,"type":"ipv64_mail","name":"Unbestaetigt","enabled":true,"verified":false},{"id":7,"type":"telegram","name":"TG","enabled":true,"verified":true}]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer api.Close()
	box, _ := secrets.Load(filepath.Join(t.TempDir(), "k"))
	a := newTestAppDeps(t, func(d *Deps) {
		ms, _ := notify.Migrations()
		if err := d.Store.Migrate(ctx, "notify", ms); err != nil {
			t.Fatal(err)
		}
		nf := notify.NewStore(d.Store, box)
		d.Notify = nf
		d.Dispatcher = notify.NewDispatcher(nf, notify.Senders("test"), d.I18n, func(_, def string) string { return def }, slog.New(slog.NewTextHandler(io.Discard, nil)))
		d.IPv64 = ipv64api.NewKey(d.Store, nil, ipv64api.NewClient(api.URL, "test"), slog.New(slog.NewTextHandler(io.Discard, nil)))
		_ = d.Store.SetSetting(ctx, ipv64api.SetKey, "notifytestkey0123456789abcdef")
	})
	loginAs(t, a, "admin", "sehr geheimes passwort")
	resp, body := a.get(t, "/notifications")
	if resp.StatusCode != 200 || !strings.Contains(body, `id="ipv64-channels"`) || !strings.Contains(body, "Handy Dennis") || strings.Contains(body, "Unbestaetigt") ||
		strings.Contains(body, ">TG<") || !strings.Contains(body, "https://ipv64.net/notifications") || strings.Contains(body, "nf.") {
		t.Fatalf("api key page: %d", resp.StatusCode)
	}
	if strings.Contains(body, "/notifications/new?type=igotify") {
		t.Fatal("igotify still offered")
	}
}
