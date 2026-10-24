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
	"strings"
	"sync"
	"testing"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
)

// fakeHC2Channels bildet die Kanal-Routen der ipv64-API v2 nach (Liste, anlegen, aendern, loeschen, bestaetigen).
type fakeHC2Channels struct {
	mu    sync.Mutex
	next  int64
	chans map[int64]map[string]any
	calls []string
}

func (f *fakeHC2Channels) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	data := func(v any) { b, _ := json.Marshal(map[string]any{"data": v}); _, _ = w.Write(b) }
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/hc2/channels"), "/"), "/")
	var id int64
	if parts[0] != "" {
		_ = json.Unmarshal([]byte(parts[0]), &id)
	}
	ch := f.chans[id]
	switch {
	case r.Method == "GET" && parts[0] == "":
		list := []any{}
		for _, c := range f.chans {
			list = append(list, c)
		}
		data(list)
	case r.Method == "POST" && parts[0] == "":
		f.next++
		c := map[string]any{"id": f.next, "type": body["type"], "name": body["name"], "lang": body["lang"], "config": body["config"], "enabled": true, "default": body["default"], "verified": false}
		f.chans[f.next] = c
		data(c)
	case ch == nil:
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"code":"not_found","detail":"Channel not found."}`)
	case r.Method == "GET":
		data(ch)
	case r.Method == "PATCH":
		for k, v := range body {
			ch[k] = v
		}
		data(ch)
	case r.Method == "DELETE":
		delete(f.chans, id)
		w.WriteHeader(204)
	case len(parts) == 3 && parts[1] == "verify" && parts[2] == "send":
		data(map[string]any{"sent": true})
	case len(parts) == 2 && parts[1] == "verify":
		if body["code"] != "123456" {
			w.WriteHeader(422)
			_, _ = io.WriteString(w, `{"code":"invalid_code","detail":"Code wrong or expired."}`)
			return
		}
		ch["verified"] = true
		data(ch)
	case len(parts) == 2 && parts[1] == "test":
		data(map[string]any{"sent": true})
	}
}

// E-Mail und SMS ueber ipv64 stehen mit API-Key (ohne Verknuepfung) in der normalen Kanaltabelle und lassen sich dort
// verwalten: anlegen, per Code bestaetigen, an/aus, loeschen. iGotify ist kein eigener Menuepunkt mehr.
func TestNotificationsIPv64Channels(t *testing.T) {
	ctx := context.Background()
	fake := &fakeHC2Channels{next: 4, chans: map[int64]map[string]any{
		4: {"id": 4, "type": "telegram", "name": "TG", "enabled": true, "verified": true}, // kein ipv64-Typ: nicht in der Tabelle
	}}
	api := httptest.NewServer(fake)
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
	if resp.StatusCode != 200 || !strings.Contains(body, `href="/notifications/ipv64/new?type=ipv64_sms"`) || strings.Contains(body, ">TG<") ||
		strings.Contains(body, "/notifications/new?type=igotify") || strings.Contains(body, "nf.") || !strings.Contains(body, `id="browser-notify-card"`) {
		t.Fatalf("page: %d", resp.StatusCode)
	}
	csrf := csrfOf(t, body)
	// anlegen -> Bestaetigung
	_, form := a.get(t, "/notifications/ipv64/new?type=ipv64_sms")
	if !strings.Contains(form, `action="/notifications/ipv64/new"`) || !strings.Contains(form, `name="cfg_number"`) {
		t.Fatal("form")
	}
	resp, _ = a.post(t, "/notifications/ipv64/new", url.Values{"_csrf": {csrf}, "type": {"ipv64_sms"}, "name": {"Handy"}, "lang": {"de"}, "enabled": {"on"}, "default": {"on"},
		"notify_down": {"on"}, "notify_up": {"on"}, "cfg_number": {"+49 177 1234567"}})
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/notifications/ipv64/5/verify" {
		t.Fatalf("create: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	_, body = a.get(t, "/notifications")
	if !strings.Contains(body, ">Handy</a>") || !strings.Contains(body, `href="/notifications/ipv64/5/verify"`) || !strings.Contains(body, `action="/notifications/ipv64/5/toggle"`) {
		t.Fatal("row in table")
	}
	_, vpage := a.get(t, "/notifications/ipv64/5/verify")
	if !strings.Contains(vpage, `action="/notifications/ipv64/5/verify/send"`) {
		t.Fatal("verify page")
	}
	if resp, _ = a.post(t, "/notifications/ipv64/5/verify", url.Values{"_csrf": {csrf}, "code": {"000000"}}); resp.Header.Get("Location") != "/notifications/ipv64/5/verify" {
		t.Fatal("wrong code accepted")
	}
	if resp, _ = a.post(t, "/notifications/ipv64/5/verify", url.Values{"_csrf": {csrf}, "code": {"123456"}}); resp.Header.Get("Location") != "/notifications" {
		t.Fatal("verify")
	}
	_, body = a.get(t, "/notifications")
	if strings.Contains(body, `href="/notifications/ipv64/5/verify"`) {
		t.Fatal("still unverified")
	}
	// an/aus und loeschen
	a.post(t, "/notifications/ipv64/5/toggle", url.Values{"_csrf": {csrf}, "field": {"enabled"}})
	fake.mu.Lock()
	enabled := fake.chans[5]["enabled"]
	fake.mu.Unlock()
	if enabled != false {
		t.Fatalf("toggle: %v", enabled)
	}
	a.post(t, "/notifications/ipv64/5/delete", url.Values{"_csrf": {csrf}})
	fake.mu.Lock()
	_, still := fake.chans[5]
	fake.mu.Unlock()
	if still {
		t.Fatal("not deleted")
	}
}
