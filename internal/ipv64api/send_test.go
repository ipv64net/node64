package ipv64api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/store"
)

func TestSendNotification(t *testing.T) {
	routeThere := false
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/hc2/channels":
			_, _ = io.WriteString(w, `{"data":[{"id":5,"type":"ipv64_mail","name":"Mail","enabled":true,"default":true,"verified":true,"lang":"de","notify_down":true,"notify_up":true,"execution":"server","sendable_via_api":true},
				{"id":6,"type":"ipv64_sms","name":"SMS","enabled":true,"default":true,"verified":false,"execution":"server"},
				{"id":7,"type":"webhook","name":"Hook","enabled":true,"default":true,"verified":true,"execution":"local"}]}`)
		case r.URL.Path == "/hc2/channels/5/send" && routeThere:
			b, _ := io.ReadAll(r.Body)
			body = string(b)
			_, _ = io.WriteString(w, `{"data":{"sent":true,"duplicate":false,"sms_left":null}}`)
		case r.URL.Path == "/hc2/channels/9/send" && routeThere:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"status":404,"code":"not_found","detail":"Channel not found."}`)
		default: // Route noch nicht hochgeladen
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"status":404,"code":"not_found","detail":"Unknown endpoint."}`)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(ctx, filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cm, _ := store.CoreMigrations()
	_ = st.Migrate(ctx, "core", cm)
	k := NewKey(st, nil, NewClient(srv.URL, "test"), log)
	ch := &notify.Channel{Name: "Mail", Execution: "server", RemoteID: 5}
	msg := notify.Message{Title: "Titel", Text: "Text", Kind: notify.KindDynIP, EventID: "e1"}

	if err := k.SendNotification(ctx, ch, msg); !errors.Is(err, notify.ErrUnavailable) {
		t.Fatalf("without key: %v", err)
	}
	_ = st.SetSetting(ctx, SetKey, testKey)
	if err := k.SendNotification(ctx, ch, msg); !errors.Is(err, notify.ErrUnavailable) {
		t.Fatalf("route missing must be 'unavailable': %v", err)
	}
	routeThere = true
	if err := k.SendNotification(ctx, ch, msg); err != nil || !strings.Contains(body, `"subject":"Titel"`) || !strings.Contains(body, `"event_id":"e1"`) || !strings.Contains(body, `"kind":"dyndns_ip"`) {
		t.Fatalf("send: %v %s", err, body)
	}
	if err := k.SendNotification(ctx, &notify.Channel{Execution: "server", RemoteID: 9}, msg); err == nil || errors.Is(err, notify.ErrUnavailable) {
		t.Fatalf("unknown channel is a real error: %v", err)
	}
	list := k.RemoteChannels(ctx)
	if len(list) != 1 || list[0].RemoteID != 5 || list[0].ID != -5 || list[0].Execution != "server" || !list[0].Default {
		t.Fatalf("remote channels: %+v", list)
	}
}
