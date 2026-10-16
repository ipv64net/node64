package ipv64api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/ipv64net/node64/internal/store"
)

// Account-Klassen: ohne Endpunkt der eingebaute Stand, mit Endpunkt die Daten von ipv64 (ohne Key, einmal am Tag).
func TestPlans(t *testing.T) {
	var up atomic.Bool
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Errorf("plans must be fetched without a key")
		}
		if !up.Load() || r.URL.Path != "/plans" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"data":[{"id":1,"key":"free","name":"Free","class_name":"Standard","price_year_eur":0,"limits":{"healthchecks":4}},
			{"id":6,"key":"supporter","name":"Home / Supporter","class_name":"Supporter","price_year_eur":40,"limits":{"healthchecks":12,"sms_24h":null}}]}`)
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
	if err := st.Migrate(ctx, "core", cm); err != nil {
		t.Fatal(err)
	}
	k := NewKey(st, nil, NewClient(srv.URL, "test"), log)
	list, live := k.Plans(ctx)
	if live || len(list) != 4 || PlanFor(list, "Supporter") == nil || PlanFor(list, "VIP") != nil {
		t.Fatalf("builtin fallback: live=%v %d", live, len(list))
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("one attempt expected, got %d", n)
	}
	k.Plans(ctx) // Fehlschlag gerade erst: kein neuer Versuch
	if n := calls.Load(); n != 1 {
		t.Fatalf("failed fetch must not be retried at once: %d", n)
	}
	// Endpunkt da: nach Ablauf der Sperre die Daten von ipv64, danach aus dem Zwischenspeicher
	up.Store(true)
	_ = st.SetSetting(ctx, setPlansAt, "")
	list, live = k.Plans(ctx)
	if !live || len(list) != 2 || *PlanFor(list, "Standard").Limits["healthchecks"] != 4 || PlanFor(list, "Supporter").Limits["sms_24h"] != nil {
		t.Fatalf("live plans: live=%v %+v", live, list)
	}
	before := calls.Load()
	if list, live = k.Plans(ctx); !live || len(list) != 2 || calls.Load() != before {
		t.Fatal("cached plans must be used for a day")
	}
}
