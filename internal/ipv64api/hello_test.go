package ipv64api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Jede Anfrage traegt X-Node64-Node (do, Honeypot-Meldung, Threat Watch); ohne Kennung keine Kopfzeile.
func TestNodeHeader(t *testing.T) {
	var mu sync.Mutex
	got := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got[r.URL.Path] = r.Header.Get(HeaderNode)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"data":{"accepted":true}}`)
	}))
	defer srv.Close()
	ctx := context.Background()
	c := NewClient(srv.URL, "test")
	_ = c.LinkNode(ctx, testKey, "ABCD1234", "", "full")
	if got["/hc2/nodes/link"] != "" {
		t.Fatalf("header without node id: %q", got["/hc2/nodes/link"])
	}
	id := "n0d3n0d3n0d3n0d3n0d3n0d3n0d3n0d3"
	c.SetNodeID(func() string { return id })
	_ = c.LinkNode(ctx, testKey, "ABCD1234", "", "full")
	_, _ = c.HoneypotReport(ctx, testKey, []byte{0x1f, 0x8b})
	_ = c.watchDo(ctx, http.MethodGet, testKey, "/threat/watch", nil, nil)
	for _, p := range []string{"/hc2/nodes/link", "/honeypot/reports", "/threat/watch"} {
		if got[p] != id {
			t.Fatalf("%s: header %q", p, got[p])
		}
	}
}

// Anmeldung: Inhalt (ohne Geheimnisse), erneut nur bei Aenderung; node_removed loest OnRemoved genau einmal aus,
// danach keine Anmeldung mehr, bis ein neuer Key eingetragen ist.
func TestPresence(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	removed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/node64/hello" || r.Header.Get("Authorization") != "Bearer "+testKey {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		bodies = append(bodies, b)
		gone := removed
		mu.Unlock()
		if gone {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"status":403,"code":"node_removed","detail":"This node was removed on ipv64.net."}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"ok":true,"removed":false}}`)
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
	_ = st.SetSetting(ctx, SetKey, testKey) // ohne Pruefung bei /me
	_ = st.SetSetting(ctx, SetAccount, `{"account":"tester"}`)
	name := "Keller"
	calls := 0
	p := NewPresence(PresenceConfig{Client: k.Client(), Key: k.Get, Log: log,
		Info: func(context.Context) Hello {
			return Hello{NodeID: "abc", Name: name, Version: "1.0", OSArch: "linux/amd64", Modules: []string{"healthchecks", "dyndns"},
				Features: HelloFeatures{HCSyncLinked: true, HubNodeID: "abc", HoneypotSensorID: "0f0e0d0c-0000-4000-8000-000000000001", CDN64Tunnel: "t1", DynDNS: true}}
		},
		Removed:   func(ctx context.Context) bool { return !k.Removed(ctx).IsZero() },
		OnRemoved: func(ctx context.Context) { calls++; _ = k.MarkRemoved(ctx) }})
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(bodies) }

	p.Tick(ctx)
	if count() != 1 {
		t.Fatalf("first hello: %d", count())
	}
	b := bodies[0]
	f, _ := b["features"].(map[string]any)
	if b["node_id"] != "abc" || b["name"] != "Keller" || b["os_arch"] != "linux/amd64" || f["hc_sync_linked"] != true || f["hub_node_id"] != "abc" ||
		f["cdn64_tunnel"] != "t1" || f["dyndns"] != true || f["honeypot_sensor_id"] == nil {
		t.Fatalf("payload: %v", b)
	}
	raw, _ := json.Marshal(b)
	for _, secret := range []string{testKey, "token", "apikey"} {
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(secret)) {
			t.Fatalf("payload contains %q: %s", secret, raw)
		}
	}
	now = now.Add(5 * time.Minute)
	p.Tick(ctx) // nichts geaendert, Lebenszeichen noch nicht faellig
	if count() != 1 {
		t.Fatalf("unchanged hello sent again: %d", count())
	}
	name = "Dachboden"
	p.Tick(ctx) // Aenderung: sofort
	if count() != 2 {
		t.Fatalf("changed hello not sent: %d", count())
	}
	now = now.Add(HelloEvery)
	p.Tick(ctx) // Lebenszeichen
	if count() != 3 {
		t.Fatalf("heartbeat not sent: %d", count())
	}

	mu.Lock()
	removed = true
	mu.Unlock()
	now = now.Add(HelloEvery)
	p.Tick(ctx)
	if count() != 4 || calls != 1 || k.Get(ctx) != "" || k.Removed(ctx).IsZero() {
		t.Fatalf("node_removed: hellos %d, calls %d, key %q, removed %v", count(), calls, k.Get(ctx), k.Removed(ctx))
	}
	now = now.Add(HelloEvery)
	p.Tick(ctx)
	if count() != 4 || calls != 1 {
		t.Fatalf("hello after removal: %d / %d", count(), calls)
	}
	// neuer Key (Pruefung ueber /me ist hier nicht moeglich): Set setzt den Merker zurueck; hier von Hand
	_ = st.SetSetting(ctx, SetRemoved, "")
	_ = st.SetSetting(ctx, SetKey, testKey)
	p.Tick(ctx)
	if count() != 5 || calls != 2 {
		t.Fatalf("after new key: hellos %d, calls %d", count(), calls)
	}
}

// Ein neuer, bei ipv64 gepruefter Key hebt den Merker "entfernt" auf.
func TestKeySetClearsRemoved(t *testing.T) {
	srv := fake()
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
	if _, err := k.Set(ctx, testKey); err != nil {
		t.Fatal(err)
	}
	if err := k.MarkRemoved(ctx); err != nil || k.Get(ctx) != "" || k.Removed(ctx).IsZero() {
		t.Fatalf("mark removed: %v", err)
	}
	if _, err := k.Set(ctx, testKey); err != nil || !k.Removed(ctx).IsZero() {
		t.Fatalf("set must clear removed: %v %v", err, k.Removed(ctx))
	}
}
