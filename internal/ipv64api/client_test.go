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

	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

const testKey = "abcdefghijklmnopqrstuvwxyz012345"

func fake() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testKey {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"status":401,"code":"unauthorized","detail":"bad key"}`)
			return
		}
		if r.URL.Path != "/me" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"status":404,"code":"not_found","detail":"no such route"}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"id":522,"email":"t@example.com","username":"tester","plan":{"name":"Supporter"},"usage":{"dyndns_updates_24h":{"used":3,"limit":64}}}}`)
	}))
}

func TestClient(t *testing.T) {
	srv := fake()
	defer srv.Close()
	c := NewClient(srv.URL, "test")
	ctx := context.Background()
	me, err := c.Me(ctx, testKey)
	if err != nil || me.Account() != "tester" || me.Plan.Name != "Supporter" || me.Usage.DynDNSUpdates.Used != 3 || *me.Usage.DynDNSUpdates.Limit != 64 {
		t.Fatalf("me: %+v %v", me, err)
	}
	if _, err := c.Me(ctx, "wrongwrongwrongwrong"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("want unauthorized, got %v", err)
	}
	if _, err := c.Records(ctx, testKey, "nix.ipv64.net"); err == nil || !strings.Contains(err.Error(), "no such route") {
		t.Fatalf("want problem detail, got %v", err)
	}
}

// Ablage: Format pruefen, bei ipv64 pruefen, verschluesselt speichern, erneut pruefen, entfernen, Umzug.
func TestKey(t *testing.T) {
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
	box, _ := secrets.New([]byte("0123456789abcdef0123456789abcdef"))
	k := NewKey(st, box, NewClient(srv.URL, "test"), log)
	if _, err := k.Set(ctx, "kurz"); !errors.Is(err, ErrFormat) {
		t.Fatalf("want ErrFormat, got %v", err)
	}
	if _, err := k.Set(ctx, "wrongwrongwrongwrong"); !errors.Is(err, ErrUnauthorized) || k.Get(ctx) != "" {
		t.Fatalf("rejected key must not be stored: %v", err)
	}
	if _, err := k.Set(ctx, testKey); err != nil {
		t.Fatal(err)
	}
	if raw := st.SettingOr(ctx, SetKey, ""); !secrets.IsEncrypted(raw) || strings.Contains(raw, testKey) {
		t.Fatalf("not encrypted: %q", raw)
	}
	if k.Get(ctx) != testKey || k.Info(ctx).Account != "tester" || k.Info(ctx).Plan != "Supporter" {
		t.Fatalf("get/info: %q %+v", k.Get(ctx), k.Info(ctx))
	}
	if _, err := k.Set(ctx, ""); err != nil { // erneut pruefen
		t.Fatal(err)
	}
	if k.Adopt(ctx, box.Encrypt("other"), "") {
		t.Fatal("adopt must not overwrite an existing key")
	}
	if err := k.Clear(ctx); err != nil || k.Get(ctx) != "" || k.Info(ctx).Account != "" {
		t.Fatal("clear")
	}
	if !k.Adopt(ctx, box.Encrypt(testKey), `{"account":"tester"}`) || k.Get(ctx) != testKey {
		t.Fatal("adopt")
	}
}
