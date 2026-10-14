package dyndns

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

const (
	testKey  = "abcdefghijklmnopqrstuvwxyz012345"
	tokA     = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tokAAAA  = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	tokSuf   = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	tokIgn   = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
	tokOther = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
)

// fakeIPv64 bildet die benutzten Routen der API v2 nach.
func fakeIPv64(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testKey {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"status":401,"code":"unauthorized","detail":"bad key"}`)
			return
		}
		data := map[string]any{}
		switch r.URL.Path {
		case "/me":
			data = map[string]any{"id": 522, "email": "t@example.com", "username": "tester", "plan": map[string]any{"name": "Supporter"},
				"usage": map[string]any{"dyndns_updates_24h": map[string]any{"used": 3, "limit": 64}}}
		case "/domains":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{
				{"id": 1, "name": "home.ipv64.net", "kind": "dyndns", "zone": "ipv64.net", "ignore": "none", "active": true, "update_token": "domtok"},
				{"id": 2, "name": "dslite.any64.de", "kind": "dyndns", "zone": "any64.de", "ignore": "ipv4", "active": true, "update_token": "domtok2"},
				{"id": 3, "name": "off.ipv64.net", "kind": "dyndns", "zone": "ipv64.net", "ignore": "none", "active": false},
			}})
			return
		case "/domains/home.ipv64.net/records":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{
				{"id": 11, "prefix": "", "fqdn": "home.ipv64.net", "type": "AAAA", "content": "2a01:4f8::1", "state": "active", "token": tokAAAA},
				{"id": 10, "prefix": "", "fqdn": "home.ipv64.net", "type": "A", "content": "93.184.216.34", "state": "active", "token": tokA},
				{"id": 12, "prefix": "nas", "fqdn": "nas.home.ipv64.net", "type": "AAAA", "content": "::1:2:3:4", "state": "active", "token": tokSuf},
				{"id": 13, "prefix": "web", "fqdn": "web.home.ipv64.net", "type": "A", "content": "93.184.216.35", "state": "cdn_proxied", "token": tokOther},
				{"id": 14, "prefix": "mail", "fqdn": "mail.home.ipv64.net", "type": "MX", "content": "x", "state": "active", "token": tokOther},
			}})
			return
		case "/domains/dslite.any64.de/records":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{
				{"id": 20, "prefix": "", "fqdn": "dslite.any64.de", "type": "A", "content": "1.2.3.4", "state": "active", "token": tokIgn},
				{"id": 21, "prefix": "", "fqdn": "dslite.any64.de", "type": "AAAA", "content": "2a01::5", "state": "active", "token": tokOther},
			}})
			return
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"status":404,"code":"not_found","detail":"no such route"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
}

func newTargetModule(t *testing.T, withBox bool) (*Module, *store.Store) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(ctx, filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	cm, _ := store.CoreMigrations()
	if err := core.Migrate(ctx, "core", cm); err != nil {
		t.Fatal(err)
	}
	var box *secrets.Box
	if withBox {
		box, _ = secrets.New([]byte("0123456789abcdef0123456789abcdef"))
	}
	m := New(core, log, box, nil, "test")
	if err := core.Migrate(ctx, Name, m.Migrations()); err != nil {
		t.Fatal(err)
	}
	return m, core
}

func TestAPIClient(t *testing.T) {
	srv := fakeIPv64(t)
	defer srv.Close()
	c := newAPIClient(srv.URL, "test")
	ctx := context.Background()
	me, err := c.me(ctx, testKey)
	if err != nil || me.Account() != "tester" || me.Plan.Name != "Supporter" || me.Usage.DynDNSUpdates.Used != 3 || *me.Usage.DynDNSUpdates.Limit != 64 {
		t.Fatalf("me: %+v %v", me, err)
	}
	if _, err := c.me(ctx, "wrongwrongwrongwrong"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("want unauthorized, got %v", err)
	}
	if _, err := c.records(ctx, testKey, "nix.ipv64.net"); err == nil || !strings.Contains(err.Error(), "no such route") {
		t.Fatalf("want problem detail, got %v", err)
	}
}

// Auswahl: je Name zusammengefasst, A-Token bevorzugt, Interface-ID -> Praefix-Modus, ignorierte Familie aus,
// CDN gesperrt, inaktive Domains und andere Record-Typen weggelassen.
func TestAccountNames(t *testing.T) {
	srv := fakeIPv64(t)
	defer srv.Close()
	m, _ := newTargetModule(t, false)
	m.api = newAPIClient(srv.URL, "test")
	names, err := m.accountNames(context.Background(), testKey)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*pickName{}
	for _, p := range names {
		got[p.FQDN] = p
	}
	if len(names) != 4 || got["mail.home.ipv64.net"] != nil || got["off.ipv64.net"] != nil {
		t.Fatalf("names: %d %v", len(names), got)
	}
	home := m.defaultsFor(got["home.ipv64.net"])
	if home.Token != tokA || home.RecordID != 10 || home.Mode4 != Mode4Auto || home.Mode6 != Mode6Host || home.TokenKind != "record" {
		t.Fatalf("home: %+v", home)
	}
	if nas := m.defaultsFor(got["nas.home.ipv64.net"]); nas.Mode6 != Mode6Prefix || nas.Mode4 != Mode4Off || nas.Token != tokSuf {
		t.Fatalf("nas: %+v", nas)
	}
	if got["web.home.ipv64.net"].Blocked != "cdn_proxied" {
		t.Fatalf("web should be blocked: %+v", got["web.home.ipv64.net"])
	}
	if ds := m.defaultsFor(got["dslite.any64.de"]); ds.Mode4 != Mode4Off || ds.Mode6 != Mode6Host || ds.Token != tokIgn {
		t.Fatalf("dslite: %+v", ds)
	}
}

// Speicher: Token verschluesselt in der Datenbank, im Speicher lesbar; Name eindeutig.
func TestTargetStore(t *testing.T) {
	ctx := context.Background()
	m, core := newTargetModule(t, true)
	tg := &Target{Domain: "Home.IPv64.net.", Host: "NAS", TokenKind: "record", Token: tokA, Mode4: Mode4Auto, Mode6: Mode6Suffix, Suffix6: "1:2:3:4", Enabled: true}
	if err := m.InsertTarget(ctx, tg); err != nil {
		t.Fatal(err)
	}
	var raw string
	_ = core.Reader().QueryRow(`SELECT token FROM dyn_targets WHERE id = ?`, tg.ID).Scan(&raw)
	if !secrets.IsEncrypted(raw) || strings.Contains(raw, tokA) {
		t.Fatalf("token not encrypted: %q", raw)
	}
	back, err := m.Target(ctx, tg.ID)
	if err != nil || back.Token != tokA || back.FQDN() != "nas.home.ipv64.net" || back.Suffix6 != "::1:2:3:4" || back.TokenMasked() != "AAAA…AAAA" {
		t.Fatalf("read back: %+v %v", back, err)
	}
	dup := &Target{Domain: "home.ipv64.net", Host: "nas", TokenKind: "record", Token: tokA, Mode4: Mode4Auto, Mode6: Mode6Off}
	if err := m.InsertTarget(ctx, dup); !errors.Is(err, ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}
	back.Mode6, back.Enabled = Mode6Off, false
	if err := m.UpdateTarget(ctx, back); err != nil {
		t.Fatal(err)
	}
	if again, _ := m.Target(ctx, tg.ID); again.Mode6 != Mode6Off || again.Enabled || again.Token != tokA {
		t.Fatalf("update: %+v", again)
	}
	if err := m.DeleteTarget(ctx, tg.ID); err != nil {
		t.Fatal(err)
	}
	if gone, err := m.Target(ctx, tg.ID); gone != nil || err != nil {
		t.Fatalf("delete: %v %v", gone, err)
	}
}

func TestNormalize(t *testing.T) {
	base := func() *Target {
		return &Target{Domain: "home.ipv64.net", TokenKind: "record", Token: tokA, Mode4: Mode4Auto, Mode6: Mode6Off}
	}
	for name, c := range map[string]struct {
		mod  func(*Target)
		want string
	}{
		"ok":          {func(*Target) {}, ""},
		"apex @":      {func(t *Target) { t.Host = "@" }, ""},
		"bad domain":  {func(t *Target) { t.Domain = "localhost" }, "domain"},
		"bad host":    {func(t *Target) { t.Host = "a b" }, "host"},
		"short token": {func(t *Target) { t.Token = "abc" }, "token"},
		"none":        {func(t *Target) { t.Mode4 = Mode4Off }, "mode_none"},
		"fixed4 priv": {func(t *Target) { t.Mode4, t.Fixed4 = Mode4Fixed, "192.168.1.2" }, "fixed4"},
		"suffix bad":  {func(t *Target) { t.Mode6, t.Suffix6 = Mode6Suffix, "2a01::1" }, "suffix6"},
		"iface bad":   {func(t *Target) { t.Mode6, t.Iface = Mode6Iface, "eth0; rm" }, "iface"},
		"kind bad":    {func(t *Target) { t.TokenKind = "account" }, "token_kind"},
	} {
		tg := base()
		c.mod(tg)
		err := tg.Normalize()
		if (err == nil && c.want != "") || (err != nil && err.Error() != c.want) {
			t.Errorf("%s: got %v want %q", name, err, c.want)
		}
	}
	a, err := withSuffix(netip.MustParsePrefix("2a01:4f8:1:2::/64"), "::1a2b:3c4d:5e6f:7a8b")
	if err != nil || a.String() != "2a01:4f8:1:2:1a2b:3c4d:5e6f:7a8b" {
		t.Fatalf("withSuffix: %s %v", a, err)
	}
}
