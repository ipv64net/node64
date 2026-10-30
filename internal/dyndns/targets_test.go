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

	"github.com/ipv64net/node64/internal/ipv64api"
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
				{"id": 15, "prefix": "web", "fqdn": "web.home.ipv64.net", "type": "A", "content": "185.1.2.3", "state": "cdn_record", "token": tokIgn},
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

// Auswahl: je Name zusammengefasst, A-Token bevorzugt, Interface-ID -> Praefix-Modus, ignorierte Familie aus,
// ueber das CDN geleitete Namen waehlbar (nur die Ursprungsadresse, nie die CDN-Records), inaktive Domains und andere Record-Typen weggelassen.
func TestAccountNames(t *testing.T) {
	srv := fakeIPv64(t)
	defer srv.Close()
	m, core := newTargetModule(t, false)
	m.SetKey(ipv64api.NewKey(core, nil, ipv64api.NewClient(srv.URL, "test"), slog.New(slog.NewTextHandler(io.Discard, nil))))
	if err := core.SetSetting(context.Background(), ipv64api.SetKey, testKey); err != nil {
		t.Fatal(err)
	}
	if m.keyOf(context.Background()) != testKey {
		t.Fatal("central key not readable")
	}
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
	if h := got["home.ipv64.net"]; h.Def4 != Mode4Auto || h.Def6 != Mode6Host || h.SuffixOf != "::1" || got["nas.home.ipv64.net"].SuffixOf != "" {
		t.Fatalf("pick defaults: %+v", h)
	}
	if suffixOf("2a01:4f8:1:2:1a2b:3c4d:5e6f:7a8b") != "::1a2b:3c4d:5e6f:7a8b" || suffixOf("2a01:4f8:1:2::") != "" {
		t.Fatal("suffixOf")
	}
	home := m.defaultsFor(got["home.ipv64.net"])
	if home.Token != tokA || home.RecordID != 10 || home.Mode4 != Mode4Auto || home.Mode6 != Mode6Host || home.TokenKind != "record" {
		t.Fatalf("home: %+v", home)
	}
	if nas := m.defaultsFor(got["nas.home.ipv64.net"]); nas.Mode6 != Mode6Prefix || nas.Mode4 != Mode4Off || nas.Token != tokSuf {
		t.Fatalf("nas: %+v", nas)
	}
	if w := got["web.home.ipv64.net"]; w.Blocked != "" || !w.CDN || len(w.A) != 1 || w.A[0] != "93.184.216.35" || m.defaultsFor(w).Token != tokOther {
		t.Fatalf("web (cdn): %+v", w)
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
	if err != nil || back.Token != tokA || back.FQDN() != "nas.home.ipv64.net" || back.Suffix6 != "::1:2:3:4" || back.TokenMasked() != "…AAAA" {
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
	// feste Adressen werden kanonisch gespeichert, ::ffff:-Adressen gelten nicht als IPv6
	tg := base()
	tg.Mode6, tg.Fixed6 = Mode6Fixed, "2a01:04F8:0:0::1"
	if err := tg.Normalize(); err != nil || tg.Fixed6 != "2a01:4f8::1" {
		t.Errorf("fixed6 kanonisch: %q %v", tg.Fixed6, err)
	}
	tg.Mode6, tg.Fixed6 = Mode6Fixed, "::ffff:8.8.8.8"
	if err := tg.Normalize(); err == nil || err.Error() != "fixed6" {
		t.Errorf("fixed6 4in6: %v", err)
	}
	a, err := withSuffix(netip.MustParsePrefix("2a01:4f8:1:2::/64"), "::1a2b:3c4d:5e6f:7a8b")
	if err != nil || a.String() != "2a01:4f8:1:2:1a2b:3c4d:5e6f:7a8b" {
		t.Fatalf("withSuffix: %s %v", a, err)
	}
}

func TestGroupTargets(t *testing.T) {
	g := groupTargets([]*Target{{Domain: "a.ipv64.net"}, {Domain: "a.ipv64.net", Host: "nas"}, {Domain: "b.any64.de", Host: "x"}})
	if len(g) != 2 || len(g[0].Items) != 2 || g[0].Items[1].Host != "nas" || g[1].Domain != "b.any64.de" {
		t.Fatalf("groups: %+v", g)
	}
}
