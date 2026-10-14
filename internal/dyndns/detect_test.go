package dyndns

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/store"
)

func TestExtractIP(t *testing.T) {
	cases := []struct {
		body string
		fam  int
		want string
	}{
		{"93.184.216.34\n", 4, "93.184.216.34"},
		{`{"data":{"ip":"93.184.216.34","family":"ipv4"}}`, 4, "93.184.216.34"},
		{`{"data":{"ip":"2a01:4f8:1:2::3","family":"ipv6"}}`, 6, "2a01:4f8:1:2::3"},
		{"2a01:4f8:1:2::3", 4, ""},
		{"", 4, ""},
		{"::ffff:93.184.216.34", 4, "93.184.216.34"},
	}
	for _, c := range cases {
		a, ok := extractIP(c.body, c.fam)
		if got := map[bool]string{true: a.String(), false: ""}[ok]; got != c.want {
			t.Errorf("%q/%d: got %q want %q", c.body, c.fam, got, c.want)
		}
	}
}

func TestPublicAddr(t *testing.T) {
	for s, want := range map[string]bool{
		"93.184.216.34": true, "10.1.2.3": false, "172.17.0.2": false, "192.168.1.1": false, "100.64.1.1": false, "127.0.0.1": false,
		"2a01:4f8:1:2::3": true, "fd00::1": false, "fe80::1": false, "::1": false, "2001:db8::1": false,
	} {
		if got := publicAddr(netip.MustParseAddr(s)); got != want {
			t.Errorf("%s: got %v want %v", s, got, want)
		}
	}
	if p := prefix64(netip.MustParseAddr("2a01:4f8:1:2:aaaa:bbbb:cccc:dddd")).String(); p != "2a01:4f8:1:2::/64" {
		t.Errorf("prefix64 = %s", p)
	}
}

func TestParseIfInet6(t *testing.T) {
	in := strings.Join([]string{
		"2a0104f8000100020000000000000003 02 40 00 80 eth0", // stabil
		"2a0104f80001000212345678abcdef01 02 40 00 01 eth0", // temporaer
		"fe800000000000000000000000000001 02 40 20 80 eth0", // link-local
		"00000000000000000000000000000001 01 80 10 80 lo",
		"2a0104f8000100020000000000000004 02 40 00 c0 eth0", // tentative
	}, "\n")
	got := parseIfInet6(strings.NewReader(in))
	if len(got) != 2 || got[0].Temporary || !got[1].Temporary || got[0].Addr.String() != "2a01:4f8:1:2::3" || got[0].Iface != "eth0" {
		t.Fatalf("got %+v", got)
	}
}

// Pruefrunde: eigene Quelle zuerst, Rueckfall bei Fehler, Aenderung nur bei neuer Adresse, ohne Route kein Abruf.
func TestRound(t *testing.T) {
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
	m := New(core, log, nil, nil, "test")
	if err := core.Migrate(ctx, Name, m.Migrations()); err != nil {
		t.Fatal(err)
	}
	_ = core.SetSetting(ctx, SetSource4, "https://own.example/ip")
	ip4 := "93.184.216.34"
	var asked []string
	m.fetch = func(_ context.Context, fam int, src string) (netip.Addr, error) {
		asked = append(asked, src)
		if src == "https://own.example/ip" {
			return netip.Addr{}, errors.New("HTTP 500")
		}
		return netip.MustParseAddr(ip4), nil
	}
	m.probe = func(fam int) bool { return fam == 4 }

	m.round(ctx)
	if len(asked) != 2 || asked[1] != defaultSource4 {
		t.Fatalf("asked %v", asked)
	}
	if s := m.state(4); s.IP.String() != ip4 || s.Err != "" || s.Source != "ipv4.ipv64.net" {
		t.Fatalf("v4 state %+v", s)
	}
	if s := m.state(6); !s.NoRoute || s.IP.IsValid() {
		t.Fatalf("v6 state %+v", s)
	}
	m.round(ctx) // gleiche Adresse -> keine Aenderung
	ip4 = "93.184.216.35"
	m.round(ctx) // neue Adresse
	var changed, total int
	_ = core.Reader().QueryRow(`SELECT count(*), coalesce(sum(changed),0) FROM dyn_checks WHERE family = '4'`).Scan(&total, &changed)
	if total != 3 || changed != 2 { // erste Ermittlung und Wechsel
		t.Fatalf("total %d changed %d", total, changed)
	}
	m2 := New(core, log, nil, nil, "test") // Neustart: Stand aus dem Protokoll
	m2.loadState(ctx)
	if s := m2.state(4); s.IP.String() != "93.184.216.35" || s.ChangedAt.IsZero() {
		t.Fatalf("reloaded %+v", s)
	}
}
