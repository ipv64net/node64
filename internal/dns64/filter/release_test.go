package filter

import (
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

// Freigabe-Listen: jede Regel gibt frei (auch @@-Ausnahmen, samt Subdomains bei ||x^); die eigene Sperrliste
// geht vor, nicht gesperrte Namen bleiben unberuehrt.
func TestReleaseManager(t *testing.T) {
	dir := t.TempDir()
	a, _ := LoadAllowlist(filepath.Join(dir, "allow.txt"))
	d, _ := LoadDenylist(filepath.Join(dir, "deny.txt"))
	m := &Manager{Allow: a, Deny: d}
	mt := newMatcher([]string{"ads"})
	mt.load(0, strings.NewReader("||tracker.example^\n||cdn.example^\n0.0.0.0 shop.example\n||own.example^\n"))
	m.cur.Store(mt)

	rel := &Manager{lists: []List{{Name: "ok", URL: "https://x.example/ok.txt"}}, release: true}
	rm := newMatcher([]string{"ok"})
	rm.loadAs(0, strings.NewReader("@@||cdn.example^\nshop.example\n||own.example^\n"), true)
	rel.cur.Store(rm)
	m.Release = rel

	if _, err := d.Add("own.example"); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name    string
		blocked bool
		reason  string
	}{
		{"tracker.example", true, "ads"},
		{"img.cdn.example", false, ReleasedPrefix + "ads"}, // @@ als Freigabe samt Subdomains
		{"shop.example", false, ReleasedPrefix + "ads"},
		{"own.example", true, OwnPrefix + "own.example"}, // eigene Sperrliste schlaegt Freigabe-Liste
		{"free.example", false, ""},
	} {
		if b, r := m.Check(tt.name); b != tt.blocked || r != tt.reason {
			t.Errorf("Check(%s) = %v %q, want %v %q", tt.name, b, r, tt.blocked, tt.reason)
		}
	}
	if l, ok := rel.Released("x.cdn.example"); !ok || l != "ok" {
		t.Fatalf("Released: %q %v", l, ok)
	}

	// ohne Listen gibt nichts frei, nil ist erlaubt
	empty, err := NewReleaseManager(filepath.Join(dir, "allowlists"), nil, 0, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := empty.Released("cdn.example"); ok {
		t.Fatal("empty release manager releases")
	}
	var none *Manager
	if _, ok := none.Released("cdn.example"); ok {
		t.Fatal("nil release manager releases")
	}
}

// Textfeld: Kommentare, "*.", Zeitstempel und Doppelte; alte Eintraege behalten ihr Datum; nur ungueltige
// Zeilen lassen die Liste unveraendert.
func TestAllowlistReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deny.txt")
	d, _ := LoadDenylist(path)
	if _, err := d.Add("alt.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Add("weg.example"); err != nil {
		t.Fatal(err)
	}
	before := d.List()
	res, err := d.Replace(strings.Split("# Kommentar\nalt.example\n*.Neu.Example\nneu.example # doppelt\nnicht gueltig!\n\nzwei.example\t2026-01-01T00:00:00Z", "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 3 || res.Added != 2 || res.Removed != 1 || res.Duplicates != 1 || len(res.Invalid) != 1 || res.Invalid[0] != "nicht" {
		t.Fatalf("result: %+v", res)
	}
	if got := d.Text(); got != "alt.example\nneu.example\nzwei.example" {
		t.Fatalf("text: %q", got)
	}
	for _, e := range d.List() {
		for _, b := range before {
			if e.Domain == b.Domain && !e.AddedAt.Equal(b.AddedAt) {
				t.Fatal("existing entry lost its date")
			}
		}
	}
	if _, ok := d.Match("x.neu.example"); !ok {
		t.Fatal("subdomain not matched")
	}
	if r, _ := LoadDenylist(path); r.Text() != d.Text() {
		t.Fatal("not persisted")
	}

	if res, err := d.Replace([]string{"kaputt", "auch kaputt"}); err != ErrInvalidDomain || res.Total != 3 || len(res.Invalid) != 2 {
		t.Fatalf("all invalid: %v %+v", err, res)
	}
	if res, err := d.Replace(nil); err != nil || res.Total != 0 || res.Removed != 3 {
		t.Fatalf("empty text must clear: %v %+v", err, res)
	}
	var nilList *Allowlist
	if nilList.Text() != "" {
		t.Fatal("nil text")
	}
}

// Dienste: als Gruppen-Schluessel bekannt, mit Namen und Domains; unbekannte fallen weg.
func TestServices(t *testing.T) {
	ids := map[string]bool{}
	for _, s := range Services {
		if ids[s.ID] || s.Name == "" || len(s.Domains) == 0 {
			t.Fatalf("service %q: duplicate or empty", s.ID)
		}
		ids[s.ID] = true
		found := false
		for _, g := range ServiceGroups {
			found = found || g == s.Group
		}
		if !found {
			t.Fatalf("service %q: unknown group %q", s.ID, s.Group)
		}
	}
	for key, name := range map[string]string{"svc:tiktok": "www.tiktok.com", "svc:youtube": "i.ytimg.com", "svc:discord": "cdn.discordapp.com", "svc:whatsapp": "web.whatsapp.com", "svc:steam": "store.steampowered.com"} {
		if !IsGroupKey(key) || ServiceName(key) == "" {
			t.Fatalf("%s not known", key)
		}
		if _, ok := GroupCategory(key).Match(name); !ok {
			t.Errorf("%s: %s not matched", key, name)
		}
	}
	if IsGroupKey("svc:gibtsnicht") || ServiceName("tiktok") != "" || GroupCategory("svc:gibtsnicht") != nil {
		t.Fatal("unknown service accepted")
	}
	got := GroupKeys([]string{"svc:tiktok", "games", "kaputt", "social", "svc:tiktok"})
	if strings.Join(got, ",") != "social,games,svc:tiktok" {
		t.Fatalf("GroupKeys: %v", got)
	}
}
