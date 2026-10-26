package filter

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		in   string
		want string
		kind ruleKind
	}{
		{"0.0.0.0 ads.example.com", "ads.example.com", ruleExact},
		{"127.0.0.1 Tracker.Example.COM # comment", "tracker.example.com", ruleExact},
		{"0.0.0.0 localhost", "", ruleNone},
		{"0.0.0.0 0.0.0.0", "", ruleNone},
		{"::1 ip6-localhost", "", ruleNone},
		{"plain.example.org", "plain.example.org", ruleExact},
		{"||ads.example.net^", "ads.example.net", ruleWildcard},
		{"||*.cdn.example.net^", "cdn.example.net", ruleWildcard},
		{"||ads.example.net^|", "ads.example.net", ruleWildcard},
		{"||ads.example.net^$important", "ads.example.net", ruleWildcard},
		{"||ads.example.net^$third-party", "", ruleNone},
		{"||example.net/path^", "", ruleNone},
		{"@@||good.example.net^", "good.example.net", ruleAllow},
		{"@@||good.example.net^|", "good.example.net", ruleAllow},
		{"! comment", "", ruleNone},
		{"# comment", "", ruleNone},
		{"[Adblock Plus 2.0]", "", ruleNone},
		{"example.com##.banner", "", ruleNone},
		{"com", "", ruleNone},
		{"", "", ruleNone},
		{"bad_host!.com", "", ruleNone},
	}
	for _, tt := range tests {
		got, kind := parseLine(tt.in)
		if got != tt.want || kind != tt.kind {
			t.Errorf("parseLine(%q) = %q, %d; want %q, %d", tt.in, got, kind, tt.want, tt.kind)
		}
	}
}

func TestMatcher(t *testing.T) {
	m := newMatcher([]string{"hosts", "adblock"})
	m.load(0, strings.NewReader("0.0.0.0 exact.example.com\n"))
	m.load(1, strings.NewReader("||wild.example.org^\n@@||ok.wild.example.org^\n"))

	tests := []struct {
		name    string
		blocked bool
		list    string
	}{
		{"exact.example.com", true, "hosts"},
		{"sub.exact.example.com", false, ""}, // hosts entries are exact
		{"example.com", false, ""},
		{"wild.example.org", true, "adblock"},
		{"a.b.wild.example.org", true, "adblock"},
		{"ok.wild.example.org", false, ""}, // exception wins
		{"x.ok.wild.example.org", false, ""},
		{"notwild.example.org", false, ""},
	}
	for _, tt := range tests {
		blocked, list := m.Match(tt.name)
		if blocked != tt.blocked || list != tt.list {
			t.Errorf("Match(%q) = %v, %q; want %v, %q", tt.name, blocked, list, tt.blocked, tt.list)
		}
	}
	if m.Size() != 2 {
		t.Errorf("Size() = %d, want 2", m.Size())
	}
}

func TestAllowlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allow.txt")
	a, err := LoadAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Add("Ads.Example.com."); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Add("not a domain"); err != ErrInvalidDomain {
		t.Fatalf("want ErrInvalidDomain, got %v", err)
	}
	for name, want := range map[string]bool{
		"ads.example.com": true, "x.ads.example.com": true, "example.com": false, "bads.example.com": false,
	} {
		if got := a.Contains(name); got != want {
			t.Errorf("Contains(%q) = %v, want %v", name, got, want)
		}
	}

	// persisted across reloads
	b, err := LoadAllowlist(path)
	if err != nil || !b.Contains("ads.example.com") {
		t.Fatalf("reload lost entry: %v", err)
	}
	if err := b.Remove("ads.example.com"); err != nil {
		t.Fatal(err)
	}
	c, _ := LoadAllowlist(path)
	if c.Contains("ads.example.com") || len(c.List()) != 0 {
		t.Error("entry still present after Remove")
	}
}

func TestManagerCheck(t *testing.T) {
	a, _ := LoadAllowlist(filepath.Join(t.TempDir(), "allow.txt"))
	m := &Manager{Allow: a}
	mt := newMatcher([]string{"list"})
	mt.load(0, strings.NewReader("||tracker.example.com^\n"))
	m.cur.Store(mt)

	if blocked, reason := m.Check("tracker.example.com"); !blocked || reason != "list" {
		t.Fatalf("got %v %q", blocked, reason)
	}
	a.Add("tracker.example.com")
	if blocked, reason := m.Check("cdn.tracker.example.com"); blocked || reason != ReleasedPrefix+"list" {
		t.Fatalf("released domain: got %v %q", blocked, reason)
	}
}

// Eigene Sperrliste: vor den Blocklisten, samt Subdomains; eine genauere oder gleiche Freigabe gewinnt.
func TestManagerDeny(t *testing.T) {
	dir := t.TempDir()
	a, _ := LoadAllowlist(filepath.Join(dir, "allow.txt"))
	d, _ := LoadDenylist(filepath.Join(dir, "deny.txt"))
	m := &Manager{Allow: a, Deny: d}
	m.cur.Store(newMatcher(nil))
	if blocked, _ := m.CheckMask("ads.example.com", ^uint64(0)); blocked {
		t.Fatal("empty denylist blocks")
	}
	if _, err := d.Add("example.com"); err != nil {
		t.Fatal(err)
	}
	if blocked, reason := m.CheckMask("ads.example.com", 0); !blocked || reason != OwnPrefix+"example.com" {
		t.Fatalf("deny: %v %q", blocked, reason)
	}
	a.Add("cdn.example.com") // genauere Freigabe
	if blocked, _ := m.CheckMask("img.cdn.example.com", 0); blocked {
		t.Fatal("more specific release must win")
	}
	if blocked, _ := m.CheckMask("www.example.com", 0); !blocked {
		t.Fatal("other subdomain must stay blocked")
	}
	d2, _ := LoadDenylist(filepath.Join(dir, "deny.txt")) // gespeichert und wieder geladen
	if _, ok := d2.Match("x.example.com"); !ok {
		t.Fatal("denylist not persisted")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "deny.txt"))
	if !strings.HasPrefix(string(b), "# Eigene Sperrliste") {
		t.Fatalf("header: %q", b)
	}
}

func BenchmarkMatch(b *testing.B) {
	m := newMatcher([]string{"l"})
	var sb strings.Builder
	for i := 0; i < 200000; i++ {
		sb.WriteString("||d")
		sb.WriteString(strings.Repeat("x", i%7))
		sb.WriteString(string(rune('a' + i%26)))
		sb.WriteString(".example.com^\n")
	}
	m.load(0, strings.NewReader(sb.String()))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Match("some.deep.subdomain.of.a.normal-site.de")
	}
}

func TestListFilesByURL(t *testing.T) {
	dir := t.TempDir()
	// Datei einer alten Version (Index in DefaultLists) wird nach URL umbenannt
	if err := os.WriteFile(filepath.Join(dir, "list-1.txt"), []byte("||ads.example.com^\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, _ := LoadAllowlist(filepath.Join(dir, "allow.txt"))
	m, err := NewManager(dir, []List{DefaultLists[1]}, time.Hour, a, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if blocked, list := m.Check("ads.example.com"); !blocked || list != DefaultLists[1].Name {
		t.Fatalf("migrated list not loaded: %v %q", blocked, list)
	}
	if _, err := os.Stat(fileFor(dir, DefaultLists[1].URL)); err != nil {
		t.Fatal("file not renamed")
	}
}

// Dateien entfernter Listen bleiben nicht liegen; die der genutzten Listen und halbe Downloads (.tmp) bleiben.
func TestListFilesPruned(t *testing.T) {
	dir := t.TempDir()
	used, gone := fileFor(dir, DefaultLists[0].URL), fileFor(dir, "https://example.org/removed.txt")
	for _, p := range []string{used, gone, gone + ".tmp"} {
		if err := os.WriteFile(p, []byte("||ads.example.com^\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	PruneFiles(dir, []string{DefaultLists[0].URL})
	if _, err := os.Stat(used); err != nil {
		t.Fatal("file of a used list removed")
	}
	if _, err := os.Stat(gone); err == nil {
		t.Fatal("file of a removed list kept")
	}
	if _, err := os.Stat(gone + ".tmp"); err != nil {
		t.Fatal("download in progress removed")
	}
}
