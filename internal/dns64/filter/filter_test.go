package filter

import (
	"path/filepath"
	"strings"
	"testing"
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
	if blocked, reason := m.Check("cdn.tracker.example.com"); blocked || !strings.HasPrefix(reason, "Freigegeben") {
		t.Fatalf("released domain: got %v %q", blocked, reason)
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
