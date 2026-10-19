package filter

import (
	"strings"
	"testing"
)

// Jede Regel kennt alle Listen, die sie enthalten; eine Gruppe sieht nur ihre Listen.
func TestMatchMask(t *testing.T) {
	m := newMatcher([]string{"A", "B"})
	m.load(0, strings.NewReader("0.0.0.0 ads.example\n||both.example^\n"))
	m.load(1, strings.NewReader("||game.example^\n||both.example^\n@@||ok.game.example^\n"))
	for _, tt := range []struct {
		name string
		mask uint64
		want bool
		why  string
	}{
		{"ads.example", 1, true, "A"}, {"ads.example", 2, false, ""},
		{"x.game.example", 2, true, "B"}, {"x.game.example", 1, false, ""},
		{"both.example", 2, true, "B"}, {"both.example", 3, true, "A"},
		{"ok.game.example", 2, false, ""}, {"ads.example", 0, false, ""},
	} {
		if got, why := m.MatchMask(tt.name, tt.mask); got != tt.want || why != tt.why {
			t.Errorf("MatchMask(%s, %b) = %v %q, want %v %q", tt.name, tt.mask, got, why, tt.want, tt.why)
		}
	}
}

func TestGroupCategories(t *testing.T) {
	for key, name := range map[string]string{"social": "www.tiktok.com", "games": "web.roblox.com", "streaming": "www.netflix.com"} {
		if _, ok := GroupCategory(key).Match(name); !ok {
			t.Errorf("%s: %s not matched", key, name)
		}
	}
	if GroupCategory("gambling") != nil || GroupCategoryLists["gambling"] == "" {
		t.Fatal("gambling must come from a blocklist")
	}
	d := NewDomainSet([]string{"*.Schule.example", "bücher.example", "kaputt"})
	if _, ok := d.Match("portal.schule.example"); !ok || d.Len() != 2 {
		t.Fatalf("domain set: %d", d.Len())
	}
	if _, ok := d.Match("xn--bcher-kva.example"); !ok {
		t.Fatal("idn not normalized")
	}
}
