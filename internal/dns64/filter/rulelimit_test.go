package filter

import (
	"strings"
	"testing"
)

// Gesamtgrenze aller Listen: neue Regeln ueber maxRules werden nicht geladen und gezaehlt, Regeln, die es schon gibt,
// bekommen weiter das Bit der Liste (Review DN-6).
func TestRuleLimit(t *testing.T) {
	old := maxRules
	maxRules = 3
	defer func() { maxRules = old }()
	m := newMatcher([]string{"a", "b"})
	if n, _ := m.load(0, strings.NewReader("0.0.0.0 a.example\n||b.example^\n")); n != 2 || m.Limited(0) != 0 {
		t.Fatalf("list a: %d rules, limited %d", n, m.Limited(0))
	}
	n, _ := m.load(1, strings.NewReader("||b.example^\n0.0.0.0 c.example\n0.0.0.0 d.example\n||e.example^\n"))
	if n != 1 || m.Limited(1) != 2 || m.Size() != 3 {
		t.Fatalf("list b: %d new, limited %d, size %d", n, m.Limited(1), m.Size())
	}
	if ok, list := m.MatchMask("x.b.example", 1<<1); !ok || list != "b" { // vorhandene Regel auch fuer Liste b
		t.Fatalf("shared rule: %v %q", ok, list)
	}
	if ok, _ := m.Match("d.example"); ok {
		t.Fatal("rule above the limit loaded")
	}
}

// Grenze nach dem Speicher: 4 Mio. als Untergrenze, 32 Mio. (32 Bit: 8 Mio.) als Obergrenze.
func TestRulesFor(t *testing.T) {
	const gb = 1 << 30
	for _, c := range []struct {
		mem  uint64
		bits int
		want int
	}{
		{0, 64, minRules},
		{512 << 20, 64, minRules},
		{2 * gb, 64, 4_194_304},
		{8 * gb, 64, 16_777_216},
		{64 * gb, 64, maxRulesCap},
		{8 * gb, 32, maxRules32},
		{1 * gb, 32, minRules},
	} {
		if got := rulesFor(c.mem, c.bits); got != c.want {
			t.Errorf("rulesFor(%d, %d) = %d, want %d", c.mem, c.bits, got, c.want)
		}
	}
	if n := autoMaxRules(); n < minRules || n > maxRulesCap {
		t.Fatalf("autoMaxRules = %d", n)
	}
}
