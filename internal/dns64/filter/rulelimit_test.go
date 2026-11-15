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
