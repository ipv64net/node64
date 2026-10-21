package module

import "testing"

// Balken der Karten: kleiner Verbrauch bleibt sichtbar, Farben wie bei den Account-Limits.
func TestBarWidthClass(t *testing.T) {
	if w := BarWidth(0, false); w != 0 {
		t.Fatalf("leer: %v", w)
	}
	if w := BarWidth(0, true); w != 1 {
		t.Fatalf("kleiner Verbrauch: %v", w)
	}
	if w := BarWidth(37.5, true); w != 37.5 {
		t.Fatalf("Mitte: %v", w)
	}
	if w := BarWidth(130, true); w != 100 {
		t.Fatalf("ueber 100: %v", w)
	}
	for _, c := range []struct {
		pct  float64
		warn bool
		want string
	}{{0, false, "bg-success"}, {79, false, "bg-success"}, {80, false, "bg-warning"}, {10, true, "bg-warning"}, {100, false, "bg-danger"}, {100, true, "bg-danger"}} {
		if got := BarClassOf(c.pct, c.warn); got != c.want {
			t.Errorf("%v/%v: %s, want %s", c.pct, c.warn, got, c.want)
		}
	}
}
