package worldmap

import (
	"regexp"
	"strings"
	"testing"
)

var pathRe = regexp.MustCompile(`^(M-?\d+ ?-?\d+l[-\d ]*z)+$`)

// TestData: alle Laender mit 2-Buchstaben-Code, keine Doppelten, Sonderfaelle zugeordnet, ohne Antarktis, klein.
func TestData(t *testing.T) {
	if len(raw) > 150*1024 {
		t.Fatalf("world.txt is %d bytes, want <= 150 KB", len(raw))
	}
	if !strings.HasPrefix(raw, "# Natural Earth") || !strings.Contains(raw, "public domain") {
		t.Error("source/license header missing")
	}
	if vb := ViewBox(); !regexp.MustCompile(`^0 0 \d+ \d+$`).MatchString(vb) {
		t.Fatalf("viewBox %q", vb)
	}
	list := Countries()
	if len(list) < 170 {
		t.Fatalf("only %d countries", len(list))
	}
	seen := map[string]bool{}
	lines := 0
	for _, l := range strings.Split(raw, "\n") {
		if l != "" && !strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "viewBox ") {
			lines++
		}
	}
	if lines != len(list) {
		t.Fatalf("%d data lines, %d countries: duplicates in the file", lines, len(list))
	}
	for i, c := range list {
		if !regexp.MustCompile(`^[A-Z]{2}$`).MatchString(c.Code) {
			t.Errorf("code %q", c.Code)
		}
		if seen[c.Code] {
			t.Errorf("duplicate %s", c.Code)
		}
		seen[c.Code] = true
		if !pathRe.MatchString(c.Path) {
			t.Errorf("%s: path %.60q", c.Code, c.Path)
		}
		if i > 0 && list[i-1].Code >= c.Code {
			t.Errorf("not sorted at %s", c.Code)
		}
	}
	for _, cc := range []string{"DE", "FR", "NO", "XK", "TW", "CY", "SO", "US", "CN", "RU", "BR", "AU", "LU"} {
		if !Has(cc) {
			t.Errorf("%s missing", cc)
		}
	}
	if Has("AQ") || Has("") || Has("-9") {
		t.Error("antarctica or invalid code present")
	}
}

func TestParse(t *testing.T) {
	d := parse("# x\nviewBox 0 0 10 5\nDE M1 1l1 0z\nDE M2 2l1 0z\n\nbroken\nFR M3 3l1 0z\n")
	if d.viewBox != "0 0 10 5" || len(d.countries) != 2 || d.countries[0].Path != "M1 1l1 0z" || d.countries[1].Code != "FR" {
		t.Fatalf("%+v", d)
	}
}
