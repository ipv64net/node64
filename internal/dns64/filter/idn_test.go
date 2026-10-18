package filter

import (
	"path/filepath"
	"testing"
)

// Internationalisierte Namen auf Listen und in den Freigaben werden als Punycode gespeichert, wie sie im DNS
// abgefragt werden.
func TestIDN(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want string
		kind ruleKind
	}{
		{"0.0.0.0 bücher.example", "xn--bcher-kva.example", ruleExact},
		{"||münchen-werbung.de^", "xn--mnchen-werbung-gsb.de", ruleWildcard},
		{"Straße.de", "xn--strae-oqa.de", ruleExact},
		{"@@||café.example^", "xn--caf-dma.example", ruleAllow},
		{"xn--bcher-kva.example", "xn--bcher-kva.example", ruleExact},
		{"bü cher.example", "", ruleNone},
	} {
		if got, kind := parseLine(tt.in); got != tt.want || kind != tt.kind {
			t.Errorf("parseLine(%q) = %q, %d; want %q, %d", tt.in, got, kind, tt.want, tt.kind)
		}
	}
	if got := ToASCII("*.bücher.example"); got != "*.xn--bcher-kva.example" {
		t.Errorf("wildcard: %q", got)
	}
	a, err := LoadAllowlist(filepath.Join(t.TempDir(), "allow.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if d, err := a.Add("Bücher.Example"); err != nil || d != "xn--bcher-kva.example" {
		t.Fatalf("add = %q %v", d, err)
	}
	if !a.Contains("shop.xn--bcher-kva.example") {
		t.Fatal("subdomain of the IDN not released")
	}
}
