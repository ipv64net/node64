package web

import (
	"testing"

	"github.com/ipv64net/node64/internal/i18n"
)

// Account-Karte: Datenmengen in GB mit Nachkommastellen nach Groesse, ab 1024 GB in TB.
func TestViewGB(t *testing.T) {
	bundle, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	de := &View{s: &Server{Deps: Deps{I18n: bundle}}, Lang: "de"}
	en := &View{s: &Server{Deps: Deps{I18n: bundle}}, Lang: "en"}
	cases := []struct {
		gb     float64
		de, en string
	}{
		{0, "0 GB", "0 GB"}, {0.4, "0,4 GB", "0.4 GB"}, {0.003, "< 0,01 GB", "< 0.01 GB"}, {1.234, "1,23 GB", "1.23 GB"},
		{12.34, "12,3 GB", "12.3 GB"}, {100, "100 GB", "100 GB"}, {512.6, "513 GB", "513 GB"}, {1024, "1 TB", "1 TB"}, {1536, "1,5 TB", "1.5 TB"},
	}
	for _, c := range cases {
		if got := de.GB(c.gb); got != c.de {
			t.Errorf("de %v: %q, want %q", c.gb, got, c.de)
		}
		if got := en.GB(c.gb); got != c.en {
			t.Errorf("en %v: %q, want %q", c.gb, got, c.en)
		}
	}
}
