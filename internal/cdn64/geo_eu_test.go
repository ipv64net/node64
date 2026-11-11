package cdn64

import (
	"slices"
	"testing"
)

// EU steht fuer die 27 Mitgliedstaaten, doppelte fallen weg (#54).
func TestGeoEU(t *testing.T) {
	mode, list := geoAllow, []string{"eu", "CH", "DE"}
	if err := normalizeGeo(&mode, &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 28 || !slices.Contains(list, "DE") || !slices.Contains(list, "SE") || !slices.Contains(list, "CH") || slices.Contains(list, "EU") {
		t.Fatalf("eu: %d %v", len(list), list)
	}
}

// Erreichbarkeit je Host abschaltbar (Forum 5100).
func TestProbedNoProbe(t *testing.T) {
	h := newHost()
	if !h.probed() {
		t.Fatal("proxy host must be probed")
	}
	h.Advanced.NoProbe = true
	if h.probed() {
		t.Fatal("no_probe must switch the probe off")
	}
}
