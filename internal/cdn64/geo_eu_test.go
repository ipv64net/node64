package cdn64

import (
	"context"
	"slices"
	"testing"
	"time"
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

// Pruefung abgeschaltet: der alte Stand "nicht erreichbar" bleibt nicht stehen.
func TestNoProbeForgetsReach(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"db.test"}, "192.0.2.1", 5432
	h.Advanced.NoProbe = true
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	e.m.reach.set(h.ID, Reach{State: ReachDown, Error: "refused", Checked: time.Now()})
	e.m.checkAll(ctx)
	if s := e.m.reach.get(h.ID).State; s != ReachUnknown {
		t.Fatalf("state %q, want unknown", s)
	}
}
