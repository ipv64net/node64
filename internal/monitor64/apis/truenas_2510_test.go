package apis

import (
	"context"
	"testing"
)

// TrueNAS 25.10 (Goldeye) hat smart.test.results entfernt (SMART-Probleme kommen dort ueber alert.list): die Abfrage
// antwortet mit -32601 und wird ohne Teilfehler uebergangen; Platten, Pools und Alarme kommen wie gewohnt (#93).
func TestTrueNAS2510NoSmartResults(t *testing.T) {
	f := newFakeTrueNAS(t, true)
	f.fail["smart.test.results"] = 404
	addr, pin := tlsServer(t, f)
	tn, err := NewTrueNAS(TrueNASConfig{Address: addr, APIKey: testSecret, User: "monitor", Pin: pin})
	if err != nil {
		t.Fatal(err)
	}
	tn.now = tnNow
	svcs, err := tn.Collect(context.Background())
	if err != nil {
		t.Fatalf("Teilfehler ohne smart.test.results: %v", deErr(err))
	}
	if tn.api != TrueNASRPC || !hasSvc(svcs, "zfs:tank") || !hasSvc(svcs, "alerts") {
		t.Fatalf("Dienste: %v", svcs)
	}
	disks := 0
	for _, s := range svcs {
		if s.Kind == "disk" {
			disks++
		}
	}
	if disks == 0 {
		t.Fatal("keine Platten ohne smart.test.results")
	}
}
