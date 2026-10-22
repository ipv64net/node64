package dns64cluster

import "testing"

// Alle Bereiche ohne Einstellung aus (Entscheidung: jeder Bereich wird einzeln eingeschaltet).
func TestModuleItemsDefaultOff(t *testing.T) {
	mi := Module()
	if mi.ID != "dns64" || len(mi.Items) != 7 {
		t.Fatalf("module = %+v", mi)
	}
	for _, it := range mi.Items {
		if it.Default || it.TitleKey == "" {
			t.Fatalf("item %+v", it)
		}
	}
}
