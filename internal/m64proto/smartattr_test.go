package m64proto

import "testing"

// Review 15: eine Zuordnung der ATA-Attribute fuer Agent, SSH und smartctl_exporter.
func TestApplyATAAttr(t *testing.T) {
	var s SMART
	for _, a := range []struct {
		id, value int
		raw       uint64
	}{{5, 100, 8}, {197, 100, 2}, {198, 100, 1}, {199, 200, 13}, {177, 92, 41}, {231, 50, 0}, {9, 99, 12345}} {
		s.ApplyATAAttr(a.id, a.value, a.raw)
	}
	if *s.Reallocated != 8 || *s.Pending != 2 || *s.Uncorrectable != 1 || *s.CRCErrors != 13 || *s.WearPercentUsed != 8 {
		t.Fatalf("%+v wear=%v", s, *s.WearPercentUsed)
	}
	var z SMART
	z.ApplyATAAttr(202, 0, 0) // kein gueltiger normierter Wert
	if z.WearPercentUsed != nil {
		t.Error("Verschleiss aus Wert 0")
	}
}
