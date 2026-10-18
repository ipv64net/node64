package dns64

import (
	"context"
	"testing"
)

// Eigene Eintraege mit Umlauten werden als Punycode gespeichert und so beantwortet.
func TestRecordIDN(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	r, err := m.AddRecord(ctx, Record{Name: "NAS.Bücher.lan", Type: "CNAME", Value: "speicher.bücher.lan"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Name != "nas.xn--bcher-kva.lan" || r.Value != "speicher.xn--bcher-kva.lan" {
		t.Fatalf("record = %+v", r)
	}
}
