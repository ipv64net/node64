package dns64

import (
	"context"
	"testing"
)

// Reservierung von Hand mit Namen, der kein DNS-Label ist ("Tablet Lea"), von IPAM64 ohne Rechnernamen uebernommen:
// der Name bleibt (auch beim naechsten Schreiben); einen Namen von IPAM64 setzt es durch, einen eigenen raeumt es ab.
func TestIPAMBridgeKeepsHandName(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	s, err := m.AddDHCPScope(ctx, DHCPScope{Iface: "eth9", Subnet: "192.168.50.0/24", Start: "192.168.50.100", End: "192.168.50.150", Domain: "home.lan"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddDHCPReservation(ctx, DHCPReservation{ScopeID: s.ID, MAC: "02:00:00:00:00:07", IP: "192.168.50.7", Name: "Tablet Lea"}); err != nil {
		t.Fatal(err)
	}
	name := func() string {
		t.Helper()
		res, _ := m.DHCPReservations(ctx)
		for _, r := range res {
			if r.IP == "192.168.50.7" {
				return r.Name
			}
		}
		t.Fatal("reservation gone")
		return ""
	}
	for i := 0; i < 2; i++ { // Kennzeichnen, dann erneut schreiben (Abgleich, Speichern)
		if err := m.PutIPAMReservation(ctx, "u7", "02:00:00:00:00:07", "192.168.50.7", ""); err != nil {
			t.Fatal(err)
		}
		if n := name(); n != "Tablet Lea" {
			t.Fatalf("run %d: name %q", i, n)
		}
	}
	if err := m.PutIPAMReservation(ctx, "u7", "02:00:00:00:00:07", "192.168.50.7", "tablet"); err != nil || name() != "tablet" {
		t.Fatalf("name from IPAM64: %q %v", name(), err)
	}
	if err := m.PutIPAMReservation(ctx, "u7", "02:00:00:00:00:07", "192.168.50.7", ""); err != nil || name() != "" {
		t.Fatalf("own name not cleared: %q %v", name(), err)
	}
}
