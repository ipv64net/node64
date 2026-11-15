package localnet

import (
	"net/netip"
	"testing"
)

// Sicherheits-Review WE-3: im Bridge-Netz ist die Gateway-Adresse keine Heimnetz-Herkunft.
func TestOrigin(t *testing.T) {
	gw := netip.MustParseAddr("172.17.0.1")
	lan := netip.MustParseAddr("192.168.1.20")
	restore := OriginForTest(true, gw)
	if !MaskedGateway(gw) || !MaskedGateway(netip.MustParseAddr("::ffff:172.17.0.1")) || MaskedGateway(lan) {
		t.Fatal("MaskedGateway im Bridge-Netz")
	}
	if Origin(gw).IsValid() || Origin(lan) != lan || Origin(netip.Addr{}).IsValid() {
		t.Fatal("Origin im Bridge-Netz")
	}
	restore()
	restore = OriginForTest(false, gw)
	defer restore()
	if MaskedGateway(gw) || Origin(gw) != gw {
		t.Fatal("ohne Bridge-Netz bleibt die Adresse")
	}
}
