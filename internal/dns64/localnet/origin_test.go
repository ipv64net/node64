package localnet

import (
	"net/netip"
	"testing"
	"time"
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

// Docker-Bridge mit IPv6: auch die IPv6-Adresse des Gateways (Default-Route) ist keine Herkunft.
func TestOriginIPv6Gateway(t *testing.T) {
	originMu.Lock()
	oldB, oldG := bridgeFn, gatewayFn
	bridgeFn = func() bool { return true }
	gatewayFn = func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("172.17.0.1"), netip.MustParseAddr("fd00:dead:beef::1"), netip.MustParseAddr("fe80::1%eth0")}
	}
	originAt = time.Time{}
	originMu.Unlock()
	defer func() {
		originMu.Lock()
		bridgeFn, gatewayFn, originAt = oldB, oldG, time.Time{}
		originMu.Unlock()
	}()
	for _, s := range []string{"172.17.0.1", "fd00:dead:beef::1", "fe80::1%eth0", "fe80::1"} {
		if !MaskedGateway(netip.MustParseAddr(s)) {
			t.Errorf("%s not recognised as gateway", s)
		}
	}
	if MaskedGateway(netip.MustParseAddr("fd00:dead:beef::5")) || MaskedGateway(netip.MustParseAddr("192.168.1.5")) {
		t.Fatal("other addresses counted as gateway")
	}
}
