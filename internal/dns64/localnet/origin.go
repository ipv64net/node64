package localnet

import (
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"
)

// Absender hinter dem Docker-Gateway: Im Bridge-Netz ersetzt Docker Absender-Adressen durch die des Gateways
// (Userland-Proxy, IPv6 ohne ip6tables, manche NAS-Systeme, Zugriffe vom Docker-Host selbst). Solche Anfragen
// koennen aus dem Internet kommen; Regeln wie "nur Heimnetz" duerfen sie deshalb nicht als lokal werten.

var (
	originMu  sync.Mutex
	originAt  time.Time
	originGw  []netip.Addr
	bridgeFn  = Bridge
	gatewayFn = bridgeGateways
)

// bridgeGateways: IPv4- und IPv6-Default-Gateway. Mit IPv6 im Bridge-Netz kommt maskierter Verkehr (Userland-Proxy,
// IPv6 ohne ip6tables) von der IPv6-Adresse der Bridge.
func bridgeGateways() []netip.Addr {
	var out []netip.Addr
	if gw := Gateway(); gw.IsValid() {
		out = append(out, gw)
	}
	if f, err := os.Open("/proc/net/ipv6_route"); err == nil {
		for _, s := range ipv6Gateways(f) {
			if a, err := netip.ParseAddr(s); err == nil {
				out = append(out, a.WithZone(""))
			}
		}
		f.Close()
	}
	return out
}

// originRefresh: so lange gilt die Erkennung (Bridge-Netz und Gateway aendern sich zur Laufzeit praktisch nie).
const originRefresh = time.Minute

// MaskedGateway meldet, ob ip im Bridge-Netz die Adresse des Gateways ist (IPv4 oder IPv6) - dann ist die echte
// Herkunft unbekannt.
func MaskedGateway(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() {
		return false
	}
	originMu.Lock()
	if originAt.IsZero() || time.Since(originAt) > originRefresh {
		originAt, originGw = time.Now(), nil
		if bridgeFn() {
			for _, gw := range gatewayFn() {
				if gw = gw.Unmap().WithZone(""); gw.IsValid() {
					originGw = append(originGw, gw)
				}
			}
		}
	}
	gws := originGw
	originMu.Unlock()
	return slices.Contains(gws, ip)
}

// Origin liefert ip oder - fuer das Gateway im Bridge-Netz - eine leere Adresse (Herkunft unbekannt: weder privat
// noch Heimnetz; Sperrlisten treffen sie nicht).
func Origin(ip netip.Addr) netip.Addr {
	if MaskedGateway(ip) {
		return netip.Addr{}
	}
	return ip
}

// OriginForTest setzt die Erkennung fuer Tests (auch anderer Pakete); restore stellt den alten Stand wieder her.
func OriginForTest(bridge bool, gw netip.Addr) (restore func()) {
	originMu.Lock()
	oldB, oldG := bridgeFn, gatewayFn
	bridgeFn, gatewayFn = func() bool { return bridge }, func() []netip.Addr { return []netip.Addr{gw} }
	originAt = time.Time{}
	originMu.Unlock()
	return func() {
		originMu.Lock()
		bridgeFn, gatewayFn, originAt = oldB, oldG, time.Time{}
		originMu.Unlock()
	}
}
