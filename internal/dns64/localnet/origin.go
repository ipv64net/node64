package localnet

import (
	"net/netip"
	"sync"
	"time"
)

// Absender hinter dem Docker-Gateway: Im Bridge-Netz ersetzt Docker Absender-Adressen durch die des Gateways
// (Userland-Proxy, IPv6 ohne ip6tables, manche NAS-Systeme, Zugriffe vom Docker-Host selbst). Solche Anfragen
// koennen aus dem Internet kommen; Regeln wie "nur Heimnetz" duerfen sie deshalb nicht als lokal werten.

var (
	originMu  sync.Mutex
	originAt  time.Time
	originGw  netip.Addr
	bridgeFn  = Bridge
	gatewayFn = Gateway
)

// originRefresh: so lange gilt die Erkennung (Bridge-Netz und Gateway aendern sich zur Laufzeit praktisch nie).
const originRefresh = time.Minute

// MaskedGateway meldet, ob ip im Bridge-Netz die Adresse des Gateways ist - dann ist die echte Herkunft unbekannt.
func MaskedGateway(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return false
	}
	originMu.Lock()
	if originAt.IsZero() || time.Since(originAt) > originRefresh {
		originAt, originGw = time.Now(), netip.Addr{}
		if bridgeFn() {
			originGw = gatewayFn().Unmap()
		}
	}
	gw := originGw
	originMu.Unlock()
	return gw.IsValid() && ip == gw
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
	bridgeFn, gatewayFn = func() bool { return bridge }, func() netip.Addr { return gw }
	originAt = time.Time{}
	originMu.Unlock()
	return func() {
		originMu.Lock()
		bridgeFn, gatewayFn, originAt = oldB, oldG, time.Time{}
		originMu.Unlock()
	}
}
