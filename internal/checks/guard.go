package checks

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// Sperre fuer interne Ziele auf den ipv64-Servern (Runner.DenyPrivate): Online-Checks duerfen nur oeffentliche
// Adressen erreichen. Geprueft wird die tatsaechlich gewaehlte Adresse beim Verbindungsaufbau – damit greift die Sperre
// auch, wenn ein Hostname auf eine interne Adresse zeigt, eine Weiterleitung dorthin fuehrt oder ein DNS-Check einen
// internen Server bzw. Nameserver nennt. Die Textpruefung (IsPrivateTarget) bleibt fuer die Meldung beim Anlegen.

// ErrPrivateAddress: Ziel liegt im privaten oder reservierten Adressbereich.
var ErrPrivateAddress = errors.New("target resolves to a private or reserved address")

// reserved: nicht oeffentlich erreichbare bzw. besondere Bereiche (zusaetzlich zu den netip-Pruefungen).
var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // „dieses Netz“
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF-Protokoll
	netip.MustParsePrefix("192.0.2.0/24"),    // Doku
	netip.MustParsePrefix("198.18.0.0/15"),   // Benchmark
	netip.MustParsePrefix("198.51.100.0/24"), // Doku
	netip.MustParsePrefix("203.0.113.0/24"),  // Doku
	netip.MustParsePrefix("240.0.0.0/4"),     // reserviert, Broadcast
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64 (kann auf interne IPv4 zeigen)
	netip.MustParsePrefix("64:ff9b:1::/48"),  // NAT64 lokal
	netip.MustParsePrefix("100::/64"),        // Discard
	netip.MustParsePrefix("2001::/32"),       // Teredo
	netip.MustParsePrefix("2001:db8::/32"),   // Doku
	netip.MustParsePrefix("2002::/16"),       // 6to4 (kann auf interne IPv4 zeigen)
	netip.MustParsePrefix("fec0::/10"),       // site-local (veraltet, intern)
	netip.MustParsePrefix("::/96"),           // IPv4-kompatibel (veraltet)
}

// PublicAddr: Adresse ist oeffentlich erreichbar (kein privates, lokales, reserviertes oder Multicast-Netz).
func PublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() {
		return false
	}
	for _, p := range reserved {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// PublicIP wie PublicAddr fuer net.IP.
func PublicIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	return ok && PublicAddr(a)
}

type denyKey struct{}

// withDenyPrivate markiert den Kontext eines Laufs mit gesperrten internen Zielen.
func withDenyPrivate(ctx context.Context) context.Context {
	return context.WithValue(ctx, denyKey{}, true)
}

func denyPrivate(ctx context.Context) bool { v, _ := ctx.Value(denyKey{}).(bool); return v }

// guard setzt bei gesperrten internen Zielen die Pruefung der Zieladresse in den Dialer (vor dem Verbindungsaufbau).
func guard(ctx context.Context, d *net.Dialer) *net.Dialer {
	if denyPrivate(ctx) {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !PublicAddr(ap.Addr()) {
				return ErrPrivateAddress
			}
			return nil
		}
	}
	return d
}
