package dns64

import (
	"context"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// clientNames: Namen fuer Client-Adressen (Abfrage-Log, Top-Clients) in dieser Reihenfolge (#49): Name aus der
// Geraetegruppe, eigener PTR-Eintrag in einer lokalen Rueckwaertszone, Router (DHCP) bzw. mDNS; ohne Namen fehlt der
// Eintrag (die Seite zeigt dann die IP).
func (m *Module) clientNames(ctx context.Context, e *engine, ips []string) map[string]string {
	out := make(map[string]string, len(ips))
	var rest []string
	for _, s := range ips {
		if n := m.ownClientName(s); n != "" {
			out[s] = n
			continue
		}
		rest = append(rest, s)
	}
	if len(rest) > 0 && e != nil && e.local != nil {
		for ip, n := range e.local.Hostnames(ctx, rest) {
			out[ip] = n
		}
	}
	return out
}

// ownClientName: selbst vergebener Name einer Adresse – Name des Geraets in einer Gruppe, sonst der eigene PTR-Eintrag.
func (m *Module) ownClientName(s string) string {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return "" // z. B. anonymisierte Adresse
	}
	ip = ip.Unmap()
	if l := m.labelFor(ip); l != "" {
		return l
	}
	arpa, err := dns.ReverseAddr(ip.String())
	if err != nil {
		return ""
	}
	if rrs, ok := m.Lookup(strings.TrimSuffix(arpa, "."), dns.TypePTR); ok {
		for _, rr := range rrs {
			if p, ok := rr.(*dns.PTR); ok {
				return strings.TrimSuffix(p.Ptr, ".")
			}
		}
	}
	return ""
}
