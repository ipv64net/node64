package dns64

import (
	"context"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// clientNames: Namen fuer Client-Adressen (Abfrage-Log, Top-Clients) in dieser Reihenfolge (#49, #119): Name aus der
// Geraetegruppe, Bezeichnung des eigenen PTR- bzw. A-Eintrags, eigener PTR-Eintrag in einer lokalen Rueckwaertszone,
// Router (DHCP) bzw. mDNS; ohne Namen fehlt der Eintrag (die Seite zeigt dann die IP).
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
	m.namesByMAC(ctx, e, ips, out)
	return out
}

// ClientNames: Namen fuer Client-Adressen wie im Abfrage-Log (Gruppe, eigene Eintraege, Router; IPAM64). Laeuft
// DNS64 nicht, kommen nur die eigenen Namen ohne Router.
func (m *Module) ClientNames(ctx context.Context, ips []string) map[string]string {
	return m.clientNames(ctx, m.running(), ips)
}

// namesByMAC: Adressen ohne Namen (meist IPv6-Datenschutz-Adressen, fuer die der Router keinen PTR hat) bekommen den
// Namen einer IPv4-Adresse desselben Geraets (gleiche MAC laut Nachbartabelle bzw. DHCP, #223).
func (m *Module) namesByMAC(ctx context.Context, e *engine, ips []string, out map[string]string) {
	if m.grp == nil {
		return
	}
	want := map[string][]string{} // IPv4-Adresse -> Adressen ohne Namen
	for _, s := range ips {
		if out[s] != "" {
			continue
		}
		ip, err := netip.ParseAddr(s)
		if err != nil || !ip.Is6() || ip.Is4In6() {
			continue
		}
		mac := m.grp.MAC(ip)
		if mac == "" {
			continue
		}
		for _, v4 := range m.grp.IPs(mac) { // sortiert: die erste IPv4-Adresse
			if v4.Is4() {
				want[v4.String()] = append(want[v4.String()], s)
				break
			}
		}
	}
	if len(want) == 0 {
		return
	}
	var rest []string
	named := map[string]string{}
	for v4 := range want {
		if n := out[v4]; n != "" {
			named[v4] = n
		} else if n := m.ownClientName(v4); n != "" {
			named[v4] = n
		} else {
			rest = append(rest, v4)
		}
	}
	if len(rest) > 0 && e != nil && e.local != nil {
		for ip, n := range e.local.Hostnames(ctx, rest) {
			named[ip] = n
		}
	}
	for v4, n := range named {
		for _, s := range want[v4] {
			if out[s] == "" {
				out[s] = n
			}
		}
	}
}

// ownClientName: selbst vergebener Name einer Adresse – Name des Geraets in einer Gruppe, sonst die Bezeichnung bzw.
// der Name des eigenen PTR-Eintrags.
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
	if l := m.recordLabel(strings.TrimSuffix(arpa, ".")); l != "" { // lesbare Bezeichnung statt DNS-Name (#119)
		return l
	}
	if rrs, ok := m.Lookup(strings.TrimSuffix(arpa, "."), dns.TypePTR); ok {
		for _, rr := range rrs {
			if p, ok := rr.(*dns.PTR); ok {
				return strings.TrimSuffix(p.Ptr, ".")
			}
		}
	}
	return m.dhcpLabel(ip) // Name aus dem DHCP-Server, auch in Netzen ohne Domain
}
