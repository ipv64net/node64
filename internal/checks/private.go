package checks

import (
	"net/netip"
	"strings"
)

// IsPrivateTarget sagt, ob ein Ziel im privaten Netz liegt (Adressen ausserhalb von PublicAddr, also RFC 1918, ULA,
// Loopback, Link-Local, CGNAT, reservierte Netze; Namen .local, .localhost, localhost). Solche Ziele kann ipv64 von
// aussen nicht pruefen.
func IsPrivateTarget(typ, target string) bool {
	if typ == string(TypeDocker) || typ == string(TypeProxmox) {
		return true // Container der Node bzw. Stand der lokalen Proxmox-Abfrage sind von aussen nie erreichbar
	}
	host := strings.ToLower(strings.TrimSpace(target))
	if typ == "dns" {
		host = strings.TrimSuffix(host, ".")
	}
	if typ == "http" || typ == "keyword" || typ == "json" {
		if i := strings.Index(host, "://"); i >= 0 {
			host = host[i+3:]
		}
		if i := strings.IndexAny(host, "/?#"); i >= 0 {
			host = host[:i]
		}
		if i := strings.LastIndex(host, "@"); i >= 0 {
			host = host[i+1:]
		}
	}
	// Klammern, Port und Zone abtrennen; Adressen pruefen wie die Sperre beim Verbindungsaufbau (PublicAddr)
	if strings.HasPrefix(host, "[") {
		if i := strings.Index(host, "]"); i >= 0 {
			host = host[1:i]
		}
	} else if i := strings.LastIndex(host, ":"); i >= 0 && strings.Count(host, ":") == 1 {
		host = host[:i]
	}
	if i := strings.Index(host, "%"); i >= 0 {
		host = host[:i]
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return !PublicAddr(a)
	}
	return host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".localhost")
}
