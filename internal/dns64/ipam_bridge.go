package dns64

import "github.com/ipv64net/node64/internal/dns64/dhcp"

// Schnittstelle zu IPAM64 (Plan docs/PLAN-NODE64-IPAM64.md). Stufe I1: nur lesend. Die Funktionen zum Schreiben
// gekennzeichneter Reservierungen und Eintraege (origin/ref) kommen mit Stufe I2.

// DHCPLeases liefert die Vergaben des laufenden DHCP-Servers (nil = DHCP aus). Aus dem Entwurf von UlrichSchwarz.
func (m *Module) DHCPLeases() []dhcp.Lease {
	s := m.dhcpSrv.Load()
	if s == nil {
		return nil
	}
	var out []dhcp.Lease
	for _, sv := range s.Snapshot().Scopes {
		out = append(out, sv.Leases...)
	}
	return out
}
