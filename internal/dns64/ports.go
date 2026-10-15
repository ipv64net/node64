package dns64

import (
	"context"

	"github.com/ipv64net/node64/internal/ports"
)

// Ports liefert die eingestellten Ports fuer die Port-Verwaltung des Kerns (aktiv = Modul laeuft und der Dienst
// ist eingeschaltet). Nur lesend; geoeffnet werden die Ports wie bisher vom Modul selbst.
func (m *Module) Ports(ctx context.Context, running bool) []ports.Claim {
	c := m.loadConfig(ctx)
	out := []ports.Claim{
		{Owner: Name, Purpose: "DNS", Proto: ports.UDP, Port: c.Port, Bind: c.Bind, Active: running},
		{Owner: Name, Purpose: "DNS", Proto: ports.TCP, Port: c.Port, Bind: c.Bind, Active: running},
	}
	if c.DoH && !m.dohViaEdge(c) { // ueber den Eingang: 443 fuehrt der Eingang
		out = append(out, ports.Claim{Owner: Name, Purpose: "DoH", Proto: ports.TCP, Port: c.DoHPort, Bind: c.Bind, Active: running})
	}
	if c.DoT {
		out = append(out, ports.Claim{Owner: Name, Purpose: "DoT", Proto: ports.TCP, Port: c.DoTPort, Bind: c.Bind, Active: running})
	}
	if c.DoQ {
		out = append(out, ports.Claim{Owner: Name, Purpose: "DoQ", Proto: ports.UDP, Port: c.DoTPort, Bind: c.Bind, Active: running})
	}
	return out
}
