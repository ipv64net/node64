package dns64

import (
	"context"

	"github.com/ipv64net/node64/internal/ports"
)

// Ports liefert die eingestellten Ports fuer die Port-Verwaltung des Kerns (aktiv = Modul laeuft und der Dienst
// ist eingeschaltet). Nur lesend; geoeffnet werden die Ports wie bisher vom Modul selbst.
func (m *Module) Ports(ctx context.Context, running bool) []ports.Claim {
	c := m.loadConfig(ctx)
	// verschluesselte Dienste: aktiv nur, wenn sie wirklich gestartet sind (z. B. nicht bei Zertifikatsfehler)
	encOn := func(proto string) bool {
		if !running {
			return false
		}
		if e := m.running(); e != nil && e.enc != nil {
			return e.enc.errs[proto] == ""
		}
		return true
	}
	// Fehler fuer die Port-Uebersicht: Start des Moduls bzw. des verschluesselten Dienstes
	startErr := ""
	if !running {
		startErr = m.startError()
	}
	encErr := func(proto string) string {
		if e := m.running(); running && e != nil && e.enc != nil {
			return e.enc.errs[proto]
		}
		return startErr
	}
	out := []ports.Claim{
		{Owner: Name, Purpose: "DNS", Proto: ports.UDP, Port: c.Port, Bind: c.Bind, Active: running, Error: startErr},
		{Owner: Name, Purpose: "DNS", Proto: ports.TCP, Port: c.Port, Bind: c.Bind, Active: running, Error: startErr},
	}
	if c.DoH && !m.dohViaEdge(c) { // ueber den Eingang: 443 fuehrt der Eingang
		out = append(out, ports.Claim{Owner: Name, Purpose: "DoH", Proto: ports.TCP, Port: c.DoHPort, Bind: c.Bind, Active: encOn("doh"), Error: encErr("doh")})
	}
	if c.DoT {
		out = append(out, ports.Claim{Owner: Name, Purpose: "DoT", Proto: ports.TCP, Port: c.DoTPort, Bind: c.Bind, Active: encOn("dot"), Error: encErr("dot")})
	}
	if c.DoQ {
		out = append(out, ports.Claim{Owner: Name, Purpose: "DoQ", Proto: ports.UDP, Port: c.DoTPort, Bind: c.Bind, Active: encOn("doq"), Error: encErr("doq")})
	}
	return out
}
