package dns64

import (
	"crypto/tls"
	"errors"
	"net"

	"github.com/ipv64net/node64/internal/dns64/dnsserver"
	"github.com/ipv64net/node64/internal/edge"
)

// DoH ueber den gemeinsamen Eingang des Kerns (internal/edge): Ist der DoH-Port der HTTPS-Port des Eingangs,
// oeffnet DNS64 keinen eigenen Listener, sondern meldet /dns-query auf seinen Namen an (und fuer Aufrufe per IP
// bzw. ohne SNI). So teilen sich DoH und CDN64 Port 443. Der Eingang laesst nur Clients aus der Freigabeliste
// durch (echte Gegenstelle, alle anderen bekommen eine neutrale 404) und oeffnet fuer DoH keinen Port 80.

// SetEdge setzt den gemeinsamen Eingang (vor dem Start).
func (m *Module) SetEdge(e *edge.Edge) { m.ingress = e }

// dohViaEdge: DoH laeuft ueber den Eingang statt ueber einen eigenen Listener.
func (m *Module) dohViaEdge(c config) bool {
	return m.ingress != nil && c.DoH && c.DoHPort == m.ingress.Config().HTTPSPort
}

// startDoHEdge meldet DoH beim Eingang an. Gehoert ein Name schon einem anderen Abnehmer (z. B. ein Proxy-Host
// von CDN64), faellt nur dieser Name weg; ist der Aufruf per IP schon vergeben, entfaellt nur er.
func (m *Module) startDoHEdge(x *encrypted, names []string, srv *dnsserver.Server) error {
	rt := edge.Route{Path: "/dns-query", Handler: dohHandler(srv), HTTP3: true, NoHTTP: true, Fallback: true, Allow: srv.Allowed,
		GetCert: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return m.cur.Load(), nil }}
	for _, n := range names {
		if net.ParseIP(n) != nil || n == "localhost" {
			continue // IPs laufen ueber Fallback
		}
		if nn, err := edge.NormalizeName(n); err == nil {
			rt.Names = append(rt.Names, nn)
		}
	}
	for {
		err := m.ingress.Set(Name, []edge.Route{rt})
		var taken *edge.NameTakenError
		if !errors.As(err, &taken) {
			if err == nil {
				x.ingress = m.ingress
			}
			return err
		}
		m.log.Warn("dns64 doh name already used on the shared entrance", "name", taken.Name, "owner", taken.Owner)
		if taken.Name == "*" && rt.Fallback {
			rt.Fallback = false
		} else if !dropName(&rt.Names, taken.Name) {
			return err
		}
		if len(rt.Names) == 0 && !rt.Fallback {
			return err
		}
	}
}

func dropName(names *[]string, n string) bool {
	for i, x := range *names {
		if x == n {
			*names = append((*names)[:i], (*names)[i+1:]...)
			return true
		}
	}
	return false
}

// edgeState: Adresse bzw. Fehler des HTTPS-Eingangs fuer die Seite (Port belegt o. ae.).
func (m *Module) edgeState() (addr, errText string) {
	if m.ingress == nil {
		return "", ""
	}
	for _, l := range m.ingress.Status().Listeners {
		if l.Name == "https" {
			return l.Addr, l.Error
		}
	}
	return "", ""
}
