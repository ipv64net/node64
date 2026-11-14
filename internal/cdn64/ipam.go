package cdn64

import "context"

// ProxyTarget ist das Ziel eines eingeschalteten Proxy-Hosts (fuer IPAM64; aus dem Entwurf von UlrichSchwarz).
type ProxyTarget struct {
	Name string // erster Name des Hosts
	Host string // Name oder IP des Ziels
}

// ProxyTargets liefert die Ziele der eingeschalteten Proxy-Hosts.
func (m *Module) ProxyTargets(ctx context.Context) []ProxyTarget {
	list, err := m.hosts(ctx)
	if err != nil {
		return nil
	}
	var out []ProxyTarget
	for _, h := range list {
		if h.Enabled && h.TargetHost != "" && len(h.Names) > 0 {
			out = append(out, ProxyTarget{Name: h.Names[0], Host: h.TargetHost})
		}
	}
	return out
}
