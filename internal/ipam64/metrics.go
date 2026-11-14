package ipam64

import (
	"context"

	"github.com/ipv64net/node64/internal/metrics"
)

// Metrics: Kennzahlen fuer GET /api/metrics (Prometheus): je Praefix belegte Adressen und Auslastung, dazu Konflikte,
// unbekannte Geraete und der letzte Netz-Scan.
func (m *Module) Metrics(ctx context.Context, w *metrics.Writer) {
	snap, err := m.Snapshot(ctx)
	if err != nil {
		return
	}
	w.Gauge("node64_ipam64_prefixes", "Zahl der Praefixe (IPAM64 und DHCP-Netze aus DNS64).", float64(len(snap.Nets)))
	for _, n := range snap.Nets {
		l := []string{"prefix", n.CIDR, "name", n.Name}
		w.Gauge("node64_ipam64_prefix_used", "Belegte Adressen direkt im Praefix.", float64(n.Used), l...)
		w.Gauge("node64_ipam64_prefix_conflicts", "Konflikte im Praefix.", float64(n.Conflicts), l...)
		if n.IsV4() || n.Container() || n.MarkFull {
			w.Gauge("node64_ipam64_prefix_utilization_ratio", "Auslastung (0-1; Container: Anteil der Kinder-Praefixe).", n.Pct/100, l...)
		}
		if n.DHCP {
			w.Gauge("node64_ipam64_prefix_pool_free", "Freie Adressen im DHCP-Adressbereich.", float64(n.PoolFree), l...)
		}
	}
	if found, err := m.Findings(ctx); err == nil {
		c, h := 0, 0
		for _, f := range found {
			if f.Severity == "conflict" {
				c++
			} else {
				h++
			}
		}
		w.Gauge("node64_ipam64_conflicts", "Konflikte (doppelte Adresse, fremde MAC, Lease gegen feste Adresse).", float64(c))
		w.Gauge("node64_ipam64_hints", "Hinweise (Geraet im DHCP-Adressbereich, lange nicht gesehen, fremder DHCP-Server).", float64(h))
	}
	if list, err := m.Unknown(ctx); err == nil {
		w.Gauge("node64_ipam64_unknown_devices", "Unbekannte Geraete (nur in der Nachbartabelle).", float64(len(list)))
	}
	if t := m.LastScan(ctx); !t.IsZero() {
		w.Gauge("node64_ipam64_last_scan_seconds", "Letzter Netz-Scan (Unix-Zeit).", float64(t.Unix()))
	}
}
