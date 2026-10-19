package certs

import (
	"context"
	"strconv"

	"github.com/ipv64net/node64/internal/metrics"
)

// Metrics liefert die Kennzahlen der Zertifikatsverwaltung fuer GET /api/metrics (der Kern ruft sie auf): je
// Zertifikat Ablauf, Zustand, Fehler und automatische Erneuerung. Eine Abfrage der Tabelle certs, nichts weiter.
func (m *Manager) Metrics(ctx context.Context, w *metrics.Writer) {
	list, err := m.List(ctx)
	if err != nil {
		return
	}
	w.Gauge("node64_certs", "Certificates", float64(len(list)))
	for _, c := range list {
		name := ""
		if len(c.Names) > 0 {
			name = c.Names[0]
		}
		l := []string{"cert_id", strconv.FormatInt(c.ID, 10), "name", name, "source", c.Source}
		if !c.NotAfter.IsZero() {
			w.Gauge("node64_cert_expiry_seconds", "Certificate expiry (Unix time)", float64(c.NotAfter.Unix()), l...)
		}
		w.Gauge("node64_cert_status", "Always 1, state in the label", 1, append(l, "status", c.Status)...)
		w.Gauge("node64_cert_error", "1 last attempt to obtain/renew failed, 0 not", metrics.Bool(c.LastError != ""), l...)
		w.Gauge("node64_cert_auto_renew", "1 renewed automatically", metrics.Bool(c.AutoRenew), l...)
	}
}
