package module

import (
	"context"

	"github.com/ipv64net/node64/internal/metrics"
)

// MetricsProvider liefert Kennzahlen eines Moduls fuer GET /api/metrics (Prometheus). Wird nur fuer laufende
// Module abgefragt. Namen beginnen mit node64_<modul>_, Werte sollen ohne teure Abfragen auskommen
// (Prometheus fragt typisch alle 15-60 Sekunden).
type MetricsProvider interface {
	Metrics(ctx context.Context, w *metrics.Writer)
}
