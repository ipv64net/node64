package dyndns

import (
	"context"
	"time"

	"github.com/ipv64net/node64/internal/metrics"
)

// Metrics: Kennzahlen je Ziel fuer GET /api/metrics (Prometheus).
func (m *Module) Metrics(ctx context.Context, w *metrics.Writer) {
	list, err := m.Targets(ctx)
	if err != nil {
		return
	}
	counts := map[string]int{}
	for _, t := range list {
		st := t.Status()
		counts[st]++
		l := []string{"target", t.FQDN()}
		w.Gauge("node64_dyndns_target_status", "Zustand des Ziels (Wert immer 1, Zustand im Label status).", 1, "target", t.FQDN(), "status", st)
		if st == "off" || st == "paused" || st == "new" {
			continue
		}
		w.Gauge("node64_dyndns_target_ok", "Letzte Aktualisierung erfolgreich (1) oder Fehler (0); fehlt bei aus/pausiert/neu.", metrics.Bool(st != "error"), l...)
		if !t.LastOKAt.IsZero() {
			w.Gauge("node64_dyndns_target_last_ok_seconds", "Letzte erfolgreiche Aktualisierung (Unix-Zeit).", float64(t.LastOKAt.Unix()), l...)
		}
		if !t.LastErrAt.IsZero() {
			w.Gauge("node64_dyndns_target_last_error_seconds", "Letzter Fehler (Unix-Zeit).", float64(t.LastErrAt.Unix()), l...)
		}
	}
	for _, s := range []string{"ok", "cdn", "pending", "dns", "error", "paused", "off", "new"} {
		w.Gauge("node64_dyndns_targets", "Anzahl Ziele je Zustand.", float64(counts[s]), "status", s)
	}
	w.Gauge("node64_dyndns_updates_24h", "Aufrufe bei ipv64.net in den letzten 24 Stunden.", float64(m.callsSince(ctx, time.Now().Add(-24*time.Hour))))
}
