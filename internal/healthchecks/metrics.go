package healthchecks

import (
	"context"
	"time"

	"github.com/ipv64net/node64/internal/metrics"
	"github.com/ipv64net/node64/internal/scheduler"
)

// Metrics: Kennzahlen je Check fuer GET /api/metrics (Prometheus). Zustand wie in der Liste
// (inkl. "unchecked" = seit drei Intervallen keine Messung).
func (m *Module) Metrics(ctx context.Context, w *metrics.Writer) {
	list, err := m.st.Checks(ctx)
	if err != nil {
		return
	}
	certs := m.st.CertExpiries(ctx)
	now := time.Now()
	counts := map[string]int{}
	for _, c := range list {
		rt := m.liveRuntime(c)
		state := string(rt.State)
		if state == "" {
			state = "pending"
		}
		if stale(c, rt.LastCheck, state) {
			state = "unchecked"
		}
		if c.Paused {
			state = string(scheduler.StatePaused)
		}
		maint := m.st.InMaintenance(ctx, c.Token, now)
		if maint && state != string(scheduler.StatePaused) {
			counts["maintenance"]++
		}
		counts[state]++
		l := []string{"token", c.Token, "check", c.Name, "type", string(c.Type), "group", c.Group}
		w.Gauge("node64_hc_check_state", "Aktueller Zustand des Checks (Wert immer 1, Zustand im Label state).", 1,
			append(l[:len(l):len(l)], "state", state)...)
		switch state {
		case string(scheduler.StateUp), string(scheduler.StateDegraded):
			w.Gauge("node64_hc_check_up", "Check erreichbar (1) oder gestoert (0); fehlt bei pausiert, wartend, nicht ueberwacht.", 1, l...)
		case string(scheduler.StateDown), string(scheduler.StateFlapping), string(scheduler.StateDependent), string(scheduler.StateStabilizing):
			w.Gauge("node64_hc_check_up", "Check erreichbar (1) oder gestoert (0); fehlt bei pausiert, wartend, nicht ueberwacht.", 0, l...)
		}
		w.Gauge("node64_hc_check_maintenance", "Check ist gerade in einer Wartung.", metrics.Bool(maint), l...)
		if !rt.LastCheck.IsZero() {
			w.Gauge("node64_hc_check_last_seconds", "Zeit der letzten Messung (Unix-Zeit).", float64(rt.LastCheck.Unix()), l...)
			w.Gauge("node64_hc_check_latency_seconds", "Antwortzeit der letzten Messung.", rt.LastLatency.Seconds(), l...)
		}
		w.Gauge("node64_hc_check_consecutive_failures", "Fehlgeschlagene Messungen in Folge.", float64(rt.ConsecutiveFail), l...)
		if c.Interval > 0 {
			w.Gauge("node64_hc_check_interval_seconds", "Pruefintervall.", c.Interval.Seconds(), l...)
		}
		if t, ok := certs[c.Token]; ok {
			w.Gauge("node64_hc_check_cert_expiry_seconds", "Ablauf des TLS-Zertifikats (Unix-Zeit).", float64(t.Unix()), l...)
		}
	}
	for _, s := range []string{"up", "down", "degraded", "flapping", "dependent", "stabilizing", "paused", "pending", "unchecked", "maintenance"} {
		w.Gauge("node64_hc_checks", "Anzahl Checks je Zustand (maintenance zaehlt zusaetzlich).", float64(counts[s]), "state", s)
	}
	if inc, err := m.st.Incidents(ctx, "", 500); err == nil {
		open := 0
		for _, i := range inc {
			if i.Open {
				open++
			}
		}
		w.Gauge("node64_hc_incidents_open", "Offene Stoerungen.", float64(open))
	}
}
