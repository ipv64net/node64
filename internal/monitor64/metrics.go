package monitor64

import (
	"context"
	"strings"

	"github.com/ipv64net/node64/internal/metrics"
	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Prometheus-Export unter /api/metrics (Plan "Prometheus"): liest nur den Stand im Speicher (keine Datenbank).
// Abschaltbar ueber die Einstellung monitor64.prometheus = "0"; Tags als Label ueber monitor64.prom_tags.

const (
	setProm     = "monitor64.prometheus"
	setPromTags = "monitor64.prom_tags"
)

// Metrics schreibt Werte und Zustaende aller Hosts (module.MetricsProvider).
func (m *Module) Metrics(ctx context.Context, w *metrics.Writer) {
	if m.st.SettingOr(ctx, setProm, "1") == "0" {
		return
	}
	tags := m.st.SettingOr(ctx, setPromTags, "1") != "0"
	// Dienstnamen sind teils Token ("i18n:monitor64.svc.fs?name=/"): als Label englisch und fest (Grafana, Alarme)
	name := func(s string) string { return s }
	if m.g.Translate != nil {
		name = func(s string) string {
			return model.Translate(s, func(k string, a ...any) string { return m.g.Translate("en", k, a...) })
		}
	}
	for _, v := range m.Views() {
		if v.Cluster != nil && !v.Cluster.Here { // Cluster: Werte liefert die ueberwachende Node
			continue
		}
		h := v.Host
		base := []string{"host", h.Name, "group", h.Group}
		if tags && len(h.Tags) > 0 {
			base = append(base, "tags", strings.Join(h.Tags, ","))
		}
		w.Gauge("node64_monitor_host_up", "Monitor64: Host erreichbar (1) oder nicht (0)", metrics.Bool(v.View != eval.ViewUnreachable), base...)
		for _, s := range v.Services {
			sl := append(append([]string{}, base...), "service", name(s.Name), "key", s.Key)
			w.Gauge("node64_monitor_state", "Monitor64: Zustand eines Dienstes (0=OK 1=Warnung 2=Kritisch 3=Unbekannt)", float64(s.State), sl...)
			for _, mt := range s.Metrics {
				ml := append(append([]string{}, sl...), "metric", mt.Name, "unit", promUnit(mt.Unit))
				w.Gauge("node64_monitor_value", "Monitor64: Messwert eines Dienstes", mt.Value, ml...)
			}
		}
	}
}

// promUnit: Einheit als Label-Wert ohne Sonderzeichen.
func promUnit(u string) string {
	switch u {
	case "%":
		return "percent"
	case "°C":
		return "celsius"
	case "B":
		return "bytes"
	case "B/s":
		return "bytes_per_second"
	case "Mbit/s":
		return "mbit_per_second"
	}
	return u
}
