package healthchecks

import (
	"context"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Lokale Datenhaltung und Diagramm-Aufloesung (nur diese Node; ipv64 hat eigene, kuerzere Fristen).
const (
	SettingRawDays     = "hc.raw_days"     // Einzelmessungen aufbewahren (Tage)
	SettingHourlyDays  = "hc.hourly_days"  // Stundenwerte aufbewahren (Tage, 0 = unbegrenzt)
	SettingChartDetail = "hc.chart_detail" // standard, fine, finest
)

// Auswahl in den Einstellungen; der erste Wert ist der Standard. Weniger als bisher ist nicht waehlbar,
// die Diagramme bis 30 Tage rechnen aus den Einzelmessungen.
var (
	RawDayOptions      = []int{30, 90, 180, 365}
	HourlyDayOptions   = []int{365, 730, 1825, 0}
	ChartDetailOptions = []string{"standard", "fine", "finest"}
)

// chartBuckets: Aufloesung je Zeitraum und Stufe (raw = jede Messung, hour, day).
var chartBuckets = map[string]map[string]string{
	"standard": {"1h": "raw", "6h": "raw", "24h": "raw", "7d": "hour", "30d": "hour", "1y": "day"},
	"fine":     {"1h": "raw", "6h": "raw", "24h": "raw", "7d": "raw", "30d": "hour", "1y": "hour"},
	"finest":   {"1h": "raw", "6h": "raw", "24h": "raw", "7d": "raw", "30d": "raw", "1y": "hour"},
}

func settingDays(core *store.Store, key string, options []int) int {
	if core != nil {
		if n, err := strconv.Atoi(core.SettingOr(context.Background(), key, "")); err == nil {
			for _, o := range options {
				if o == n {
					return n
				}
			}
		}
	}
	return options[0]
}

// RawDays, HourlyDays und ChartDetail liefern die gueltige Einstellung (sonst den Standard).
func RawDays(core *store.Store) int    { return settingDays(core, SettingRawDays, RawDayOptions) }
func HourlyDays(core *store.Store) int { return settingDays(core, SettingHourlyDays, HourlyDayOptions) }
func ChartDetail(core *store.Store) string {
	if core != nil {
		v := core.SettingOr(context.Background(), SettingChartDetail, "")
		if _, ok := chartBuckets[v]; ok {
			return v
		}
	}
	return ChartDetailOptions[0]
}

// retention liefert die Aufbewahrung fuer die Verdichtung (Stundenwerte 0 = unbegrenzt).
func (m *Module) retention() (raw, hourly time.Duration) {
	raw = time.Duration(RawDays(m.core)) * 24 * time.Hour
	if d := HourlyDays(m.core); d > 0 {
		hourly = time.Duration(d) * 24 * time.Hour
	}
	return raw, hourly
}
