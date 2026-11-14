package promscrape

import (
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// smartctl_exporter (prometheus-community, #135): je Platte die Werte von "smartctl -j" als Metriken mit dem Label
// device (ohne /dev/). Daraus wird derselbe SMART-Abschnitt wie beim Agent, der Kern macht daraus die Platten-Dienste
// (Zustand, Temperatur, Verschleiss, Sektoren) samt SMART-Dialog. Formate aus der Ausgabe von smartctl_exporter 0.14.0
// (testdata/smartctl_exporter-0.14.0.txt): smart_status fehlt bei einer kaputten Platte – dann zaehlt Bit 3 des
// Exit-Status von smartctl ("DISK FAILING"); eine schlafende Platte fehlt ganz.

// ExporterSmartctl ist die Kennung des smartctl_exporter.
const ExporterSmartctl = "smartctl_exporter"

const maxSmartctlDevices = 64

// smartctlSMART liest die Platten aus den smartctl-Metriken (nil = keine).
func smartctlSMART(m *Metrics) []m64proto.SMART {
	byDev := map[string]*m64proto.SMART{}
	var order []string
	get := func(s *Sample) *m64proto.SMART {
		d := strings.TrimSpace(s.Label("device"))
		if d == "" || strings.ContainsAny(d, " \t") || len(d) > 64 {
			return nil
		}
		if x, ok := byDev[d]; ok {
			return x
		}
		if len(order) >= maxSmartctlDevices {
			return nil
		}
		x := &m64proto.SMART{Device: "/dev/" + strings.TrimPrefix(d, "/dev/")}
		byDev[d] = x
		order = append(order, d)
		return x
	}
	// Geraete nur aus smartctl_device (ohne Eintrag dort: Platte nicht gelesen, z. B. schlafend)
	for _, s := range m.Get("smartctl_device") {
		x := get(&s)
		if x == nil {
			continue
		}
		x.Model = clip(firstNonEmpty(clean(s.Label("model_name")), clean(s.Label("scsi_product"))), 120)
		x.Serial = clip(clean(s.Label("serial_number")), 120)
		x.Firmware = clip(firstNonEmpty(clean(s.Label("firmware_version")), clean(s.Label("scsi_revision"))), 60)
		switch p := strings.ToLower(s.Label("protocol")); p {
		case "ata", "nvme", "scsi":
			x.Type = p
		default:
			x.Type = clip(p, 16)
		}
	}
	if len(order) == 0 {
		return nil
	}
	val := func(name string) map[string]float64 {
		out := map[string]float64{}
		for _, s := range m.Get(name) {
			if _, ok := byDev[s.Label("device")]; ok && finite(s.Value) {
				out[s.Label("device")] = s.Value
			}
		}
		return out
	}
	u := func(v float64) *uint64 { x := u64(v); return &x }
	f := func(v float64) *float64 { return &v }
	b := func(v bool) *bool { return &v }

	for d, v := range val("smartctl_device_capacity_bytes") {
		byDev[d].CapacityBytes = u64(v)
	}
	for d, v := range val("smartctl_device_nvme_capacity_bytes") {
		if byDev[d].CapacityBytes == 0 {
			byDev[d].CapacityBytes = u64(v)
		}
	}
	for d, v := range val("smartctl_device_smart_status") {
		byDev[d].Passed = b(v == 1)
	}
	for d, v := range val("smartctl_device_smartctl_exit_status") {
		if x := byDev[d]; x.Passed == nil && int(v)&8 != 0 {
			x.Passed = b(false) // "DISK FAILING" (smart_status fehlt dann)
		}
	}
	for _, s := range m.Get("smartctl_device_temperature") {
		if x, ok := byDev[s.Label("device")]; ok && s.Label("temperature_type") == "current" && s.Value > 0 && s.Value < 150 {
			x.TempC = f(s.Value)
		}
	}
	for d, v := range val("smartctl_device_power_on_seconds") {
		if v >= 0 {
			byDev[d].PowerOnHours = u(math.Floor(v / 3600))
		}
	}
	// NVMe
	for d, v := range val("smartctl_device_percentage_used") {
		byDev[d].WearPercentUsed = f(v)
	}
	for d, v := range val("smartctl_device_media_errors") {
		byDev[d].MediaErrors = u(v)
	}
	for d, v := range val("smartctl_device_critical_warning") {
		byDev[d].CriticalWarning = u(v)
	}
	// SCSI/SAS
	for d, v := range val("smartctl_scsi_grown_defect_list") {
		byDev[d].Reallocated = u(v)
	}
	rd, wr := val("smartctl_read_total_uncorrected_errors"), val("smartctl_write_total_uncorrected_errors")
	for _, d := range order {
		r, ok1 := rd[d]
		w, ok2 := wr[d]
		if ok1 || ok2 {
			byDev[d].Uncorrectable = u(r + w)
		}
	}
	for d, v := range val("smartctl_scsi_percentage_used_endurance_indicator") {
		byDev[d].WearPercentUsed = f(v)
	}
	smartctlAttrs(m, byDev)
	smartctlValues(m, byDev)

	out := make([]m64proto.SMART, 0, len(order))
	for _, d := range order {
		out = append(out, *byDev[d])
	}
	return out
}

// smartctlAttrs: ATA-Attribute (je Attribut die Reihen value, worst, thresh, raw) als Tabelle fuer den SMART-Dialog
// und die ausgewerteten Zaehler wie beim Agent (5, 197, 198, 199, Verschleiss).
func smartctlAttrs(m *Metrics, byDev map[string]*m64proto.SMART) {
	type key struct {
		dev string
		id  int
	}
	attrs := map[key]*m64proto.SMARTAttr{}
	var keys []key
	for _, s := range m.Get("smartctl_device_attribute") {
		d := s.Label("device")
		if _, ok := byDev[d]; !ok || !finite(s.Value) {
			continue
		}
		id, err := strconv.Atoi(s.Label("attribute_id"))
		if err != nil || id <= 0 || id > 255 {
			continue
		}
		k := key{d, id}
		a, ok := attrs[k]
		if !ok {
			if len(keys) >= maxSmartctlDevices*m64proto.MaxSmartRows {
				continue
			}
			a = &m64proto.SMARTAttr{ID: id, Name: clip(clean(s.Label("attribute_name")), 120)}
			attrs[k] = a
			keys = append(keys, k)
		}
		switch s.Label("attribute_value_type") {
		case "value":
			a.Value = int(s.Value)
		case "worst":
			a.Worst = int(s.Value)
		case "thresh":
			a.Thresh = int(s.Value)
		case "raw":
			a.Raw = strconv.FormatFloat(s.Value, 'f', -1, 64)
		}
	}
	sort.SliceStable(keys, func(i, j int) bool {
		if keys[i].dev != keys[j].dev {
			return keys[i].dev < keys[j].dev
		}
		return keys[i].id < keys[j].id
	})
	for _, k := range keys {
		x, a := byDev[k.dev], attrs[k]
		if len(x.Attrs) >= m64proto.MaxSmartRows {
			continue
		}
		if a.Thresh > 0 && a.Value > 0 && a.Value <= a.Thresh {
			a.Fail = "now"
		}
		x.Attrs = append(x.Attrs, *a)
		raw, _ := strconv.ParseFloat(a.Raw, 64)
		switch a.ID {
		case 5:
			x.Reallocated = ptrU(raw)
		case 197:
			x.Pending = ptrU(raw)
		case 198:
			x.Uncorrectable = ptrU(raw)
		case 199:
			x.CRCErrors = ptrU(raw)
		case 177, 231, 233, 202, 169: // verbleibende Lebensdauer in % (normierter Wert); erster Treffer gilt
			if x.WearPercentUsed == nil && a.Value > 0 && a.Value <= 100 {
				w := float64(100 - a.Value)
				x.WearPercentUsed = &w
			}
		}
	}
}

func ptrU(v float64) *uint64 { x := u64(v); return &x }

// smartctlValues: einzelne Werte von NVMe- und SCSI-Platten fuer den SMART-Dialog (Schluessel wie beim Agent).
func smartctlValues(m *Metrics, byDev map[string]*m64proto.SMART) {
	for _, d := range []struct{ metric, key, unit string }{
		{"smartctl_device_critical_warning", "critical_warning", "hex"},
		{"smartctl_device_available_spare", "available_spare", "%"},
		{"smartctl_device_available_spare_threshold", "available_spare_threshold", "%"},
		{"smartctl_device_percentage_used", "percentage_used", "%"},
		{"smartctl_device_bytes_read", "data_units_read", "B"},
		{"smartctl_device_bytes_written", "data_units_written", "B"},
		{"smartctl_device_power_cycle_count", "power_cycles", ""},
		{"smartctl_device_media_errors", "media_errors", ""},
		{"smartctl_device_num_err_log_entries", "num_err_log_entries", ""},
		{"smartctl_scsi_grown_defect_list", "grown_defects", ""},
		{"smartctl_read_errors_corrected_by_eccfast", "read_corrected", ""},
		{"smartctl_read_total_uncorrected_errors", "read_uncorrected", ""},
		{"smartctl_write_errors_corrected_by_eccfast", "write_corrected", ""},
		{"smartctl_write_total_uncorrected_errors", "write_uncorrected", ""},
	} {
		for _, s := range m.Get(d.metric) {
			x, ok := byDev[s.Label("device")]
			if !ok || len(x.Attrs) > 0 || !finite(s.Value) || len(x.Values) >= m64proto.MaxSmartRows {
				continue // ATA: die Tabelle sagt alles
			}
			x.Values = append(x.Values, m64proto.SMARTValue{Key: d.key, Value: s.Value, Unit: d.unit})
		}
	}
	for _, x := range byDev {
		if len(x.Attrs) > 0 || len(x.Values) == 0 {
			continue
		}
		if x.TempC != nil {
			x.Values = append([]m64proto.SMARTValue{{Key: "temperature", Value: *x.TempC, Unit: "°C"}}, x.Values...)
		}
		if x.PowerOnHours != nil {
			x.Values = append(x.Values, m64proto.SMARTValue{Key: "power_on_hours", Value: float64(*x.PowerOnHours), Unit: "h"})
		}
	}
}

// clean: Platzhalter des Exporters ("unknown") zaehlen nicht.
func clean(s string) string {
	s = strings.TrimSpace(s)
	if strings.EqualFold(s, "unknown") {
		return ""
	}
	return s
}
