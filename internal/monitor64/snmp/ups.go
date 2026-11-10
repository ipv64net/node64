package snmp

import (
	"fmt"
	"strings"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// UPS-MIB (RFC 1628).
const (
	upsMIB          = ".1.3.6.1.2.1.33.1"
	upsManufacturer = upsMIB + ".1.1.0"
	upsModel        = upsMIB + ".1.2.0"
	upsBattStatus   = upsMIB + ".2.1.0" // 2 normal, 3 low, 4 depleted
	upsSecsOnBatt   = upsMIB + ".2.2.0"
	upsMinutesLeft  = upsMIB + ".2.3.0"
	upsCharge       = upsMIB + ".2.4.0"
	upsBattTemp     = upsMIB + ".2.7.0"
	upsOutSource    = upsMIB + ".4.1.0"       // 3 normal, 4 bypass, 5 battery, 6 booster, 7 reducer
	upsOutLoad      = upsMIB + ".4.4.1.5"     // je Phase
	upsInVoltage    = upsMIB + ".3.3.1.3"     // je Phase
	upsAlarmDescr   = upsMIB + ".6.2.1.2"     // upsAlarmDescr (OID aus upsWellKnownAlarms)
	upsWellKnown    = ".1.3.6.1.2.1.33.1.6.3" // .N
)

// Bekannte Alarme (upsWellKnownAlarms); ohne Eintrag: nur Hinweis, kein Alarm-Fact.
var upsAlarms = map[int]string{1: "monitor64.txt.upsa_battery_bad", 5: "monitor64.txt.upsa_temp", 6: "monitor64.txt.upsa_input_bad",
	7: "monitor64.txt.upsa_output_bad", 8: "monitor64.txt.ups_overload", 9: "monitor64.txt.upsa_bypass", 10: "monitor64.txt.upsa_bypass_bad",
	13: "monitor64.txt.upsa_charger", 14: "monitor64.txt.upsa_output_off", 15: "monitor64.txt.upsa_ups_off", 16: "monitor64.txt.upsa_fan",
	17: "monitor64.txt.upsa_fuse", 18: "monitor64.txt.upsa_general", 19: "monitor64.txt.upsa_test_failed", 20: "monitor64.txt.upsa_comm_lost",
	22: "monitor64.txt.upsa_shutdown_pending", 23: "monitor64.txt.upsa_shutdown_imminent"}

// collectUPS: Dienst ups (Ladung, Restlaufzeit, Last; auf Batterie, Batterie schwach, Alarme).
func (c *Collector) collectUPS(r *round) {
	if c.isAbsent("ups", r.now) {
		return
	}
	res, err := getScalars(r.ctx, r.c, []string{upsManufacturer, upsModel, upsBattStatus, upsSecsOnBatt, upsMinutesLeft, upsCharge, upsBattTemp, upsOutSource})
	if err != nil {
		r.part.add("UPS-MIB", err, "ups")
		return
	}
	_, hasStatus := res[upsBattStatus]
	_, hasSource := res[upsOutSource]
	c.markAbsent("ups", r.now, !hasStatus && !hasSource)
	if !hasStatus && !hasSource {
		return
	}
	t, err := walkColumns(r.ctx, r.c, []string{upsOutLoad, upsInVoltage, upsAlarmDescr}, c.cfg.MaxRep)
	if err != nil {
		r.part.add(model.T("monitor64.txt.mib_tables", "mib", "UPS-MIB"), err, "ups")
	}
	name := strings.TrimSpace(text(res[upsManufacturer]) + " " + text(res[upsModel]))
	s := model.Service{Key: "ups", Name: model.T("monitor64.svc.ups_plain"), Kind: "ups", Default: true}
	if name != "" {
		s.Name = model.T("monitor64.svc.ups", "name", name)
	}
	var parts []string
	src, _ := num(res[upsOutSource])
	secs, okSecs := num(res[upsSecsOnBatt])
	onBatt := src == 5 || (src == 0 && okSecs && secs > 0)
	switch src {
	case 3:
		parts = append(parts, model.T("monitor64.txt.ups_online"))
	case 4:
		parts = append(parts, "Bypass")
	case 5:
		parts = append(parts, model.T("monitor64.txt.ups_on_battery"))
	case 6, 7:
		parts = append(parts, model.T("monitor64.txt.ups_online_avr"))
	}
	if onBatt {
		txt := model.T("monitor64.txt.ups_on_battery")
		if okSecs && secs > 0 {
			txt = model.T("monitor64.txt.ups_on_battery_since", "d", model.Sub(durTextSec(secs)))
		}
		s.Facts = append(s.Facts, model.Fact{Code: factUPSOnBattery, Text: txt})
	}
	s.Metrics = append(s.Metrics, model.Metric{Name: "on_battery", Value: b2f(onBatt)})
	if v, ok := num(res[upsCharge]); ok && v >= 0 && v <= 100 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "charge", Value: v, Unit: "%"})
		parts = append(parts, model.T("monitor64.txt.charge", "v", fmt.Sprintf("%.0f", v)))
	}
	if v, ok := num(res[upsMinutesLeft]); ok && v >= 0 && v < 100000 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "runtime", Value: v * 60, Unit: "s", Rule: RuleUPSRuntime})
		parts = append(parts, model.T("monitor64.txt.runtime", "v", model.Sub(durTextSec(v*60))))
	}
	if t != nil {
		load := -1.0
		for _, p := range t.col(upsOutLoad) {
			if v, ok := num(p); ok && v >= 0 && v < 1000 {
				load = max(load, v)
			}
		}
		if load >= 0 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "load", Value: load, Unit: "%"})
			parts = append(parts, model.T("monitor64.txt.load_pct", "v", fmt.Sprintf("%.0f", load)))
		}
		for _, idx := range t.rows() {
			if v, ok := num(t.col(upsInVoltage)[idx]); ok && v >= 0 && v < 1000 {
				s.Metrics = append(s.Metrics, model.Metric{Name: "input_v", Value: v, Unit: "V"})
				break
			}
		}
		var alarms []string
		for _, idx := range t.rows() {
			p, ok := t.col(upsAlarmDescr)[idx]
			if !ok {
				continue
			}
			o, _ := p.Value.(string)
			oo, ok := parseOID(o)
			wk, _ := parseOID(upsWellKnown)
			if !ok || !oo.hasPrefix(wk) || len(oo) != len(wk)+1 {
				continue
			}
			if a, ok := upsAlarms[int(oo[len(wk)])]; ok {
				alarms = append(alarms, model.T(a))
			}
		}
		if len(alarms) > 0 {
			s.Facts = append(s.Facts, model.Fact{Code: FactUPSAlarm, Text: strings.Join(limitList(alarms, 5), ", ")})
			parts = append(parts, "Alarm: "+strings.Join(limitList(alarms, 3), ", "))
		}
	}
	if v, ok := num(res[upsBattTemp]); ok && v > -40 && v < 120 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "battery_temp", Value: v, Unit: "°C"})
	}
	switch st, _ := num(res[upsBattStatus]); st {
	case 3:
		s.Facts = append(s.Facts, model.Fact{Code: FactUPSBatteryLow, Text: model.T("monitor64.txt.ups_low_battery")})
		parts = append(parts, model.T("monitor64.txt.ups_low_battery"))
	case 4:
		s.Facts = append(s.Facts, model.Fact{Code: FactUPSBatteryLow, Text: model.T("monitor64.txt.ups_depleted")})
		parts = append(parts, model.T("monitor64.txt.ups_depleted"))
	}
	s.Text = strings.Join(parts, " · ")
	r.out = append(r.out, s)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
