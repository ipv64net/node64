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
var upsAlarms = map[int]string{1: "Batterie defekt", 5: "Temperatur", 6: "Eingang gestört", 7: "Ausgang gestört", 8: "Überlast",
	9: "Bypass", 10: "Bypass gestört", 13: "Ladegerät defekt", 14: "Ausgang aus", 15: "USV aus", 16: "Lüfter", 17: "Sicherung",
	18: "Allgemeiner Fehler", 19: "Selbsttest fehlgeschlagen", 20: "Kommunikation verloren", 22: "Abschaltung angekündigt",
	23: "Abschaltung steht bevor"}

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
		r.part.add("UPS-MIB Tabellen", err, "ups")
	}
	name := strings.TrimSpace(text(res[upsManufacturer]) + " " + text(res[upsModel]))
	s := model.Service{Key: "ups", Name: "USV", Kind: "ups", Default: true}
	if name != "" {
		s.Name = "USV " + name
	}
	var parts []string
	src, _ := num(res[upsOutSource])
	secs, okSecs := num(res[upsSecsOnBatt])
	onBatt := src == 5 || (src == 0 && okSecs && secs > 0)
	switch src {
	case 3:
		parts = append(parts, "Netzbetrieb")
	case 4:
		parts = append(parts, "Bypass")
	case 5:
		parts = append(parts, "auf Batterie")
	case 6, 7:
		parts = append(parts, "Netzbetrieb (Spannung geregelt)")
	}
	if onBatt {
		txt := "auf Batterie"
		if okSecs && secs > 0 {
			txt += " seit " + durTextSec(secs)
		}
		s.Facts = append(s.Facts, model.Fact{Code: factUPSOnBattery, Text: txt})
	}
	s.Metrics = append(s.Metrics, model.Metric{Name: "on_battery", Value: b2f(onBatt)})
	if v, ok := num(res[upsCharge]); ok && v >= 0 && v <= 100 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "charge", Value: v, Unit: "%"})
		parts = append(parts, fmt.Sprintf("Ladung %.0f %%", v))
	}
	if v, ok := num(res[upsMinutesLeft]); ok && v >= 0 && v < 100000 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "runtime", Value: v * 60, Unit: "s", Rule: RuleUPSRuntime})
		parts = append(parts, "Restlaufzeit "+durTextSec(v*60))
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
			parts = append(parts, fmt.Sprintf("Last %.0f %%", load))
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
				alarms = append(alarms, a)
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
		s.Facts = append(s.Facts, model.Fact{Code: FactUPSBatteryLow, Text: "Batterie schwach"})
		parts = append(parts, "Batterie schwach")
	case 4:
		s.Facts = append(s.Facts, model.Fact{Code: FactUPSBatteryLow, Text: "Batterie erschöpft"})
		parts = append(parts, "Batterie erschöpft")
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
