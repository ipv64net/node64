package snmp

import (
	"fmt"
	"math"
	"strings"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// ENTITY-SENSOR-MIB (entPhySensorTable) mit Namen aus ENTITY-MIB (entPhysicalName/Descr).
const (
	entSensor      = ".1.3.6.1.2.1.99.1.1.1"
	entSensorType  = entSensor + ".1" // 8 = celsius
	entSensorScale = entSensor + ".2" // 9 = units (10^0), 8 = milli ...
	entSensorPrec  = entSensor + ".3"
	entSensorValue = entSensor + ".4"
	entSensorOper  = entSensor + ".5" // 1 = ok
	entPhysDescr   = ".1.3.6.1.2.1.47.1.1.1.1.2"
	entPhysName    = ".1.3.6.1.2.1.47.1.1.1.1.7"
)

// collectSensors: Temperaturen als temp:<Name> (Regel temp.system wie im Mapper).
func (c *Collector) collectSensors(r *round) {
	if c.isAbsent("entsensor", r.now) {
		return
	}
	t, err := walkColumns(r.ctx, r.c, []string{entSensorType, entSensorScale, entSensorPrec, entSensorValue, entSensorOper}, c.cfg.MaxRep)
	if emptyTable(t, err) { // Geraet ohne Sensoren (z. B. Drucker): nicht vorhanden statt Teilfehler
		c.markAbsent("entsensor", r.now, true)
		return
	}
	if err != nil {
		r.part.add("ENTITY-SENSOR", err, "temp:")
		return
	}
	c.markAbsent("entsensor", r.now, len(t.col(entSensorType)) == 0)
	var idxs []string
	for _, idx := range t.rows() {
		if typ, _ := num(t.col(entSensorType)[idx]); typ == 8 {
			idxs = append(idxs, idx)
		}
	}
	if len(idxs) == 0 {
		return
	}
	if c.sensorNames == nil || r.now.Sub(c.sensorNamesAt) >= staticEvery {
		var oids []string
		for _, idx := range idxs {
			oids = append(oids, entPhysName+"."+idx, entPhysDescr+"."+idx)
		}
		res, err := getScalars(r.ctx, r.c, oids)
		if err != nil {
			r.part.add(model.T("monitor64.txt.mib_names", "mib", "ENTITY-MIB"), err, "temp:")
		}
		if err == nil || c.sensorNames == nil {
			names := map[string]string{}
			for _, idx := range idxs {
				names[idx] = firstNonEmpty(text(res[entPhysName+"."+idx]), text(res[entPhysDescr+"."+idx]))
			}
			c.sensorNames, c.sensorNamesAt = names, r.now
		}
	}
	count := map[string]int{}
	for _, idx := range idxs {
		count[c.sensorNames[idx]]++
	}
	for _, idx := range idxs {
		if oper, ok := num(t.col(entSensorOper)[idx]); ok && oper != 1 {
			continue
		}
		raw, ok := num(t.col(entSensorValue)[idx])
		if !ok {
			continue
		}
		scale, ok := num(t.col(entSensorScale)[idx])
		if !ok || scale < 1 || scale > 17 {
			scale = 9
		}
		prec, _ := num(t.col(entSensorPrec)[idx])
		if prec < -8 || prec > 9 {
			prec = 0
		}
		v := raw * math.Pow(10, 3*(scale-9)) / math.Pow(10, prec)
		if !finite(v) || v < -60 || v > 250 {
			continue
		}
		name := c.sensorNames[idx]
		key := name
		if name == "" {
			name, key = "Sensor "+idx, "sensor-"+idx
		} else if count[name] > 1 {
			key = name + "#" + idx
		}
		r.out = append(r.out, model.Service{Key: "temp:" + keyPart(key), Name: model.T("monitor64.svc.temp", "name", name), Kind: "temp", Default: true,
			Metrics: []model.Metric{{Name: "temp", Value: round2(v), Unit: "°C", Rule: model.RuleTemp}},
			Text:    strings.Replace(fmt.Sprintf("%.1f °C", v), ".", ",", 1)})
	}
}
