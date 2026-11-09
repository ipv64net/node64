package snmp

import (
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// collectCustom: eigene OIDs als Dienst oid:<OID> mit Messgroesse value (Zahl, Zaehler als Rate) bzw. Text.
func (c *Collector) collectCustom(r *round) {
	if len(c.cfg.Custom) == 0 {
		return
	}
	oids := make([]string, 0, len(c.cfg.Custom))
	for _, co := range c.cfg.Custom {
		oids = append(oids, co.OID)
	}
	res, err := getScalars(r.ctx, r.c, oids)
	if err != nil {
		r.part.add("eigene OIDs", err, "oid:")
		return
	}
	r.at = c.now() // Messzeitpunkt der Zaehler
	for _, co := range c.cfg.Custom {
		s := model.Service{Key: "oid:" + co.OID, Name: co.Name, Kind: "oid", Default: true}
		p, ok := res[co.OID]
		if !ok {
			s.Text = "kein Wert"
			r.out = append(r.out, s)
			continue
		}
		factor := co.Factor
		if factor == 0 {
			factor = 1
		}
		switch {
		case co.Counter:
			if rt, ok := c.rate("oid|"+co.OID, p, r.at); ok && finite(rt*factor) {
				v := round4(rt * factor)
				s.Metrics = []model.Metric{{Name: "value", Value: v, Unit: co.Unit, Rule: co.Rule}}
				s.Text = valueText(v, co.Unit)
			}
		default:
			if f, ok := num(p); ok && finite(f*factor) {
				v := round4(f * factor)
				s.Metrics = []model.Metric{{Name: "value", Value: v, Unit: co.Unit, Rule: co.Rule}}
				s.Text = valueText(v, co.Unit)
			} else {
				s.Text = text(p) // Text-Wert: nur Anzeige
			}
		}
		r.out = append(r.out, s)
	}
}
