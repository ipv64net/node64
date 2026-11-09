package snmp

import (
	"fmt"
	"strings"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Printer-MIB (RFC 3805) und hrPrinterTable (HOST-RESOURCES).
const (
	prtSupply      = ".1.3.6.1.2.1.43.11.1.1"
	prtSupplyClass = prtSupply + ".4" // 3 verbraucht sich, 4 Auffangbehaelter
	prtSupplyType  = prtSupply + ".5"
	prtSupplyDescr = prtSupply + ".6"
	prtSupplyMax   = prtSupply + ".8"
	prtSupplyLevel = prtSupply + ".9" // -1 other, -2 unknown, -3 someRemaining
	prtInput       = ".1.3.6.1.2.1.43.8.2.1"
	prtInputType   = prtInput + ".2" // 5 = manuelle Zufuhr
	prtInputMax    = prtInput + ".9"
	prtInputLevel  = prtInput + ".10"
	prtInputName   = prtInput + ".13"
	prtInputDescr  = prtInput + ".18"
	prtLifeCount   = ".1.3.6.1.2.1.43.10.2.1.4"
	hrPrinter      = ".1.3.6.1.2.1.25.3.5.1"
	hrPrinterState = hrPrinter + ".1" // 3 idle, 4 printing, 5 warmup
	hrPrinterErr   = hrPrinter + ".2" // BITS
)

// Bits von hrPrinterDetectedErrorState (Bit 0 = hoechstes Bit des ersten Bytes); true = Fehler (sonst nur Hinweis).
var printerBits = []struct {
	text string
	err  bool
}{
	{"Papier knapp", false}, {"kein Papier", true}, {"Toner knapp", false}, {"kein Toner", true}, {"Klappe offen", true},
	{"Papierstau", true}, {"offline", true}, {"Wartung nötig", true}, {"Papierfach fehlt", true}, {"Ausgabefach fehlt", true},
	{"Verbrauchsmaterial fehlt", true}, {"Ausgabefach fast voll", false}, {"Ausgabefach voll", true}, {"Papierfach leer", false},
	{"Wartung überfällig", false},
}

var supplyTypes = map[int]string{3: "Toner", 4: "Resttoner", 5: "Tinte", 9: "Trommel", 15: "Fixiereinheit", 19: "Resttinte"}

// collectPrinter: Dienst printer (Status, Fehler), supply:<n> (Fuellstand) und tray:<n> (Papier).
func (c *Collector) collectPrinter(r *round) {
	if c.isAbsent("printer", r.now) {
		return
	}
	t, err := walkColumns(r.ctx, r.c, []string{prtSupplyClass, prtSupplyType, prtSupplyDescr, prtSupplyMax, prtSupplyLevel,
		prtInputType, prtInputMax, prtInputLevel, prtInputName, prtInputDescr, prtLifeCount, hrPrinterState, hrPrinterErr}, c.cfg.MaxRep)
	if err != nil {
		r.part.add("Printer-MIB", err, "printer", "supply:", "tray:")
		return
	}
	present := len(t.col(prtSupplyLevel)) > 0 || len(t.col(hrPrinterState)) > 0
	c.markAbsent("printer", r.now, !present)
	if !present {
		return
	}
	// Status
	ps := model.Service{Key: "printer", Name: "Drucker", Kind: "printer", Default: true}
	var parts, errs []string
	if p, ok := firstVal(t.col(hrPrinterState)); ok {
		v, _ := num(p)
		switch v {
		case 3:
			parts = append(parts, "bereit")
		case 4:
			parts = append(parts, "druckt")
		case 5:
			parts = append(parts, "wärmt auf")
		}
	}
	if p, ok := firstVal(t.col(hrPrinterErr)); ok {
		b := rawBytes(p)
		for i, bit := range printerBits {
			if i/8 < len(b) && b[i/8]&(0x80>>(i%8)) != 0 {
				parts = append(parts, bit.text)
				if bit.err {
					errs = append(errs, bit.text)
				}
			}
		}
	}
	if len(errs) > 0 {
		ps.Facts = append(ps.Facts, model.Fact{Code: FactPrinterError, Text: strings.Join(errs, ", ")})
	}
	if p, ok := firstVal(t.col(prtLifeCount)); ok {
		if v, ok := num(p); ok && v >= 0 {
			ps.Metrics = append(ps.Metrics, model.Metric{Name: "pages", Value: v})
			parts = append(parts, fmt.Sprintf("%.0f Seiten", v))
		}
	}
	ps.Text = strings.Join(parts, " · ")
	r.out = append(r.out, ps)
	// Verbrauchsmaterial (Index hrDeviceIndex.supplyIndex)
	for _, idx := range t.rows() {
		lvl, ok := num(t.col(prtSupplyLevel)[idx])
		if !ok {
			continue
		}
		typ, _ := num(t.col(prtSupplyType)[idx])
		name := firstNonEmpty(text(t.col(prtSupplyDescr)[idx]), supplyTypes[int(typ)], "Verbrauchsmaterial "+idx)
		s := model.Service{Key: "supply:" + idx, Name: name, Kind: "supply", Default: true}
		mx, _ := num(t.col(prtSupplyMax)[idx])
		class, _ := num(t.col(prtSupplyClass)[idx])
		switch {
		case lvl >= 0 && mx > 0:
			v := pct(lvl, mx)
			s.Metrics = []model.Metric{{Name: "level", Value: v, Unit: "%", Rule: RulePrinterSupply}}
			if class == 4 {
				s.Text = fmt.Sprintf("noch %.0f %% Platz", v)
			} else {
				s.Text = fmt.Sprintf("%.0f %%", v)
			}
		case lvl == -3:
			s.Text = "vorhanden"
		default:
			s.Text = "Füllstand unbekannt"
		}
		r.out = append(r.out, s)
	}
	// Papierfaecher
	for _, idx := range t.rows() {
		typ, ok := num(t.col(prtInputType)[idx])
		if !ok {
			continue
		}
		name := firstNonEmpty(text(t.col(prtInputName)[idx]), text(t.col(prtInputDescr)[idx]), "Fach "+idx)
		manual := typ == 5
		s := model.Service{Key: "tray:" + idx, Name: "Papier " + name, Kind: "tray", Default: !manual}
		lvl, okl := num(t.col(prtInputLevel)[idx])
		mx, _ := num(t.col(prtInputMax)[idx])
		switch {
		case okl && lvl >= 0 && mx > 0:
			v := pct(lvl, mx)
			s.Metrics = []model.Metric{{Name: "level", Value: v, Unit: "%"}}
			s.Text = fmt.Sprintf("%.0f %%", v)
			if lvl == 0 && !manual {
				s.Facts = append(s.Facts, model.Fact{Code: FactPaperEmpty, Text: name + " leer"})
				s.Text = "leer"
			}
		case okl && lvl == 0 && !manual:
			s.Facts = append(s.Facts, model.Fact{Code: FactPaperEmpty, Text: name + " leer"})
			s.Text = "leer"
		case okl && lvl == -3:
			s.Text = "Papier vorhanden"
		default:
			s.Text = "Füllstand unbekannt"
		}
		r.out = append(r.out, s)
	}
}

// firstVal: Wert mit dem kleinsten Index einer Spalte (ein Drucker je Geraet).
func firstVal(m map[string]pdu) (pdu, bool) {
	idx := make([]string, 0, len(m))
	for k := range m {
		idx = append(idx, k)
	}
	if len(idx) == 0 {
		return pdu{}, false
	}
	sortIdx(idx)
	return m[idx[0]], true
}
