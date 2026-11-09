package eval

import (
	"math"
	"time"
)

// Trend fuer Fuellstaende (Plan "Zahlenwerte"): lineare Ausgleichsgerade ueber 7 Tage, erst ab 24 h Daten.
const (
	TrendWindow  = 7 * 24 * time.Hour
	TrendMinSpan = 24 * time.Hour
)

// NoForecast ist der Wert fuer KindFSTrendDays, wenn der Fuellstand nicht steigt (oder zu wenig Daten
// vorliegen): so gross, dass keine Schwelle greift.
const NoForecast = 1e6

// Point ist ein Punkt einer Messreihe.
type Point struct {
	At time.Time
	V  float64
}

// TrendResult ist das Ergebnis der Trendrechnung.
type TrendResult struct {
	Enough bool    `json:"enough"` // mindestens TrendMinSpan Daten im Fenster
	Full   bool    `json:"full"`   // der Wert laeuft auf die Grenze zu
	Days   float64 `json:"days"`   // Tage bis zur Grenze ab dem letzten Wert (nur mit Full)
	Slope  float64 `json:"slope"`  // Steigung je Tag
}

// Value liefert den Messwert fuer KindFSTrendDays (NoForecast ohne Vorhersage).
func (r TrendResult) Value() float64 {
	if !r.Enough || !r.Full {
		return NoForecast
	}
	return math.Min(r.Days, NoForecast)
}

// Trend rechnet aus den Punkten der letzten TrendWindow vor now, wann limit erreicht ist (z. B. 100 fuer
// Prozent belegt oder 0 fuer freie Bytes). Punkte nach now oder mit nicht endlichem Wert zaehlen nicht.
// Ausgangspunkt ist der letzte Wert, die Geschwindigkeit die Steigung der Ausgleichsgeraden.
func Trend(points []Point, now time.Time, limit float64) TrendResult {
	from := now.Add(-TrendWindow)
	var n, sx, sy, sxx, sxy float64
	var first, last time.Time
	lastV := 0.0
	for _, p := range points {
		if p.At.Before(from) || p.At.After(now) || math.IsNaN(p.V) || math.IsInf(p.V, 0) {
			continue
		}
		if first.IsZero() || p.At.Before(first) {
			first = p.At
		}
		if last.IsZero() || !p.At.Before(last) {
			last, lastV = p.At, p.V
		}
	}
	if first.IsZero() || last.Sub(first) < TrendMinSpan {
		return TrendResult{}
	}
	for _, p := range points {
		if p.At.Before(from) || p.At.After(now) || math.IsNaN(p.V) || math.IsInf(p.V, 0) {
			continue
		}
		x := p.At.Sub(first).Hours() / 24 // Tage ab dem ersten Punkt (kleine Zahlen, genauer)
		n++
		sx += x
		sy += p.V
		sxx += x * x
		sxy += x * p.V
	}
	res := TrendResult{Enough: true}
	den := n*sxx - sx*sx
	if den <= 0 {
		return res
	}
	res.Slope = (n*sxy - sx*sy) / den
	switch {
	case lastV == limit:
		// erreicht; jenseits der Grenze gibt es keine Vorhersage (die Richtung ist dann nicht eindeutig,
		// der Fuellstand selbst ist ohnehin Kritisch)
		res.Full, res.Days = true, 0
	case limit > lastV && res.Slope > 0:
		res.Full, res.Days = true, (limit-lastV)/res.Slope
	case limit < lastV && res.Slope < 0:
		res.Full, res.Days = true, (lastV-limit)/-res.Slope
	}
	return res
}
