package worldmap

import (
	"math"
	"sync"
)

// Kleine Laender und Gebiete, die Natural Earth 1:110m nicht als Flaeche enthaelt (Singapur, Hongkong, Malta, …):
// fester Punkt aus Laenge/Breite, in dieselbe Projektion umgerechnet wie die Karte (gen/main.go: Natural Earth,
// Breite 1000; Rand links/rechts Fidschi bei 180°/16,5° S, oben Groenland bei 83,65° N - auf 1-2 Einheiten genau).
// So bekommen auch Angriffe aus diesen Laendern und Sensoren dort einen Bogen.
var smallLonLat = map[string][2]float64{
	"AD": {1.52, 42.51}, "AG": {-61.8, 17.08}, "AI": {-63.06, 18.22}, "AS": {-170.7, -14.3}, "AW": {-69.97, 12.52},
	"AX": {19.94, 60.1}, "BB": {-59.55, 13.19}, "BH": {50.56, 26.07}, "BL": {-62.83, 17.9}, "BM": {-64.75, 32.31},
	"BQ": {-68.26, 12.15}, "CC": {96.83, -12.16}, "CK": {-159.78, -21.24}, "CV": {-23.6, 15.1}, "CW": {-68.93, 12.17},
	"CX": {105.69, -10.45}, "DM": {-61.37, 15.41}, "FM": {158.22, 6.92}, "FO": {-6.91, 62.01}, "GD": {-61.68, 12.12},
	"GF": {-53.13, 3.93}, "GG": {-2.58, 49.45}, "GI": {-5.35, 36.14}, "GP": {-61.55, 16.25}, "GU": {144.79, 13.44},
	"HK": {114.17, 22.32}, "IM": {-4.55, 54.24}, "JE": {-2.13, 49.21}, "KI": {173.0, 1.42}, "KM": {43.33, -11.7},
	"KN": {-62.78, 17.3}, "KY": {-81.25, 19.31}, "LC": {-60.98, 13.91}, "LI": {9.55, 47.14}, "MC": {7.42, 43.74},
	"MF": {-63.07, 18.08}, "MH": {171.18, 7.13}, "MO": {113.54, 22.19}, "MP": {145.75, 15.18}, "MQ": {-61.02, 14.64},
	"MS": {-62.19, 16.74}, "MT": {14.45, 35.9}, "MU": {57.55, -20.25}, "MV": {73.51, 4.18}, "NF": {167.95, -29.04},
	"NR": {166.93, -0.52}, "NU": {-169.87, -19.05}, "PF": {-149.43, -17.65}, "PM": {-56.33, 46.89}, "PW": {134.58, 7.51},
	"RE": {55.54, -21.12}, "SC": {55.45, -4.68}, "SG": {103.82, 1.35}, "SH": {-5.71, -15.97}, "SM": {12.46, 43.94},
	"ST": {6.61, 0.19}, "SX": {-63.06, 18.04}, "TC": {-71.8, 21.69}, "TK": {-171.85, -9.17}, "TO": {-175.2, -21.18},
	"TV": {179.2, -8.52}, "VA": {12.45, 41.9}, "VC": {-61.2, 13.25}, "VG": {-64.62, 18.42}, "VI": {-64.9, 17.73},
	"WF": {-176.2, -13.29}, "WS": {-172.1, -13.76}, "YT": {45.17, -12.83},
}

// project: Natural-Earth-Projektion wie gen/main.go (ohne Massstab, y nach Norden).
func project(lon, lat float64) (float64, float64) {
	l, f := lon*math.Pi/180, lat*math.Pi/180
	f2 := f * f
	f4 := f2 * f2
	x := l * (0.8707 - 0.131979*f2 + f4*(-0.013791+f4*(0.003971*f2-0.001529*f4)))
	y := f * (1.007226 + f2*(0.015085+f4*(-0.044475+0.028874*f2-0.005916*f4)))
	return x, y
}

var smallPoints = sync.OnceValue(func() map[string][2]float64 {
	x180, _ := project(180, -16.5)
	_, yn := project(0, 83.65)
	s := 1000 / (2 * x180)
	out := make(map[string][2]float64, len(smallLonLat))
	for cc, ll := range smallLonLat {
		if Has(cc) {
			continue // auf der Karte: Schwerpunkt der Flaeche
		}
		x, y := project(ll[0], ll[1])
		// in der Karte halten: oestlich von Fidschi (z. B. Tuvalu bei 179,2 O) laege der Punkt sonst jenseits des Rands
		px := min(max(math.Round((x*s+500)*10)/10, 3), 997)
		out[cc] = [2]float64{px, math.Round((yn-y)*s*10) / 10}
	}
	return out
})

// Points liefert die festen Punkte der kleinen Laender, die nicht als Flaeche auf der Karte sind (Code -> x, y).
func Points() map[string][2]float64 { return smallPoints() }
