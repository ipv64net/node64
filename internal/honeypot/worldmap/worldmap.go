// Package worldmap liefert eine vereinfachte Weltkarte als SVG-Pfade je Land (ISO 3166 alpha-2) fuer die
// Laenderkarte von Honeypot64. Daten: Natural Earth 1:110m Admin-0 Countries (public domain,
// naturalearthdata.com), Projektion Natural Earth, ohne Antarktis; erzeugt mit ./gen (siehe dort), eingebettet,
// keine Netz-Abhaengigkeit zur Laufzeit.
package worldmap

//go:generate go run ./gen -in ne_110m_admin_0_countries.geojson -out world.txt

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed world.txt
var raw string

// Country ist ein Land der Karte.
type Country struct {
	Code string // ISO 3166 alpha-2 (gross)
	Path string // SVG-Pfad (Koordinaten der ViewBox)
}

type data struct {
	viewBox   string
	countries []Country
	byCode    map[string]int
}

var load = sync.OnceValue(func() data { return parse(raw) })

func parse(s string) data {
	d := data{byCode: map[string]int{}}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		if k == "viewBox" {
			d.viewBox = v
			continue
		}
		if _, dup := d.byCode[k]; dup {
			continue
		}
		d.byCode[k] = len(d.countries)
		d.countries = append(d.countries, Country{Code: k, Path: v})
	}
	return d
}

// ViewBox liefert die viewBox der Karte ("0 0 Breite Hoehe").
func ViewBox() string { return load().viewBox }

// Countries liefert alle Laender (nach Code sortiert). Die Liste nicht veraendern.
func Countries() []Country { return load().countries }

// Has meldet, ob ein Land auf der Karte ist (kleine Inseln und Gebiete fehlen in 1:110m).
func Has(code string) bool {
	_, ok := load().byCode[code]
	return ok
}
