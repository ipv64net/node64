package honeypot

import (
	"context"
	"encoding/json"
	"math"

	"github.com/ipv64net/node64/internal/geoip"
	"github.com/ipv64net/node64/internal/honeypot/worldmap"
)

// Laenderkarte (Wunsch „von wo kommen die Angriffe – auf einer Laenderkarte“): Laender nach Ereignissen im Zeitraum
// in fuenf logarithmischen Stufen eingefaerbt (Klassen m0 … m5, Farben in node64.css bzw. der CSS der Info-Seite),
// serverseitig als Inline-SVG. Kartendaten: worldmap (Natural Earth 1:110m, eingebettet).

// MapLevels ist die Zahl der Stufen (ohne Stufe 0 = keine Angriffe).
const MapLevels = 5

// MapView ist die Karte fuer die Seiten (Uebersicht und Info-Seite ohne Oberflaeche).
type MapView struct {
	ViewBox   string
	Countries []MapCountry // alle Laender der Karte (Reihenfolge der Kartendaten)
	Legend    []MapStep    // nur Stufen mit Werten (leer = keine Angriffe mit Land)
	Max       int64        // Ereignisse des staerksten Landes
	Missing   int          // Laender mit Ereignissen, die auf der Karte fehlen (kleine Inseln u. ae.)
}

// MapCountry ist ein Land der Karte.
type MapCountry struct {
	Code, Flag, Name, Path string
	Count, Sources         int64
	Level                  int // 0 = keine Angriffe, 1 … MapLevels
}

// MapStep ist eine Stufe der Legende (From bis To Ereignisse).
type MapStep struct {
	Level    int
	From, To int64
}

// mapBounds liefert die Untergrenzen der Stufen 1 … MapLevels (logarithmisch, Stufe i ab max^((i-1)/MapLevels);
// Index MapLevels+1 = max+1). Das staerkste Land liegt immer in der obersten Stufe.
func mapBounds(max int64) [MapLevels + 2]int64 {
	var b [MapLevels + 2]int64
	for i := 1; i <= MapLevels; i++ {
		b[i] = int64(math.Ceil(math.Pow(float64(max), float64(i-1)/MapLevels) - 1e-9))
		if b[i] < b[i-1] {
			b[i] = b[i-1]
		}
	}
	b[MapLevels+1] = max + 1
	return b
}

// mapLevel ordnet eine Anzahl einer Stufe zu (0 = keine Ereignisse).
func mapLevel(n int64, b [MapLevels + 2]int64) int {
	if n <= 0 {
		return 0
	}
	for i := MapLevels; i > 1; i-- {
		if n >= b[i] {
			return i
		}
	}
	return 1
}

// BuildMap faerbt die Karte nach der Rangliste je Land ein (lang fuer die Laendernamen).
func BuildMap(list []CountryCount, lang string) MapView {
	by := make(map[string]CountryCount, len(list))
	var max int64
	for _, c := range list {
		by[c.Key] = c
		max = maxInt64(max, c.Count)
	}
	b := mapBounds(max)
	all := worldmap.Countries()
	v := MapView{ViewBox: worldmap.ViewBox(), Countries: make([]MapCountry, 0, len(all)), Max: max}
	for _, c := range all {
		x := by[c.Code]
		v.Countries = append(v.Countries, MapCountry{Code: c.Code, Flag: geoip.Flag(c.Code), Name: geoip.Name(c.Code, lang), Path: c.Path,
			Count: x.Count, Sources: x.Sources, Level: mapLevel(x.Count, b)})
	}
	for _, c := range list {
		if c.Count > 0 && !worldmap.Has(c.Key) {
			v.Missing++
		}
	}
	if max > 0 {
		for i := 1; i <= MapLevels; i++ {
			if from, to := b[i], b[i+1]-1; from <= to {
				v.Legend = append(v.Legend, MapStep{Level: i, From: from, To: to})
			}
		}
	}
	return v
}

// validCountry: Filter country=XX (ISO 3166 alpha-2, gross oder klein).
func validCountry(v string) (string, bool) {
	if len(v) != 2 {
		return "", false
	}
	b := []byte(v)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if c < 'A' || c > 'Z' {
			return "", false
		}
		b[i] = c
	}
	return string(b), true
}

// sourcesIn liefert die gespeicherten Quell-IPs eines Landes (Land wird je IP nachgeschlagen, nicht gespeichert).
func (s *Store) sourcesIn(ctx context.Context, cc string) ([]string, error) {
	rows, err := s.st.Reader().QueryContext(ctx, `SELECT DISTINCT src FROM hp_events WHERE src <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var src string
		if err := rows.Scan(&src); err != nil {
			return nil, err
		}
		if countryOf(src) == cc {
			out = append(out, src)
		}
	}
	return out, rows.Err()
}

// countryWhere liefert die Bedingung "src aus Land cc" (eine Liste als JSON-Parameter statt vieler Platzhalter).
// none = das Land hat keine Quell-IPs (dann gibt es nichts zu suchen).
func (s *Store) countryWhere(ctx context.Context, cc string) (cond string, arg any, none bool, err error) {
	srcs, err := s.sourcesIn(ctx, cc)
	if err != nil || len(srcs) == 0 {
		return "", nil, err == nil, err
	}
	raw, _ := json.Marshal(srcs)
	return `src IN (SELECT value FROM json_each(?))`, string(raw), false, nil
}
