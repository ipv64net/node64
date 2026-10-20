// Command gen erzeugt die eingebettete Weltkarte (world.txt) aus Natural Earth 1:110m Admin-0 Countries
// (public domain, https://www.naturalearthdata.com, Datei geojson/ne_110m_admin_0_countries.geojson aus
// github.com/nvkelso/natural-earth-vector). Die GeoJSON-Datei liegt nicht im Repo; einmalig laden und angeben:
//
//	go run ./internal/honeypot/worldmap/gen -in ne_110m_admin_0_countries.geojson -out internal/honeypot/worldmap/world.txt
//
// Je Land eine Zeile "CC <SVG-Pfad>" (ISO 3166 alpha-2), Projektion Natural Earth, ganze Zahlen, relative Pfade,
// vereinfacht (Douglas-Peucker). Antarktis faellt weg; ISO_A2 = -99 wird ueber ISO_A2_EH bzw. ADM0_A3 zugeordnet
// (Frankreich, Norwegen, Kosovo XK, Nordzypern zu CY, Somaliland zu SO). Mehrere Eintraege eines Codes werden ein Pfad.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
)

// a3Codes ordnet Gebiete ohne ISO_A2/ISO_A2_EH einem Land zu (so liefern es auch die Laenderdaten).
var a3Codes = map[string]string{"CYN": "CY", "SOL": "SO", "KOS": "XK"}

// skip: Antarktis (nimmt viel Platz, keine Angreifer).
var skip = map[string]bool{"AQ": true}

type feature struct {
	Properties map[string]any `json:"properties"`
	Geometry   struct {
		Type        string          `json:"type"`
		Coordinates json.RawMessage `json:"coordinates"`
	} `json:"geometry"`
}

type pt struct{ x, y float64 }

func main() {
	in := flag.String("in", "ne_110m_admin_0_countries.geojson", "Natural-Earth-GeoJSON (1:110m Admin-0 Countries)")
	out := flag.String("out", "world.txt", "Ausgabe")
	width := flag.Float64("width", 1000, "Breite der Karte (Einheiten der viewBox)")
	tol := flag.Float64("tol", 0.4, "Toleranz der Vereinfachung (Einheiten)")
	minArea := flag.Float64("min-area", 0.6, "kleinere Inseln fallen weg (Flaeche in Einheiten², das groesste Teil bleibt immer)")
	flag.Parse()
	if err := run(*in, *out, *width, *tol, *minArea); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

// Code liefert den ISO-Code eines Gebiets ("" = keiner bzw. weglassen).
func Code(p map[string]any) string {
	str := func(k string) string { s, _ := p[k].(string); return s }
	for _, k := range []string{"ISO_A2_EH", "ISO_A2"} {
		if c := str(k); validCode(c) {
			return c
		}
	}
	return a3Codes[str("ADM0_A3")]
}

func validCode(c string) bool {
	return len(c) == 2 && c[0] >= 'A' && c[0] <= 'Z' && c[1] >= 'A' && c[1] <= 'Z'
}

// project: Natural-Earth-Projektion (Savric u. a. 2011), Laenge/Breite in Grad, Ergebnis ohne Massstab.
func project(lon, lat float64) pt {
	l, f := lon*math.Pi/180, lat*math.Pi/180
	f2 := f * f
	f4 := f2 * f2
	x := l * (0.8707 - 0.131979*f2 + f4*(-0.013791+f4*(0.003971*f2-0.001529*f4)))
	y := f * (1.007226 + f2*(0.015085+f4*(-0.044475+0.028874*f2-0.005916*f4)))
	return pt{x, y}
}

func rings(g feature) ([][][2]float64, error) {
	switch g.Geometry.Type {
	case "Polygon":
		var p [][][2]float64
		err := json.Unmarshal(g.Geometry.Coordinates, &p)
		return p, err
	case "MultiPolygon":
		var mp [][][][2]float64
		if err := json.Unmarshal(g.Geometry.Coordinates, &mp); err != nil {
			return nil, err
		}
		var out [][][2]float64
		for _, p := range mp {
			out = append(out, p...)
		}
		return out, nil
	}
	return nil, fmt.Errorf("geometry %q", g.Geometry.Type)
}

func run(in, out string, width, tol, minArea float64) error {
	raw, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var fc struct {
		Features []feature `json:"features"`
	}
	if err := json.Unmarshal(raw, &fc); err != nil {
		return err
	}
	type country struct {
		code  string
		rings [][]pt
	}
	by := map[string]*country{}
	minX, minY, maxX, maxY := math.Inf(1), math.Inf(1), math.Inf(-1), math.Inf(-1)
	for _, f := range fc.Features {
		cc := Code(f.Properties)
		if cc == "" {
			fmt.Fprintf(os.Stderr, "gen: ohne Code: %v\n", f.Properties["ADMIN"])
			continue
		}
		if skip[cc] {
			continue
		}
		rs, err := rings(f)
		if err != nil {
			return fmt.Errorf("%s: %w", cc, err)
		}
		c := by[cc]
		if c == nil {
			c = &country{code: cc}
			by[cc] = c
		}
		for _, r := range rs {
			var pr []pt
			for _, ll := range r {
				p := project(ll[0], ll[1])
				p.y = -p.y // SVG: y nach unten
				minX, maxX = math.Min(minX, p.x), math.Max(maxX, p.x)
				minY, maxY = math.Min(minY, p.y), math.Max(maxY, p.y)
				pr = append(pr, p)
			}
			c.rings = append(c.rings, pr)
		}
	}
	scale := width / (maxX - minX)
	height := math.Ceil((maxY - minY) * scale)
	codes := make([]string, 0, len(by))
	for cc := range by {
		codes = append(codes, cc)
	}
	sort.Strings(codes)
	var b strings.Builder
	b.WriteString("# Natural Earth 1:110m Admin-0 Countries (public domain, naturalearthdata.com), Projektion Natural Earth, erzeugt mit internal/honeypot/worldmap/gen\n")
	fmt.Fprintf(&b, "viewBox 0 0 %d %d\n", int(width), int(height))
	for _, cc := range codes {
		c := by[cc]
		type sring struct {
			pts  []pt
			area float64
		}
		var srs []sring
		for _, r := range c.rings {
			pts := make([]pt, len(r))
			for i, p := range r {
				pts[i] = pt{(p.x - minX) * scale, (p.y - minY) * scale}
			}
			s := roundPts(simplify(pts, tol))
			if len(s) < 3 {
				continue
			}
			srs = append(srs, sring{s, math.Abs(area(s))})
		}
		if len(srs) == 0 { // zu klein: das groesste Teil ungekuerzt (gerundet)
			var best []pt
			for _, r := range c.rings {
				pts := make([]pt, len(r))
				for i, p := range r {
					pts[i] = pt{(p.x - minX) * scale, (p.y - minY) * scale}
				}
				if s := roundPts(pts); len(s) > len(best) {
					best = s
				}
			}
			if len(best) < 3 {
				fmt.Fprintf(os.Stderr, "gen: %s zu klein, weggelassen\n", cc)
				continue
			}
			srs = append(srs, sring{best, math.Abs(area(best))})
		}
		sort.SliceStable(srs, func(i, j int) bool { return srs[i].area > srs[j].area })
		var path strings.Builder
		for i, r := range srs {
			if i > 0 && r.area < minArea {
				continue
			}
			writeRing(&path, r.pts)
		}
		b.WriteString(cc + " " + path.String() + "\n")
	}
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "gen: %d Laender, %d Bytes, viewBox 0 0 %d %d\n", len(codes), b.Len(), int(width), int(height))
	return nil
}

// roundPts rundet auf ganze Zahlen und laesst doppelte Punkte (auch den schliessenden) weg.
func roundPts(in []pt) []pt {
	var out []pt
	for _, p := range in {
		q := pt{math.Round(p.x), math.Round(p.y)}
		if len(out) > 0 && out[len(out)-1] == q {
			continue
		}
		out = append(out, q)
	}
	for len(out) > 1 && out[len(out)-1] == out[0] {
		out = out[:len(out)-1]
	}
	return out
}

func area(p []pt) float64 {
	var a float64
	for i := range p {
		j := (i + 1) % len(p)
		a += p[i].x*p[j].y - p[j].x*p[i].y
	}
	return a / 2
}

// simplify: Douglas-Peucker fuer einen geschlossenen Ring (erster und weitester Punkt bleiben).
func simplify(p []pt, tol float64) []pt {
	if len(p) < 4 {
		return p
	}
	far, fd := 0, -1.0
	for i, q := range p {
		if d := math.Hypot(q.x-p[0].x, q.y-p[0].y); d > fd {
			far, fd = i, d
		}
	}
	a := dp(p[:far+1], tol)
	b := dp(append(append([]pt{}, p[far:]...), p[0]), tol)
	return append(a[:len(a)-1], b[:len(b)-1]...)
}

func dp(p []pt, tol float64) []pt {
	if len(p) < 3 {
		return p
	}
	a, b := p[0], p[len(p)-1]
	idx, maxD := 0, 0.0
	for i := 1; i < len(p)-1; i++ {
		if d := segDist(p[i], a, b); d > maxD {
			idx, maxD = i, d
		}
	}
	if maxD <= tol {
		return []pt{a, b}
	}
	l := dp(p[:idx+1], tol)
	r := dp(p[idx:], tol)
	return append(l[:len(l)-1], r...)
}

func segDist(p, a, b pt) float64 {
	dx, dy := b.x-a.x, b.y-a.y
	if dx == 0 && dy == 0 {
		return math.Hypot(p.x-a.x, p.y-a.y)
	}
	t := ((p.x-a.x)*dx + (p.y-a.y)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(p.x-(a.x+t*dx), p.y-(a.y+t*dy))
}

// writeRing schreibt "M x y l dx dy dx dy …z" kompakt (Vorzeichen trennt Zahlen, sonst Leerzeichen).
func writeRing(w *strings.Builder, p []pt) {
	num := func(v float64, first bool) {
		s := strconv.Itoa(int(v))
		if !first && !strings.HasPrefix(s, "-") {
			w.WriteByte(' ')
		}
		w.WriteString(s)
	}
	w.WriteByte('M')
	num(p[0].x, true)
	num(p[0].y, false)
	w.WriteByte('l')
	for i := 1; i < len(p); i++ {
		num(p[i].x-p[i-1].x, i == 1)
		num(p[i].y-p[i-1].y, false)
	}
	w.WriteByte('z')
}
