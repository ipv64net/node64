package worldmap

import (
	"math"
	"strconv"
	"sync"
)

// Mittelpunkte der Laender fuer die Live-Karte (Boegen von der Quelle zum Ziel): Schwerpunkt der groessten Flaeche
// eines Landes in Koordinaten der ViewBox (Festland statt Inseln und Ueberseegebiete). Die Pfade bestehen nur aus
// "M x y", relativen "l dx dy …" und "z".

var centroids = sync.OnceValue(func() map[string][2]float64 {
	out := map[string][2]float64{}
	for _, c := range Countries() {
		if x, y, ok := pathCentroid(c.Path); ok {
			out[c.Code] = [2]float64{x, y}
		}
	}
	return out
})

// Centroid liefert den Mittelpunkt eines Landes (ok = auf der Karte, als Flaeche oder als fester Punkt, points.go).
func Centroid(code string) (x, y float64, ok bool) {
	p, ok := centroids()[code]
	if !ok {
		p, ok = smallPoints()[code]
	}
	return p[0], p[1], ok
}

// pathCentroid: Schwerpunkt der flaechengroessten Teilflaeche eines Pfads.
func pathCentroid(path string) (float64, float64, bool) {
	var polys [][][2]float64
	var cur [][2]float64
	var x, y float64
	cmd := byte(0)
	var nums []float64
	flush := func() {
		if len(cur) >= 3 {
			polys = append(polys, cur)
		}
		cur = nil
	}
	apply := func() {
		switch cmd {
		case 'M':
			for i := 0; i+1 < len(nums); i += 2 {
				if i == 0 {
					flush()
				}
				x, y = nums[i], nums[i+1]
				cur = append(cur, [2]float64{x, y})
			}
		case 'l':
			for i := 0; i+1 < len(nums); i += 2 {
				x, y = x+nums[i], y+nums[i+1]
				cur = append(cur, [2]float64{x, y})
			}
		}
		nums = nums[:0]
	}
	for i := 0; i < len(path); {
		ch := path[i]
		switch {
		case ch == 'M' || ch == 'l' || ch == 'z':
			apply()
			if ch == 'z' {
				flush()
				cmd = 0
			} else {
				cmd = ch
			}
			i++
		case ch == '-' || (ch >= '0' && ch <= '9') || ch == '.':
			j := i + 1
			for j < len(path) && (path[j] >= '0' && path[j] <= '9' || path[j] == '.') {
				j++
			}
			if v, err := strconv.ParseFloat(path[i:j], 64); err == nil {
				nums = append(nums, v)
			}
			i = j
		default:
			i++
		}
	}
	apply()
	flush()
	best, bestA := -1, 0.0
	for i, p := range polys {
		if a := math.Abs(area(p)); a > bestA {
			best, bestA = i, a
		}
	}
	if best < 0 {
		return 0, 0, false
	}
	return centroidOf(polys[best])
}

func area(p [][2]float64) float64 {
	s := 0.0
	for i := range p {
		j := (i + 1) % len(p)
		s += p[i][0]*p[j][1] - p[j][0]*p[i][1]
	}
	return s / 2
}

// centroidOf: Flaechenschwerpunkt (bei entarteter Flaeche der Mittelwert der Punkte).
func centroidOf(p [][2]float64) (float64, float64, bool) {
	a := area(p)
	if math.Abs(a) < 1e-9 {
		var sx, sy float64
		for _, q := range p {
			sx, sy = sx+q[0], sy+q[1]
		}
		return sx / float64(len(p)), sy / float64(len(p)), true
	}
	var cx, cy float64
	for i := range p {
		j := (i + 1) % len(p)
		f := p[i][0]*p[j][1] - p[j][0]*p[i][1]
		cx += (p[i][0] + p[j][0]) * f
		cy += (p[i][1] + p[j][1]) * f
	}
	return cx / (6 * a), cy / (6 * a), true
}
