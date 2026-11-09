package tsdb

import (
	"context"
	"errors"
	"math"
	"slices"
	"time"
)

// Point ist ein Diagrammpunkt. T ist der Zeitstempel (Unix-Sekunden) bzw. der Beginn des Zeitfensters.
// S ist die Breite dieses Punkts in Sekunden (0 = einzelner Rohwert). Sie kann groesser als Series.Step
// sein, wenn groebere Daten eine Luecke fuellen (z. B. Stundenwerte vor 5-Minuten-Werten).
type Point struct {
	T   int64   `json:"t"`
	Min float64 `json:"min"`
	Avg float64 `json:"avg"`
	Max float64 `json:"max"`
	S   int64   `json:"s,omitempty"`
}

// Series ist das Ergebnis einer Abfrage. Reine Werte ohne Datenbank-Bezug, damit spaeter auch eine
// andere Node im Cluster antworten kann.
//
// Luecken erkennen: zwischen zwei Punkten fehlen Daten erst, wenn ihr Abstand groesser ist als ein Vielfaches
// von max(Step, S des vorigen Punkts, S des Punkts) – nicht von Step allein, denn bei gemischter Aufloesung
// liegen aufgefuellte groebere Punkte weiter auseinander.
type Series struct {
	Key    string  `json:"key"`
	Res    string  `json:"res"`  // gewaehlte Hauptaufloesung: raw, 5m, 1h ("" ohne Daten)
	Step   int64   `json:"step"` // Breite der Punkte der Hauptaufloesung bzw. Verdichtung (0 = einzelne Rohwerte)
	Points []Point `json:"points"`
}

var errRange = errors.New("tsdb: Zeitraum ungueltig")

// Query liefert eine Reihe im Zeitraum [from, to] mit hoechstens maxPoints Punkten (0 = 700).
// Die Aufloesung richtet sich nach dem Zeitraum (bis 6 h roh, bis 30 Tage 5 min, darueber Stunde);
// fehlt sie fuer einen Teil des Zeitraums, fuellt die naechst groebere (aeltere Daten) bzw. feinere
// (juengste, noch nicht verdichtete Daten) Aufloesung die Luecke.
func (db *DB) Query(ctx context.Context, key string, from, to time.Time, maxPoints int) (Series, error) {
	res, err := db.QueryMulti(ctx, []string{key}, from, to, maxPoints)
	if err != nil {
		return Series{Key: key}, err
	}
	return res[0], nil
}

// QueryMulti fragt mehrere Reihen fuer denselben Zeitraum ab (Diagramme mit mehreren Linien).
// Unbekannte Reihen liefern ein leeres Ergebnis.
func (db *DB) QueryMulti(ctx context.Context, keys []string, from, to time.Time, maxPoints int) ([]Series, error) {
	if db.closed.Load() {
		return nil, ErrClosed
	}
	f, t := from.Unix(), to.Unix()
	if t < f {
		return nil, errRange
	}
	if maxPoints <= 0 {
		maxPoints = defaultMaxPoints
	}
	lv := 0
	switch span := t - f; {
	case span > 30*86400:
		lv = 2
	case span > 6*hour:
		lv = 1
	}
	out := make([]Series, len(keys))
	for i, key := range keys {
		out[i] = Series{Key: key, Points: []Point{}}
		s := db.lookup(key)
		if s == nil {
			continue
		}
		pts, used, err := db.collect(ctx, s, lv, f, t)
		if err != nil {
			return nil, err
		}
		if len(pts) == 0 {
			continue
		}
		out[i].Res = levels[used].name
		out[i].Step = levels[used].step
		if len(pts) > maxPoints {
			pts, out[i].Step = downsample(pts, f, t, maxPoints)
		}
		out[i].Points = make([]Point, len(pts))
		for k, p := range pts {
			out[i].Points[k] = Point{T: p.t, Min: p.min, Avg: p.avg, Max: p.max, S: p.w}
		}
	}
	return out, nil
}

// collect holt die Punkte der gewuenschten Aufloesung und fuellt Luecken am Rand aus den Nachbarn.
func (db *DB) collect(ctx context.Context, s *series, lv int, from, to int64) ([]aggPt, int, error) {
	pts, err := db.fetch(ctx, s, lv, from, to)
	if err != nil {
		return nil, lv, err
	}
	if len(pts) == 0 {
		// nichts in dieser Aufloesung: erst groeber (aeltere Daten), dann feiner (juengste Daten)
		for _, l := range []int{lv + 1, lv + 2, lv - 1, lv - 2} {
			if l < 0 || l >= len(levels) {
				continue
			}
			if pts, err = db.fetch(ctx, s, l, from, to); err != nil {
				return nil, lv, err
			}
			if len(pts) > 0 {
				lv = l
				break
			}
		}
		if len(pts) == 0 {
			return nil, lv, nil
		}
	}
	older, err := db.coarser(ctx, s, lv+1, from, pts[0].t-1)
	if err != nil {
		return nil, lv, err
	}
	newer, err := db.finer(ctx, s, lv-1, pts[len(pts)-1].t+max(levels[lv].step, 1), to)
	if err != nil {
		return nil, lv, err
	}
	if len(older) > 0 || len(newer) > 0 {
		pts = slices.Concat(older, pts, newer)
	}
	return pts, lv, nil
}

// coarser liefert aeltere Punkte aus groeberen Aufloesungen fuer [from, to].
func (db *DB) coarser(ctx context.Context, s *series, lv int, from, to int64) ([]aggPt, error) {
	if lv >= len(levels) || to-from < levels[lv].step {
		return nil, nil
	}
	pts, err := db.fetch(ctx, s, lv, from, to)
	if err != nil {
		return nil, err
	}
	// Punkte, die ueber to hinausreichen, gehoeren schon der feineren Aufloesung
	for len(pts) > 0 && pts[len(pts)-1].t+levels[lv].step > to+1 {
		pts = pts[:len(pts)-1]
	}
	end := to
	if len(pts) > 0 {
		end = pts[0].t - 1
	}
	older, err := db.coarser(ctx, s, lv+1, from, end)
	if err != nil {
		return nil, err
	}
	return slices.Concat(older, pts), nil
}

// finer liefert juengere Punkte aus feineren Aufloesungen fuer [from, to].
func (db *DB) finer(ctx context.Context, s *series, lv int, from, to int64) ([]aggPt, error) {
	if lv < 0 || to < from {
		return nil, nil
	}
	pts, err := db.fetch(ctx, s, lv, from, to)
	if err != nil {
		return nil, err
	}
	start := from
	if len(pts) > 0 {
		start = pts[len(pts)-1].t + max(levels[lv].step, 1)
	}
	newer, err := db.finer(ctx, s, lv-1, start, to)
	if err != nil {
		return nil, err
	}
	return slices.Concat(pts, newer), nil
}

// fetch liest eine Aufloesung im Zeitraum; Rohwerte aus dem Speicher gehen der Datenbank vor.
func (db *DB) fetch(ctx context.Context, s *series, lv int, from, to int64) ([]aggPt, error) {
	L := levels[lv]
	s.mu.Lock()
	id := s.id
	var mem map[int64][]aggPt
	var sealed []sealedBlock
	if lv == 0 {
		mem = map[int64][]aggPt{}
		if len(s.off) > 0 && s.start > from-hour && s.start <= to {
			pts := make([]aggPt, len(s.off))
			for i, o := range s.off {
				v := s.val[i]
				pts[i] = aggPt{t: s.start + int64(o), min: v, avg: v, max: v, n: 1}
			}
			mem[s.start] = pts
		}
		for _, b := range s.sealed {
			if b.start > from-hour && b.start <= to {
				sealed = append(sealed, b)
			}
		}
	}
	s.mu.Unlock()
	// abgeschlossene, noch nicht geschriebene Stunden ausserhalb der Sperre dekodieren
	for _, b := range sealed {
		ts, vs, err := decodeRaw(b.data)
		if err != nil {
			return nil, err
		}
		mem[b.start] = rawPts(ts, vs)
	}

	blocks := map[int64][]aggPt{}
	if id != 0 {
		rows, err := db.sql.QueryContext(ctx, `SELECT start, data FROM `+L.table+` WHERE sid = ? AND start > ? AND start <= ?`, id, from-L.span, to)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var start int64
			var data []byte
			if err := rows.Scan(&start, &data); err != nil {
				rows.Close()
				return nil, err
			}
			if _, ok := mem[start]; ok {
				continue
			}
			var pts []aggPt
			if lv == 0 {
				ts, vs, derr := decodeRaw(data)
				if derr != nil {
					continue
				}
				pts = rawPts(ts, vs)
			} else if pts, err = decodeAgg(data); err != nil {
				continue
			}
			blocks[start] = pts
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	for k, v := range mem {
		blocks[k] = v
	}
	starts := make([]int64, 0, len(blocks))
	for k := range blocks {
		starts = append(starts, k)
	}
	slices.Sort(starts)
	var out []aggPt
	for _, k := range starts {
		for _, p := range blocks[k] {
			// verdichtete Punkte zaehlen, wenn ihr Fenster in den Zeitraum ragt
			if p.t+max(L.step, 1) > from && p.t <= to && finite(p.avg) {
				p.w = L.step
				out = append(out, p)
			}
		}
	}
	return out, nil
}

func rawPts(ts []int64, vs []float64) []aggPt {
	pts := make([]aggPt, len(ts))
	for i, t := range ts {
		v := vs[i]
		pts[i] = aggPt{t: t, min: v, avg: v, max: v, n: 1}
	}
	return pts
}

// niceSteps sind die Fensterbreiten fuer verdichtete Diagramme.
var niceSteps = []int64{60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 2 * 86400, 7 * 86400}

func niceStep(min int64) int64 {
	for _, s := range niceSteps {
		if s >= min {
			return s
		}
	}
	w := int64(7 * 86400)
	return (min + w - 1) / w * w
}

// downsample fasst Punkte in Fenster zusammen (Min der Min, Max der Max, Mittel nach Anzahl gewichtet).
// Die Fenster beginnen bei from (nicht an der Epoche), damit [from, to] genau ceil((to-from)/step) <=
// maxPoints Fenster ergibt; Punkte vor from (ueberlappende Zeitfenster) zaehlen zum ersten, ein Punkt
// genau bei to zum letzten Fenster. Die Breite eines Ergebnispunkts ist mindestens step, bei groeberen
// Quellpunkten deren Breite.
func downsample(pts []aggPt, from, to int64, maxPoints int) ([]aggPt, int64) {
	span := max(to-from, 1)
	step := niceStep((span + int64(maxPoints) - 1) / int64(maxPoints))
	last := (span+step-1)/step - 1 // Index des letzten Fensters
	out := make([]aggPt, 0, min(int(last)+1, len(pts)))
	for _, p := range pts {
		k := min(max((p.t-from)/step, 0), last)
		b := from + k*step
		if len(out) == 0 || out[len(out)-1].t != b {
			out = append(out, aggPt{t: b, min: p.min, avg: p.avg * p.n, max: p.max, n: p.n, w: max(step, p.w)})
			continue
		}
		q := &out[len(out)-1]
		q.min = math.Min(q.min, p.min)
		q.max = math.Max(q.max, p.max)
		q.avg += p.avg * p.n
		q.n += p.n
		q.w = max(q.w, p.w)
	}
	for i := range out {
		if out[i].n > 0 {
			out[i].avg /= out[i].n
		}
	}
	return out, step
}
