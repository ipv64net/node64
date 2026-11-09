package eval

import (
	"math"
	"testing"
	"time"
)

// series erzeugt stuendliche Punkte ueber hours Stunden bis now mit Startwert v0 und Steigung je Tag.
func series(now time.Time, hours int, v0, perDay float64) []Point {
	var ps []Point
	for h := hours; h >= 0; h-- {
		at := now.Add(-time.Duration(h) * time.Hour)
		ps = append(ps, Point{At: at, V: v0 + perDay*float64(hours-h)/24})
	}
	return ps
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func TestTrend(t *testing.T) {
	now := t0
	t.Run("zu wenig Daten", func(t *testing.T) {
		r := Trend(series(now, 23, 50, 10), now, 100)
		if r.Enough || r.Value() != NoForecast {
			t.Fatalf("%+v", r)
		}
		if r := Trend(nil, now, 100); r.Enough {
			t.Fatal("leer")
		}
	})
	t.Run("genau 24 h", func(t *testing.T) {
		r := Trend(series(now, 24, 50, 10), now, 100)
		if !r.Enough || !r.Full || !near(r.Slope, 10) || !near(r.Days, 4) {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("7 Tage, 1 %/Tag", func(t *testing.T) {
		r := Trend(series(now, 7*24, 50, 1), now, 100)
		if !near(r.Days, 43) || !near(r.Value(), 43) {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("aeltere Punkte zaehlen nicht", func(t *testing.T) {
		ps := append([]Point{{At: now.Add(-30 * 24 * time.Hour), V: 0}}, series(now, 7*24, 50, 1)...)
		ps = append(ps, Point{At: now.Add(time.Hour), V: 1000}, Point{At: now.Add(-time.Hour), V: math.NaN()})
		r := Trend(ps, now, 100)
		if !near(r.Slope, 1) || !near(r.Days, 43) {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("faellt oder bleibt", func(t *testing.T) {
		if r := Trend(series(now, 48, 80, -1), now, 100); !r.Enough || r.Full || r.Value() != NoForecast {
			t.Fatalf("faellt: %+v", r)
		}
		if r := Trend(series(now, 48, 80, 0), now, 100); r.Full {
			t.Fatalf("flach: %+v", r)
		}
	})
	t.Run("freie Bytes gegen 0", func(t *testing.T) {
		r := Trend(series(now, 48, 1000*GB, -100*GB), now, 0)
		if !r.Full || !near(r.Days, 8) {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("schon voll", func(t *testing.T) {
		if r := Trend(series(now, 48, 98, 1), now, 100); !r.Full || r.Days != 0 {
			t.Fatalf("%+v", r)
		}
		if r := Trend(series(now, 48, 101, -1), now, 100); r.Full {
			t.Fatalf("faellt von oben: %+v", r)
		}
	})
	t.Run("unsortiert", func(t *testing.T) {
		ps := series(now, 72, 50, 2)
		for i, j := 0, len(ps)-1; i < j; i, j = i+1, j-1 {
			ps[i], ps[j] = ps[j], ps[i]
		}
		if r := Trend(ps, now, 100); !near(r.Days, 22) {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("Schwellen ueber Tracker", func(t *testing.T) {
		e := eff(KindFSTrendDays, nil)
		cases := []struct {
			perDay float64
			want   State
		}{{1, OK}, {10, Warn}, {20, Crit}} // letzter Wert 50 + 2*perDay
		for _, c := range cases {
			var tr Tracker
			r := Trend(series(now, 48, 50, c.perDay), now, 100)
			if st := tr.Observe(e, Sample{At: now, Value: r.Value()}); st.State != c.want {
				t.Errorf("%v/Tag (voll in %.1f Tagen): %v, erwartet %v", c.perDay, r.Days, st.State, c.want)
			}
		}
		var tr Tracker
		if st := tr.Observe(e, Sample{At: now, Value: NoForecast}); st.State != OK {
			t.Fatalf("ohne Vorhersage: %v", st.State)
		}
	})
}
