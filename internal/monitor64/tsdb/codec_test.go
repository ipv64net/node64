package tsdb

import (
	"encoding/binary"
	"math"
	"math/rand/v2"
	"testing"
)

func sameFloat(a, b float64) bool {
	return a == b || (math.IsNaN(a) && math.IsNaN(b))
}

func roundTrip(t *testing.T, ts []int64, cols [][]float64, digits int) ([]int64, [][]float64, int) {
	t.Helper()
	b := encodeBlock(ts, cols, digits)
	gt, gc, err := decodeBlock(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(gt) != len(ts) || len(gc) != len(cols) {
		t.Fatalf("laenge: %d/%d Punkte, %d/%d Spalten", len(gt), len(ts), len(gc), len(cols))
	}
	for i := range ts {
		if gt[i] != ts[i] {
			t.Fatalf("zeit %d: %d statt %d", i, gt[i], ts[i])
		}
	}
	return gt, gc, len(b)
}

func TestCodecExact(t *testing.T) {
	cases := map[string][]float64{
		"leer":       {},
		"eins":       {42},
		"ganz":       {1, 2, 3, 100, -5, 0, 0, 7},
		"dezimal":    {12.345, 12.3, 0.001, -0.5, 99.999, 1e6 + 0.125},
		"konstant":   {1, 1, 1, 1, 1, 1},
		"null":       {0, 0, 0},
		"sonder":     {math.NaN(), 1.5, math.Inf(1), 2.25, math.Inf(-1), math.NaN()},
		"nur NaN":    {math.NaN(), math.NaN()},
		"riesig":     {1e300, -1e300, 5e-324, 1.7976931348623157e308},
		"gross":      {1e15, 2.5e15, 9e15},
		"gross+NaN":  {1e20, math.NaN(), 3},
		"negativ":    {-1.001, -2.002, -1000000.5},
		"zehntel":    {0.1, 0.2, 0.30000000000000004},
		"millionen":  {123456789.123, 123456789.124},
		"min/max 64": {math.MaxInt32, math.MinInt32},
	}
	for name, vals := range cases {
		t.Run(name, func(t *testing.T) {
			ts := make([]int64, len(vals))
			for i := range ts {
				ts[i] = 1_700_000_000 + int64(i)*60
			}
			_, gc, _ := roundTrip(t, ts, [][]float64{vals}, 3)
			maxAbs := 0.0
			for _, v := range vals {
				if finite(v) {
					maxAbs = max(maxAbs, math.Abs(v))
				}
			}
			big := maxAbs*1000 > exactInt // weniger Nachkommastellen oder float-Bits
			for i, v := range vals {
				want := v
				if finite(v) && !big {
					want = math.Round(v*1000) / 1000
				}
				got := gc[0][i]
				if big && finite(v) {
					if math.Abs(got-v) > maxAbs*1e-15 {
						t.Errorf("wert %d: %v statt %v", i, got, v)
					}
					continue
				}
				if !sameFloat(got, want) {
					t.Errorf("wert %d: %v statt %v", i, got, want)
				}
			}
		})
	}
}

func TestCodecTimestamps(t *testing.T) {
	ts := []int64{-5, 0, 1, 1, 100, 99, math.MaxInt64, math.MinInt64, 0}
	vals := make([]float64, len(ts))
	roundTrip(t, ts, [][]float64{vals}, 3)
}

func TestCodecScale(t *testing.T) {
	for _, c := range []struct {
		vals []float64
		want int
	}{
		{[]float64{1, 2, 300}, 0},
		{[]float64{1.5, 2}, 1},
		{[]float64{1.25, 2.5}, 2},
		{[]float64{1.0004}, 0}, // auf 3 Stellen gerundet ganz
		{[]float64{0.001, 1e6}, 3},
		{[]float64{1e14}, 0},
		// kleine Spalten (Betrag < 1): 4 signifikante Stellen des groessten Betrags, hoechstens 6 Stellen
		{[]float64{0.0012, 0, 0.0003}, 4},
		{[]float64{0.123456}, 4},
		{[]float64{0.5, 0.25}, 2},
		{[]float64{0.0000004}, 0},   // unter 6 Stellen: 0
		{[]float64{2.5, 0.0003}, 1}, // groesster Betrag >= 1: wie bisher 3 Stellen
	} {
		_, s, ok := scaleColumn(c.vals, 3)
		if !ok || s != c.want {
			t.Errorf("%v: Stellen %d (ok %v), erwartet %d", c.vals, s, ok, c.want)
		}
	}
	if _, _, ok := scaleColumn([]float64{1e17}, 3); ok {
		t.Error("1e17 passt nicht exakt in eine Ganzzahl, erwartet float-Modus")
	}
}

// TestCodecSize prueft die Groesse typischer Stundenbloecke (60 Punkte, eine Minute Abstand).
func TestCodecSize(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	ts := make([]int64, 60)
	for i := range ts {
		ts[i] = 1_700_000_000 + int64(i)*60
	}
	gen := map[string]func(i int) float64{
		"konstant":  func(int) float64 { return 1 },
		"ganz":      func(i int) float64 { return float64(40 + rng.IntN(3)) },
		"cpu 2 st.": func(i int) float64 { return math.Round((20+rng.Float64()*5)*100) / 100 },
		"mbit 3 st": func(i int) float64 { return 50 + rng.Float64()*10 },
		"fehlerrate": func(i int) float64 { // meist 0, gelegentlich kleine Raten mit 4 Stellen
			if rng.IntN(4) > 0 {
				return 0
			}
			return math.Round(rng.Float64()*0.05*1e4) / 1e4
		},
		"rate klein": func(i int) float64 { return 0.01 + rng.Float64()*0.05 }, // volle 6 Stellen
	}
	for name, g := range gen {
		vals := make([]float64, len(ts))
		for i := range vals {
			vals[i] = g(i)
		}
		_, _, n := roundTrip(t, ts, [][]float64{vals}, 3)
		bpp := float64(n) / float64(len(ts))
		t.Logf("%-10s %4d Byte, %.2f Byte/Punkt", name, n, bpp)
		if bpp > 3.5 {
			t.Errorf("%s: %.2f Byte/Punkt, erwartet hoechstens 3,5", name, bpp)
		}
	}
}

func TestDecodeCorrupt(t *testing.T) {
	b := encodeBlock([]int64{1, 2, 3}, [][]float64{{1.5, math.NaN(), 3}}, 3)
	for i := 0; i < len(b); i++ {
		if _, _, err := decodeBlock(b[:i]); err == nil {
			t.Errorf("abgeschnitten bei %d: kein Fehler", i)
		}
	}
	if _, _, err := decodeBlock(append(b, 0)); err == nil {
		t.Error("Muell am Ende: kein Fehler")
	}
	for _, bad := range [][]byte{nil, {2, 0}, {1, 4}, {1, 1, 0xff, 0xff}} {
		if _, _, err := decodeBlock(bad); err == nil {
			t.Errorf("%x: kein Fehler", bad)
		}
	}
}

func FuzzDecodeBlock(f *testing.F) {
	f.Add(encodeBlock([]int64{1, 2, 3}, [][]float64{{1.5, math.NaN(), 3}}, 3))
	f.Add(encodeBlock([]int64{10, 70, 130, 191}, [][]float64{{1, 2, 3, 4}, {1e300, 0, -1, 5}, {0, 0, 0, 0}, {1, 1, 1, 1}}, 3))
	ts := make([]int64, 200)
	vs := make([]float64, 200)
	for i := range ts {
		ts[i], vs[i] = int64(i*60), float64(i%7)
	}
	f.Add(encodeBlock(ts, [][]float64{vs}, 3))
	f.Fuzz(func(t *testing.T, b []byte) {
		gt, gc, err := decodeBlock(b)
		if err != nil {
			return
		}
		for _, c := range gc {
			if len(c) != len(gt) {
				t.Fatalf("spalte mit %d statt %d Werten", len(c), len(gt))
			}
		}
		// was sich lesen laesst, muss sich wieder schreiben und lesen lassen
		roundTrip(t, gt, gc, maxDigits)
	})
}

// FuzzRoundTrip erzeugt Punkte aus den Eingabebytes (je 16 Byte: Zeitabstand, float64-Bits).
func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte{}, uint8(3))
	f.Add(binary.LittleEndian.AppendUint64(binary.LittleEndian.AppendUint64(nil, 60), math.Float64bits(1.25)), uint8(3))
	f.Add(binary.LittleEndian.AppendUint64(binary.LittleEndian.AppendUint64(nil, 1), math.Float64bits(math.NaN())), uint8(0))
	f.Fuzz(func(t *testing.T, b []byte, digits uint8) {
		d := int(digits % 7)
		var ts []int64
		var vs []float64
		var cur int64
		for len(b) >= 16 && len(ts) < 2000 {
			cur += int64(binary.LittleEndian.Uint64(b))
			ts = append(ts, cur)
			vs = append(vs, math.Float64frombits(binary.LittleEndian.Uint64(b[8:])))
			b = b[16:]
		}
		_, gc, _ := roundTrip(t, ts, [][]float64{vs, vs}, d)
		maxAbs := 0.0
		for _, v := range vs {
			if finite(v) {
				maxAbs = max(maxAbs, math.Abs(v))
			}
		}
		for i, v := range vs {
			got := gc[0][i]
			if !finite(v) || math.Round(maxAbs*pow10[d]) > exactInt {
				// Sonderwerte bleiben, sehr grosse Spalten werden hoechstens um 1 ULP-Bereich gerundet
				if !finite(v) && !sameFloat(got, v) {
					t.Fatalf("wert %d: %v statt %v", i, got, v)
				}
				if finite(v) && math.Abs(got-v) > maxAbs*1e-15+0.5 {
					t.Fatalf("wert %d: %v statt %v", i, got, v)
				}
				continue
			}
			if math.Abs(got-v) > 0.5/pow10[d]+math.Abs(v)*1e-15 {
				t.Fatalf("wert %d: %v statt %v (Stellen %d)", i, got, v, d)
			}
		}
	})
}
