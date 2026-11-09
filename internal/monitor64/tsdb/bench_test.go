package tsdb

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Schreib-Benchmark: je Durchlauf eine simulierte Stunde mit einem Punkt je Reihe und Minute,
// Sicherung alle 5 simulierten Minuten. Aufruf (3 Stunden):
//
//	go test ./internal/monitor64/tsdb/ -run XXX -bench Write -benchtime 3x
//
// Werte je Reihe gemischt: 30 % ganze Zahlen (Temperatur), 40 % Prozent mit 2 Stellen (CPU, Zufallsweg),
// 20 % Mbit/s mit 3 Stellen (verrauscht), 10 % konstant (Status). Zeitstempel mit festem Versatz je Reihe,
// jeder 20. Punkt eine Sekunde spaet.
//
// Messwerte (2026-11-09, -benchtime 3x = 3 simulierte Stunden). raw-B/pt = Rohblock-Daten je Punkt;
// B/pt = ganze Datei (Rohbloecke, 5-min- und Stundenbloecke, Indizes, Seitenreste) / Rohpunkte – nach
// nur 3 Stunden von den erst angefangenen Verdichtungsbloecken dominiert, daher hoeher als im Dauerbetrieb.
// pt/s = Append samt Flush (inkl. Stundenabschluss); flush-max = laengste einzelne Sicherung (Stundenwechsel,
// Append und Abfragen laufen waehrenddessen weiter).
//
//	Windows 11, Ryzen 9 9900X:
//	  3.000 Reihen:  raw-B/pt 1.62, B/pt 5.05, 564.000 pt/s, flush-max  102 ms, Heap  5 MB
//	 30.000 Reihen:  raw-B/pt 1.62, B/pt 4.99, 436.000 pt/s, flush-max 1365 ms, Heap 30 MB
//	Linux agentbox (QEMU-VM, golang:1.27 in Docker):
//	  3.000 Reihen:  raw-B/pt 1.62, B/pt 5.04, 304.000 pt/s, flush-max  279 ms, Heap  5 MB
//	 30.000 Reihen:  raw-B/pt 1.62, B/pt 5.00, 256.000 pt/s, flush-max 3165 ms, Heap 28 MB
//
// Dauerbetrieb (BenchmarkSizeSteady, volle Bloecke): roh 1.47 B/pt, 5-min-Wert 3.6 B, Stundenwert 4.1 B
// (je Min/Mittel/Max/Anzahl) -> ca. 73 KB je Reihe bzw. 2.1 MB je Host mit 30 Messgroessen bei
// Standard-Aufbewahrung (Plan-Schaetzung: 5 MB). Abfrage 24 h (288 Punkte): ca. 60-100 us.
//
// Bedarf im Betrieb: 30.000 Reihen mit einem Punkt je Minute sind 500 Punkte/s (Reserve > 500fach).

func BenchmarkWrite3000(b *testing.B)  { benchWrite(b, 3000) }
func BenchmarkWrite30000(b *testing.B) { benchWrite(b, 30000) }

func benchWrite(b *testing.B, nSeries int) {
	c := &clock{t: base}
	db := openTest(b, filepath.Join(b.TempDir(), "m.db"), c, DefaultOptions())
	defer db.Close()
	ctx := context.Background()
	rng := rand.New(rand.NewPCG(7, 9))
	keys := make([]string, nSeries)
	offset := make([]time.Duration, nSeries)
	for i := range keys {
		keys[i] = fmt.Sprintf("host-%05d|svc%02d|in", i/30, i%30)
		offset[i] = time.Duration(i*7%60) * time.Second
	}
	value := newGen(rng, nSeries)

	var points int64
	var maxFlush time.Duration
	hours := 0
	for b.Loop() {
		h := base.Add(time.Duration(hours) * time.Hour)
		for m := 0; m < 60; m++ {
			minute := h.Add(time.Duration(m) * time.Minute)
			c.Set(minute.Add(59 * time.Second))
			for i, k := range keys {
				ts := minute.Add(offset[i])
				if rng.IntN(20) == 0 {
					ts = ts.Add(time.Second)
				}
				db.Append(k, ts, value(i))
			}
			points += int64(nSeries)
			if (m+1)%5 == 0 {
				if err := db.Flush(ctx); err != nil {
					b.Fatal(err)
				}
				maxFlush = max(maxFlush, db.Stats().FlushDuration)
			}
		}
		hours++
	}
	elapsed := b.Elapsed()
	b.StopTimer()

	// letzte Stunde abschliessen und messen
	c.Set(base.Add(time.Duration(hours)*time.Hour + 5*time.Minute))
	if err := db.Flush(ctx); err != nil {
		b.Fatal(err)
	}
	if _, err := db.sql.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		b.Fatal(err)
	}
	var rawBytes int64
	db.sql.QueryRow(`SELECT coalesce(sum(length(data)), 0) FROM blk_raw`).Scan(&rawBytes)
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	b.ReportMetric(float64(db.Size())/float64(points), "B/pt")
	b.ReportMetric(float64(rawBytes)/float64(points), "raw-B/pt")
	b.ReportMetric(float64(points)/elapsed.Seconds(), "pt/s")
	b.ReportMetric(float64(ms.HeapInuse)/(1<<20), "heap-MB")
	b.ReportMetric(float64(maxFlush.Milliseconds()), "flush-max-ms")
}

// newGen liefert gemischte Messwerte je Reihe (siehe oben).
func newGen(rng *rand.Rand, n int) func(i int) float64 {
	state := make([]float64, n)
	for i := range state {
		state[i] = 20 + rng.Float64()*20
	}
	return func(i int) float64 {
		switch k := i % 10; {
		case k < 3:
			if rng.IntN(10) == 0 {
				state[i] += float64(rng.IntN(3) - 1)
			}
			return math.Round(state[i])
		case k < 7:
			state[i] = math.Max(0, math.Min(100, state[i]+rng.NormFloat64()))
			return math.Round(state[i]*100) / 100
		case k < 9:
			return state[i] * (0.8 + 0.4*rng.Float64())
		default:
			return 1
		}
	}
}

// BenchmarkSizeSteady schaetzt den Platz je Reihe bei Standard-Aufbewahrung (roh 48 h, 5 min 30 Tage,
// 1 h 1 Jahr) aus vollen Bloecken: 100 Reihen, 30 Tage mit einem Punkt je Minute, ohne Datenbank.
// Zeilen-Overhead von SQLite (Schluessel, Indizes, Seitenreste) grob mit 40 Byte je Block angesetzt.
func BenchmarkSizeSteady(b *testing.B) {
	const nSeries, days = 100, 30
	var rawB, m5B, h1B, rawN, m5N, h1N int64
	for b.Loop() {
		value := newGen(rand.New(rand.NewPCG(3, 4)), nSeries)
		rawB, m5B, h1B, rawN, m5N, h1N = 0, 0, 0, 0, 0, 0
		for i := 0; i < nSeries; i++ {
			var month []aggPt
			for d := 0; d < days; d++ {
				var day []aggPt
				for h := 0; h < 24; h++ {
					start := base.Unix() + int64(d*86400+h*hour)
					ts := make([]int64, 60)
					vs := make([]float64, 60)
					for m := range ts {
						ts[m] = start + int64(m*60+i*7%60)
						vs[m] = value(i)
					}
					sb := makeSealed(start, ts, vs, defaultDigits)
					rawB += int64(len(sb.data))
					rawN++
					day = append(day, sb.agg5...)
					month = append(month, sb.agg1h...)
				}
				m5B += int64(len(encodeAgg(day, defaultDigits)))
				m5N++
			}
			h1B += int64(len(encodeAgg(month, defaultDigits)))
			h1N++
		}
	}
	const rowOverhead = 40
	perRaw := float64(rawB)/float64(rawN) + rowOverhead
	per5m := float64(m5B)/float64(m5N) + rowOverhead
	per1h := float64(h1B)/float64(h1N) + rowOverhead
	perSeries := 48*perRaw + 30*per5m + 365.0/30*per1h
	b.ReportMetric(float64(rawB)/float64(rawN*60), "raw-B/pt")
	b.ReportMetric(float64(m5B)/float64(m5N*288), "5m-B/pt")
	b.ReportMetric(float64(h1B)/float64(h1N*24*days), "1h-B/pt")
	b.ReportMetric(perSeries/1024, "KB/series")
	b.ReportMetric(30*perSeries/(1<<20), "MB/host30")
}

// BenchmarkQuery misst eine 24-h-Abfrage (5-Minuten-Werte, 288 Punkte) aus der Datenbank.
func BenchmarkQuery(b *testing.B) {
	c := &clock{t: base}
	db := openTest(b, filepath.Join(b.TempDir(), "m.db"), c, DefaultOptions())
	defer db.Close()
	ctx := context.Background()
	fill(db, c, "k", base, base.Add(25*time.Hour), time.Minute, func(i int) float64 { return float64(i%97) / 10 })
	if err := db.Flush(ctx); err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if _, err := db.Query(ctx, "k", base, base.Add(24*time.Hour), 0); err != nil {
			b.Fatal(err)
		}
	}
}
