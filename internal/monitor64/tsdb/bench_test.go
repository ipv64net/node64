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
//	  3.000 Reihen:  raw-B/pt 1.62, B/pt 5.07, 533.000 pt/s, flush-max   98 ms, Heap  5 MB
//	 30.000 Reihen:  raw-B/pt 1.62, B/pt 5.01, 454.000 pt/s, flush-max 1346 ms, Heap 32 MB
//	Linux agentbox (QEMU-VM, golang:1.27 in Docker):
//	  3.000 Reihen:  raw-B/pt 1.62, B/pt 5.07, 243.000 pt/s, flush-max  315 ms, Heap  6 MB
//	 30.000 Reihen:  raw-B/pt 1.62, B/pt 5.02, 259.000 pt/s, flush-max 2399 ms, Heap 32 MB
//
// Dauerbetrieb (BenchmarkSizeSteady, volle Bloecke, Stundenbloecke je 7 Tage): roh 1.47 B/pt, 5-min-Wert
// 3.6 B, Stundenwert 4.5 B (je Min/Mittel/Max/Anzahl) -> ca. 78 KB je Reihe bzw. 2.3 MB je Host mit 30
// Messgroessen bei Standard-Aufbewahrung (Plan-Schaetzung: 5 MB). Abfrage 24 h (288 Punkte): ca. 60-110 us.
// Zum Vergleich Stundenbloecke je 30 Tage (bis Dateiversion 0): 4.1 B, 73 KB; je 1 Tag: 6.1 B, 104 KB.
//
// Stundenabschluss mit vollen Verdichtungsbloecken (BenchmarkFlushFull, 3.000 Reihen, eine Sicherung):
//
//	Stundenbloecke je   Windows      agentbox     geschriebene Blockdaten je Reihe
//	30 Tage (alt)       880-955 ms   1858 ms      3.9 KB
//	 7 Tage (aktuell)   630-700 ms   1596 ms      1.9 KB
//	 1 Tag              440-470 ms   -            1.3 KB (Datei aber +33 %)
//
// Kleine Werte (Fehlerraten, Betrag < 1) behalten bis 4 signifikante Stellen (hoechstens 6 Nachkommastellen);
// TestCodecSize: Fehlerrate (meist 0, 4 Stellen) 1.25 B/pt, kleine Rate mit 6 Stellen 2.42 B/pt. Die
// gemischten Werte oben (alle Betraege >= 1) sind davon nicht betroffen.
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
// 1 h 1 Jahr) aus vollen Bloecken: 100 Reihen, 28 Tage (4 volle Stundenbloecke) mit einem Punkt je Minute,
// ohne Datenbank. Zeilen-Overhead von SQLite (Schluessel, Indizes, Seitenreste) grob mit 40 Byte je Block.
func BenchmarkSizeSteady(b *testing.B) {
	const nSeries, days = 100, 28
	blockDays := int(levels[2].span / 86400)
	var rawB, m5B, h1B, rawN, m5N, h1N int64
	for b.Loop() {
		value := newGen(rand.New(rand.NewPCG(3, 4)), nSeries)
		rawB, m5B, h1B, rawN, m5N, h1N = 0, 0, 0, 0, 0, 0
		for i := 0; i < nSeries; i++ {
			var week []aggPt
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
					week = append(week, sb.agg1h...)
				}
				m5B += int64(len(encodeAgg(day, defaultDigits)))
				m5N++
				if (d+1)%blockDays == 0 {
					h1B += int64(len(encodeAgg(week, defaultDigits)))
					h1N++
					week = week[:0]
				}
			}
		}
	}
	const rowOverhead = 40
	perRaw := float64(rawB)/float64(rawN) + rowOverhead
	per5m := float64(m5B)/float64(m5N) + rowOverhead
	per1h := float64(h1B)/float64(h1N) + rowOverhead
	perSeries := 48*perRaw + 30*per5m + 365.0/float64(blockDays)*per1h
	b.ReportMetric(float64(rawB)/float64(rawN*60), "raw-B/pt")
	b.ReportMetric(float64(m5B)/float64(m5N*288), "5m-B/pt")
	b.ReportMetric(float64(h1B)/float64(h1N*24*int64(blockDays)), "1h-B/pt")
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

// BenchmarkFlushFull misst die Sicherung beim Stundenwechsel, wenn 5-Minuten- und Stundenblock fast voll
// sind (letzte Stunde des Blockzeitraums): je Reihe eine abgeschlossene Stunde (60 Rohpunkte) schreiben
// und beide Verdichtungsbloecke lesen, mischen und neu schreiben. ns/op = Dauer dieser einen Sicherung;
// write-KB/series = dabei neu geschriebene Blockdaten je Reihe (ohne SQLite-Seiten-Overhead).
func BenchmarkFlushFull(b *testing.B) {
	const nSeries = 3000
	span5, span1 := levels[1].span, levels[2].span
	start := (base.Unix()/span1+2)*span1 - hour // letzte Stunde eines Stundenblocks (und eines Tages)
	ctx := context.Background()
	var aggBytes, aggPts, written int64
	for b.Loop() {
		b.StopTimer()
		path := filepath.Join(b.TempDir(), "m.db")
		c := &clock{t: time.Unix(start, 0)}
		db := openTest(b, path, c, DefaultOptions())
		tx, err := db.sql.Begin()
		if err != nil {
			b.Fatal(err)
		}
		aggBytes, aggPts = 0, 0
		for i := 0; i < nSeries; i++ {
			id := int64(i + 1)
			if _, err := tx.Exec(`INSERT INTO series(id, key, sealed) VALUES(?, ?, ?)`, id, fmt.Sprintf("h%05d|v", i), start); err != nil {
				b.Fatal(err)
			}
			for lv, span := range map[int]int64{1: span5, 2: span1} {
				step := levels[lv].step
				rng := rand.New(rand.NewPCG(uint64(i), uint64(lv)))
				var pts []aggPt
				for t := start - start%span; t < start; t += step {
					v := math.Round((20+rng.Float64()*10)*100) / 100
					pts = append(pts, aggPt{t: t, min: v - 1, avg: v + rng.Float64(), max: v + 2, n: float64(step / 60)})
				}
				data := encodeAgg(pts, defaultDigits)
				aggBytes += int64(len(data))
				aggPts += int64(len(pts))
				if _, err := tx.Exec(`INSERT INTO `+levels[lv].table+`(sid, start, n, data) VALUES(?, ?, ?, ?)`, id, start-start%span, len(pts), data); err != nil {
					b.Fatal(err)
				}
			}
		}
		if err := tx.Commit(); err != nil {
			b.Fatal(err)
		}
		db.Close()
		db = openTest(b, path, c, DefaultOptions())
		for m := 0; m < 60; m++ {
			ts := time.Unix(start+int64(m*60), 0)
			c.Set(ts)
			for i := 0; i < nSeries; i++ {
				db.Append(fmt.Sprintf("h%05d|v", i), ts, float64(i%50)+float64(m)/4)
			}
		}
		c.Set(time.Unix(start+hour+sealGrace, 0))
		b.StartTimer()
		if err := db.Flush(ctx); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		if err := db.sql.QueryRow(`SELECT (SELECT sum(length(data)) FROM blk_raw) + (SELECT sum(length(data)) FROM blk_5m) + (SELECT sum(length(data)) FROM blk_1h)`).Scan(&written); err != nil {
			b.Fatal(err)
		}
		db.Close()
		b.StartTimer() // b.Loop verlangt laufende Uhr
	}
	b.ReportMetric(float64(aggBytes)/float64(aggPts), "agg-B/pt")
	b.ReportMetric(float64(written)/nSeries/1024, "write-KB/series")
}
