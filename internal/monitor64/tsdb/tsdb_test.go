package tsdb

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

// base liegt auf einer Stunden- und Tagesgrenze.
var base = time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func openTest(t testing.TB, path string, c *clock, opts Options) *DB {
	t.Helper()
	opts.Now = c.Now
	if opts.FlushInterval == 0 {
		opts.FlushInterval = -1
	}
	db, err := Open(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// crash beendet die DB ohne abschliessende Sicherung (wie ein Absturz).
func crash(db *DB) {
	db.closed.Store(true)
	if db.stop != nil {
		close(db.stop)
		<-db.done
	}
	db.sql.Close()
}

// fill schreibt Punkte im Abstand step von from bis vor to; Wert = f(Index), Uhr laeuft mit.
func fill(db *DB, c *clock, key string, from, to time.Time, step time.Duration, f func(i int) float64) int {
	n := 0
	for ts := from; ts.Before(to); ts = ts.Add(step) {
		c.Set(ts)
		db.Append(key, ts, f(n))
		n++
	}
	return n
}

func query(t *testing.T, db *DB, key string, from, to time.Time, maxPoints int) Series {
	t.Helper()
	s, err := db.Query(context.Background(), key, from, to, maxPoints)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRawRoundTripAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "monitor64.db")
	c := &clock{t: base}
	db := openTest(t, path, c, DefaultOptions())
	val := func(i int) float64 { return float64(i) * 0.125 }
	n := fill(db, c, "h1|cpu", base, base.Add(3*time.Hour), time.Minute, val)

	check := func(db *DB, when string) {
		s := query(t, db, "h1|cpu", base, base.Add(3*time.Hour), 1000)
		if s.Res != "raw" || s.Step != 0 || len(s.Points) != n {
			t.Fatalf("%s: res %q step %d, %d Punkte statt %d", when, s.Res, s.Step, len(s.Points), n)
		}
		for i, p := range s.Points {
			if p.T != base.Unix()+int64(i)*60 || p.Avg != val(i) || p.Min != p.Avg || p.Max != p.Avg {
				t.Fatalf("%s: Punkt %d = %+v", when, i, p)
			}
		}
	}
	check(db, "Speicher")
	if err := db.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	check(db, "nach Flush")
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = openTest(t, path, c, DefaultOptions())
	defer db.Close()
	check(db, "nach Neustart")
	if st := db.Stats(); st.Series != 1 || st.Points != 60 {
		t.Errorf("Stats %+v: erwartet 1 Reihe und 60 Punkte der laufenden Stunde im Speicher", st)
	}
}

func TestAggregates(t *testing.T) {
	c := &clock{t: base}
	db := openTest(t, filepath.Join(t.TempDir(), "m.db"), c, DefaultOptions())
	defer db.Close()
	ctx := context.Background()
	fill(db, c, "k", base, base.Add(3*time.Hour), time.Minute, func(i int) float64 { return float64(i % 60) })
	// Stunde 3 laeuft noch (10 Punkte), Stunden 0..2 sind ueber die Gnadenfrist hinaus
	fill(db, c, "k", base.Add(3*time.Hour), base.Add(3*time.Hour+10*time.Minute), time.Minute, func(int) float64 { return 100 })
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	var n5, n1 int
	db.sql.QueryRow(`SELECT count(*) FROM blk_5m`).Scan(&n5)
	db.sql.QueryRow(`SELECT count(*) FROM blk_1h`).Scan(&n1)
	if n5 != 1 || n1 != 1 {
		t.Fatalf("Bloecke 5m %d, 1h %d, erwartet je 1", n5, n1)
	}

	s := query(t, db, "k", base, base.Add(7*24*time.Hour), 0)
	if s.Res != "5m" || s.Step != 300 {
		t.Fatalf("res %q step %d", s.Res, s.Step)
	}
	if len(s.Points) != 36+10 {
		t.Fatalf("%d Punkte, erwartet 36 Fuenf-Minuten-Werte und 10 Rohwerte", len(s.Points))
	}
	if p := s.Points[0]; p.T != base.Unix() || p.Min != 0 || p.Avg != 2 || p.Max != 4 {
		t.Errorf("erster 5-min-Wert %+v", p)
	}
	if p := s.Points[36]; p.T != base.Add(3*time.Hour).Unix() || p.Avg != 100 {
		t.Errorf("erster Rohwert nach den 5-min-Werten %+v", p)
	}

	s = query(t, db, "k", base, base.Add(60*24*time.Hour), 0)
	if s.Res != "1h" || len(s.Points) != 3+10 {
		t.Fatalf("res %q, %d Punkte", s.Res, len(s.Points))
	}
	for i := 0; i < 3; i++ {
		if p := s.Points[i]; p.Min != 0 || p.Max != 59 || p.Avg != 29.5 {
			t.Errorf("Stundenwert %d: %+v", i, p)
		}
	}

	// Verdichtung bei Bedarf: 46 Punkte auf hoechstens 10 (ein Tagesfenster)
	s = query(t, db, "k", base, base.Add(7*24*time.Hour), 10)
	if len(s.Points) > 10 || s.Points[0].Max != 100 || s.Points[0].Min != 0 {
		t.Errorf("verdichtet: %d Punkte, erster %+v, step %d", len(s.Points), s.Points[0], s.Step)
	}
}

func TestFallbackToCoarser(t *testing.T) {
	c := &clock{t: base}
	opts := DefaultOptions()
	opts.RetentionRaw = 2 * time.Hour
	db := openTest(t, filepath.Join(t.TempDir(), "m.db"), c, opts)
	defer db.Close()
	ctx := context.Background()
	fill(db, c, "k", base, base.Add(5*time.Hour), time.Minute, func(i int) float64 { return float64(i) })
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Purge(ctx, c.Now()); err != nil {
		t.Fatal(err)
	}
	var raw int
	db.sql.QueryRow(`SELECT count(*) FROM blk_raw`).Scan(&raw)
	if raw != 3 { // Stunden 2, 3 (fertig) und 4 (laufend)
		t.Fatalf("%d Rohbloecke nach Purge, erwartet 3", raw)
	}
	s := query(t, db, "k", base, base.Add(5*time.Hour), 1000)
	if s.Res != "raw" {
		t.Fatalf("res %q", s.Res)
	}
	// Stunden 0 und 1 aus 5-Minuten-Werten (24), danach 180 Rohwerte
	if len(s.Points) != 24+180 {
		t.Fatalf("%d Punkte, erwartet 204", len(s.Points))
	}
	if p := s.Points[23]; p.T != base.Add(115*time.Minute).Unix() || p.Avg != 117 {
		t.Errorf("letzter 5-min-Wert %+v", p)
	}
	if p := s.Points[24]; p.T != base.Add(2*time.Hour).Unix() || p.Avg != 120 {
		t.Errorf("erster Rohwert %+v", p)
	}
	for i := 1; i < len(s.Points); i++ {
		if s.Points[i].T <= s.Points[i-1].T {
			t.Fatalf("nicht aufsteigend bei %d", i)
		}
	}
}

func TestCrashRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	c := &clock{t: base}
	ctx := context.Background()
	db := openTest(t, path, c, DefaultOptions())
	fill(db, c, "k", base, base.Add(30*time.Minute), time.Minute, func(i int) float64 { return 1 })
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	fill(db, c, "k", base.Add(30*time.Minute), base.Add(40*time.Minute), time.Minute, func(i int) float64 { return 2 })
	crash(db) // die letzten 10 Punkte sind verloren

	db = openTest(t, path, c, DefaultOptions())
	if s := query(t, db, "k", base, base.Add(time.Hour), 0); len(s.Points) != 30 {
		t.Fatalf("nach Absturz %d Punkte, erwartet 30", len(s.Points))
	}
	fill(db, c, "k", base.Add(45*time.Minute), base.Add(50*time.Minute), time.Minute, func(i int) float64 { return 3 })
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	crash(db)

	// Neustart erst zwei Stunden spaeter: die offene Stunde wird beim naechsten Flush abgeschlossen
	c.Set(base.Add(2*time.Hour + 30*time.Minute))
	db = openTest(t, path, c, DefaultOptions())
	defer db.Close()
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	s := query(t, db, "k", base, base.Add(60*24*time.Hour), 0)
	if s.Res != "1h" || len(s.Points) != 1 || s.Points[0].Max != 3 || s.Points[0].Min != 1 {
		t.Fatalf("Stundenwert nach Absturz: %+v", s)
	}
	// verspaetete Punkte fuer die abgeschlossene Stunde werden verworfen, auch nach Neustart
	before := db.Stats().Dropped
	db.Append("k", base.Add(55*time.Minute), 9)
	if db.Stats().Dropped != before+1 {
		t.Error("Punkt fuer abgeschlossene Stunde nicht verworfen")
	}
}

func TestDrops(t *testing.T) {
	c := &clock{t: base.Add(30 * time.Minute)}
	db := openTest(t, filepath.Join(t.TempDir(), "m.db"), c, DefaultOptions())
	defer db.Close()
	ts := base.Add(10 * time.Minute)
	db.Append("k", ts, 1)
	db.Append("k", ts, 2)                   // gleicher Zeitstempel
	db.Append("k", ts.Add(-time.Minute), 3) // rueckwaerts
	db.Append("k", ts.Add(time.Minute), math.NaN())
	db.Append("k", ts.Add(time.Minute), math.Inf(1))
	db.Append("k", c.Now().Add(time.Hour), 4) // Zukunft
	db.Append("", ts.Add(time.Minute), 5)
	db.Append("k", ts.Add(2*time.Minute), 6)
	db.Append("k", ts.Add(2*time.Hour-30*time.Minute), 7) // naechste Stunde, schliesst die erste ab
	db.Append("k", ts.Add(5*time.Minute), 8)              // abgeschlossene Stunde
	st := db.Stats()
	if st.Dropped != 7 || st.Points != 3 {
		t.Fatalf("Stats %+v, erwartet 7 verworfen und 3 Punkte", st)
	}
	// je Grund: NaN, Inf, leerer Schluessel; Zukunft (+1 h, naechste Stunde); gleich, rueckwaerts
	if st.DroppedInvalid != 3 || st.DroppedFuture != 2 || st.DroppedLate != 2 || st.ClockResets != 0 {
		t.Fatalf("Stats %+v, erwartet je Grund 3 ungueltig, 2 Zukunft, 2 verspaetet", st)
	}
}

func TestDeleteSeriesPrefix(t *testing.T) {
	c := &clock{t: base}
	db := openTest(t, filepath.Join(t.TempDir(), "m.db"), c, DefaultOptions())
	defer db.Close()
	ctx := context.Background()
	for _, k := range []string{"h1|cpu", "h1|mem", "h10|cpu", "h2|cpu"} {
		fill(db, c, k, base, base.Add(90*time.Minute), time.Minute, func(i int) float64 { return 1 })
	}
	c.Set(base.Add(3 * time.Hour))
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	db.Append("h1|new", c.Now(), 1) // nur im Speicher
	n, err := db.DeleteSeriesPrefix(ctx, "h1|")
	if err != nil || n != 3 {
		t.Fatalf("geloescht %d (%v), erwartet 3", n, err)
	}
	for _, k := range []string{"h1|cpu", "h1|new"} {
		if s := query(t, db, k, base, base.Add(4*time.Hour), 0); len(s.Points) != 0 {
			t.Errorf("%s hat noch %d Punkte", k, len(s.Points))
		}
	}
	for _, k := range []string{"h10|cpu", "h2|cpu"} {
		if s := query(t, db, k, base, base.Add(4*time.Hour), 0); len(s.Points) != 90 {
			t.Errorf("%s: %d Punkte statt 90", k, len(s.Points))
		}
	}
	var rows int
	db.sql.QueryRow(`SELECT (SELECT count(*) FROM series) + (SELECT count(*) FROM blk_raw WHERE sid NOT IN (SELECT id FROM series))`).Scan(&rows)
	if rows != 2 {
		t.Errorf("%d Reihen/verwaiste Bloecke, erwartet 2 Reihen", rows)
	}
	if _, err := db.DeleteSeriesPrefix(ctx, ""); err == nil {
		t.Error("leeres Praefix ohne Fehler")
	}
	// neue Daten nach dem Loeschen ergeben eine neue Reihe
	db.Append("h1|cpu", c.Now(), 5)
	if s := query(t, db, "h1|cpu", base, base.Add(4*time.Hour), 0); len(s.Points) != 1 {
		t.Errorf("neue Reihe: %d Punkte", len(s.Points))
	}
}

func TestPurgeRetentionAndOrphans(t *testing.T) {
	c := &clock{t: base}
	opts := Options{RetentionRaw: 2 * time.Hour, Retention5m: 2 * 24 * time.Hour, Retention1h: 0} // 1h unbegrenzt
	db := openTest(t, filepath.Join(t.TempDir(), "m.db"), c, opts)
	defer db.Close()
	ctx := context.Background()
	fill(db, c, "alt", base, base.Add(2*time.Hour), time.Minute, func(i int) float64 { return float64(i) })
	c.Set(base.Add(3 * time.Hour))
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// 40 Tage spaeter: nur noch Stundenwerte (unbegrenzt)
	later := base.Add(40 * 24 * time.Hour)
	if _, err := db.Purge(ctx, later); err != nil {
		t.Fatal(err)
	}
	var raw, m5, h1 int
	db.sql.QueryRow(`SELECT (SELECT count(*) FROM blk_raw), (SELECT count(*) FROM blk_5m), (SELECT count(*) FROM blk_1h)`).Scan(&raw, &m5, &h1)
	if raw != 0 || m5 != 0 || h1 != 1 {
		t.Fatalf("raw %d, 5m %d, 1h %d", raw, m5, h1)
	}
	s := query(t, db, "alt", base, base.Add(3*time.Hour), 0)
	if s.Res != "1h" || len(s.Points) != 2 {
		t.Fatalf("nach Purge: res %q, %d Punkte (erwartet 2 Stundenwerte)", s.Res, len(s.Points))
	}

	// Aufbewahrung 1 Jahr: danach ist die Reihe ganz leer und wird entfernt
	db.opts.Retention1h = 365 * 24 * time.Hour
	if _, err := db.Purge(ctx, base.Add(400*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if st := db.Stats(); st.Series != 0 {
		t.Errorf("verwaiste Reihe nicht entfernt: %+v", st)
	}
	var free int
	db.sql.QueryRow(`PRAGMA freelist_count`).Scan(&free)
	if free != 0 {
		t.Errorf("freelist_count %d nach Purge", free)
	}
}

func TestAutoVacuumEnabled(t *testing.T) {
	db := openTest(t, filepath.Join(t.TempDir(), "m.db"), &clock{t: base}, DefaultOptions())
	defer db.Close()
	var av int
	if err := db.sql.QueryRow(`PRAGMA auto_vacuum`).Scan(&av); err != nil || av != 2 {
		t.Fatalf("auto_vacuum %d (%v), erwartet 2 (INCREMENTAL)", av, err)
	}
	if db.Size() <= 0 {
		t.Error("Size 0")
	}
}

func TestDownsampleRaw(t *testing.T) {
	c := &clock{t: base}
	db := openTest(t, filepath.Join(t.TempDir(), "m.db"), c, DefaultOptions())
	defer db.Close()
	fill(db, c, "k", base, base.Add(6*time.Hour), 10*time.Second, func(i int) float64 { return float64(i % 6) })
	res, err := db.QueryMulti(context.Background(), []string{"k", "fehlt"}, base, base.Add(6*time.Hour), 700)
	if err != nil {
		t.Fatal(err)
	}
	s := res[0]
	if len(s.Points) > 700 || s.Step != 60 || len(s.Points) != 360 {
		t.Fatalf("%d Punkte, step %d", len(s.Points), s.Step)
	}
	for _, p := range s.Points {
		if p.Min != 0 || p.Max != 5 || p.Avg != 2.5 {
			t.Fatalf("Punkt %+v", p)
		}
	}
	if res[1].Key != "fehlt" || len(res[1].Points) != 0 || res[1].Points == nil {
		t.Errorf("unbekannte Reihe: %+v", res[1])
	}
	if _, err := db.Query(context.Background(), "k", base.Add(time.Hour), base, 0); err == nil {
		t.Error("umgekehrter Zeitraum ohne Fehler")
	}
}

func TestConcurrent(t *testing.T) {
	c := &clock{t: base}
	db := openTest(t, filepath.Join(t.TempDir(), "m.db"), c, DefaultOptions())
	ctx := context.Background()
	var wg sync.WaitGroup
	const writers, keys, steps = 4, 50, 200
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < steps; i++ {
				ts := base.Add(time.Duration(i) * time.Minute)
				for k := w; k < keys; k += writers {
					db.Append(fmt.Sprintf("h%d|v", k), ts, float64(i))
				}
			}
		}(w)
	}
	stop := make(chan struct{})
	var bg sync.WaitGroup
	bg.Add(1)
	go func() {
		defer bg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			c.Set(base.Add(time.Duration(i%steps) * time.Minute))
			if err := db.Flush(ctx); err != nil {
				t.Error(err)
				return
			}
			if _, err := db.QueryMulti(ctx, []string{"h1|v", "h2|v"}, base, base.Add(5*time.Hour), 100); err != nil {
				t.Error(err)
				return
			}
			db.Stats()
		}
	}()
	wg.Wait()
	close(stop)
	bg.Wait()
	c.Set(base.Add(steps * time.Minute))
	for k := 0; k < keys; k++ {
		s := query(t, db, fmt.Sprintf("h%d|v", k), base, base.Add(steps*time.Minute), 1000)
		if len(s.Points) == 0 {
			t.Fatalf("Reihe %d leer", k)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Flush(ctx); err != ErrClosed {
		t.Errorf("Flush nach Close: %v", err)
	}
}

func TestBackgroundFlush(t *testing.T) {
	c := &clock{t: base}
	db := openTest(t, filepath.Join(t.TempDir(), "m.db"), c, Options{FlushInterval: 10 * time.Millisecond})
	db.Append("k", base, 1)
	deadline := time.Now().Add(5 * time.Second)
	for db.Stats().LastFlush.IsZero() {
		if time.Now().After(deadline) {
			t.Fatal("keine Hintergrund-Sicherung")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal("zweites Close:", err)
	}
}

// F4-K1: Uhr springt ueber den Beginn der laufenden Stunde zurueck -> die Reihe beginnt neu statt alles zu
// verwerfen, auch nach einem Neustart (Untergrenze in der Datei zurueckgesetzt).
func TestClockJumpBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	c := &clock{t: base}
	ctx := context.Background()
	db := openTest(t, path, c, DefaultOptions())
	fill(db, c, "k", base.Add(12*time.Hour), base.Add(14*time.Hour+30*time.Minute), time.Minute, func(int) float64 { return 1 })
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	back := base.Add(12*time.Hour + 10*time.Minute)
	n := fill(db, c, "k", back, back.Add(30*time.Minute), time.Minute, func(int) float64 { return 2 })
	st := db.Stats()
	if st.ClockResets != 1 || st.Dropped != 0 {
		t.Fatalf("nach Uhrsprung: %+v, erwartet 1 Neubeginn und nichts verworfen", st)
	}
	s := query(t, db, "k", back, back.Add(30*time.Minute), 1000)
	if len(s.Points) != n || s.Points[0].Avg != 2 {
		t.Fatalf("nach Uhrsprung %d Punkte (erwartet %d): %+v", len(s.Points), n, s.Points[:min(2, len(s.Points))])
	}
	// echte verspaetete Punkte (Uhr richtig) werden weiter verworfen, ohne Neubeginn
	db.Append("k", back.Add(-time.Hour), 9)
	if st := db.Stats(); st.DroppedLate != 1 || st.ClockResets != 1 {
		t.Fatalf("verspaeteter Punkt: %+v", st)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db = openTest(t, path, c, DefaultOptions())
	defer db.Close()
	db.Append("k", back.Add(35*time.Minute), 3)
	if st := db.Stats(); st.Dropped != 0 || st.ClockResets != 0 {
		t.Fatalf("nach Neustart: %+v", st)
	}
	if s := query(t, db, "k", back, back.Add(40*time.Minute), 1000); len(s.Points) != n+1 || s.Points[n].Avg != 3 {
		t.Fatalf("nach Neustart %d Punkte, erwartet %d", len(s.Points), n+1)
	}
	// die Stunde "aus der Zukunft" bleibt erhalten (abgeschlossen), bis neue Daten sie ersetzen
	var fin int
	db.sql.QueryRow(`SELECT fin FROM blk_raw WHERE start = ?`, base.Add(14*time.Hour).Unix()).Scan(&fin)
	if fin != 1 {
		t.Errorf("Block 14:00 fin = %d, erwartet 1", fin)
	}
}

// F4-K1: offener Block in der Zukunft beim Laden (Absturz, danach Uhr zurueck) wird abgeschlossen.
func TestClockJumpBackAfterCrash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	c := &clock{t: base}
	ctx := context.Background()
	db := openTest(t, path, c, DefaultOptions())
	fill(db, c, "k", base.Add(13*time.Hour), base.Add(14*time.Hour+30*time.Minute), time.Minute, func(int) float64 { return 1 })
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	crash(db)

	c.Set(base.Add(12*time.Hour + 10*time.Minute))
	db = openTest(t, path, c, DefaultOptions())
	defer db.Close()
	s := db.lookup("k")
	if len(s.off) != 0 || len(s.sealed) != 1 || s.sealed[0].start != base.Add(14*time.Hour).Unix() {
		t.Fatalf("Block der Zukunft: laufend %d Punkte, %d abgeschlossen", len(s.off), len(s.sealed))
	}
	db.Append("k", c.Now(), 2)
	if st := db.Stats(); st.Dropped != 0 || st.ClockResets != 1 || st.Points != 31 {
		t.Fatalf("Stats %+v", st)
	}
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	var floor int64
	db.sql.QueryRow(`SELECT sealed FROM series WHERE key = ?`, "k").Scan(&floor)
	if floor != base.Add(12*time.Hour).Unix() {
		t.Errorf("Untergrenze in der Datei %v, erwartet 12:00", time.Unix(floor, 0).UTC())
	}
}

// F4-K2: dauerhaft scheiternde Sicherung -> ungesicherte Stunden sind begrenzt, die aeltesten fallen weg.
func TestBacklogLimit(t *testing.T) {
	defer func(h int, p int64) { maxSealedHours, maxBacklogPoints = h, p }(maxSealedHours, maxBacklogPoints)
	maxSealedHours = 5
	c := &clock{t: base}
	db := openTest(t, filepath.Join(t.TempDir(), "m.db"), c, DefaultOptions())
	defer db.Close()
	failing, cancel := context.WithCancel(context.Background())
	cancel()
	fill(db, c, "a", base, base.Add(10*time.Hour), time.Minute, func(i int) float64 { return float64(i) })
	if err := db.Flush(failing); err == nil {
		t.Fatal("Flush mit abgebrochenem Kontext ohne Fehler")
	}
	st := db.Stats()
	if st.Points != 6*60 || st.DroppedBacklog != 4*60 || st.Dropped != 4*60 {
		t.Fatalf("Stats %+v, erwartet 360 Punkte im Speicher und 240 verworfen", st)
	}
	if err := db.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := query(t, db, "a", base.Add(4*time.Hour), base.Add(10*time.Hour), 1000); len(s.Points) != 360 || s.Points[0].T != base.Add(4*time.Hour).Unix() {
		t.Fatalf("nach Sicherung %d Punkte", len(s.Points))
	}
	if s := query(t, db, "a", base, base.Add(4*time.Hour-time.Second), 1000); len(s.Points) != 0 {
		t.Fatalf("verworfene Stunden: %d Punkte", len(s.Points))
	}
	if b := db.backlog.Load(); b != 0 {
		t.Errorf("backlog %d nach Sicherung", b)
	}

	// Obergrenze insgesamt: je Reihe bleibt die neueste Stunde
	maxSealedHours, maxBacklogPoints = 24, 150
	fill(db, c, "b", base.Add(20*time.Hour), base.Add(24*time.Hour), time.Minute, func(int) float64 { return 1 })
	fill(db, c, "c", base.Add(20*time.Hour), base.Add(24*time.Hour), time.Minute, func(int) float64 { return 1 })
	b, cc := db.lookup("b"), db.lookup("c")
	if len(b.sealed) != 2 || len(cc.sealed) != 1 || cc.sealed[0].start != base.Add(22*time.Hour).Unix() {
		t.Fatalf("b %d, c %d ungesicherte Stunden", len(b.sealed), len(cc.sealed))
	}
	if st := db.Stats(); st.DroppedBacklog != 4*60+3*60 {
		t.Errorf("DroppedBacklog %d", st.DroppedBacklog)
	}
}

// F4-K2: waehrend des Schreibens wegfallende Stunden duerfen nach dem Commit keine neueren mitnehmen.
func TestBacklogDropDuringWrite(t *testing.T) {
	defer func(h int) { maxSealedHours = h }(maxSealedHours)
	c := &clock{t: base}
	db := openTest(t, filepath.Join(t.TempDir(), "m.db"), c, DefaultOptions())
	defer db.Close()
	s := db.get("k")
	block := func(h int) sealedBlock {
		start := base.Add(time.Duration(h) * time.Hour).Unix()
		return makeSealed(start, []int64{start}, []float64{float64(h)}, 3)
	}
	s.mu.Lock()
	for h := 0; h < 3; h++ {
		db.pushSealed(s, block(h))
	}
	j := flushJob{s: s, key: s.key, sealed: slices.Clone(s.sealed), floor: s.floor, setFloor: true}
	maxSealedHours = 3
	db.pushSealed(s, block(3)) // verdraengt 0
	db.pushSealed(s, block(4)) // verdraengt 1
	s.mu.Unlock()
	if err := db.writeJobs(context.Background(), []flushJob{j}); err != nil {
		t.Fatal(err)
	}
	if len(s.sealed) != 2 || s.sealed[0].start != base.Add(3*time.Hour).Unix() || db.backlog.Load() != 2 {
		t.Fatalf("%d ungesicherte Stunden, backlog %d", len(s.sealed), db.backlog.Load())
	}
}

// F4-K3: Stundenbloecke umfassen 7 Tage (hoechstens 168 Punkte).
func TestHourBlockSpan(t *testing.T) {
	c := &clock{t: base}
	db := openTest(t, filepath.Join(t.TempDir(), "m.db"), c, DefaultOptions())
	defer db.Close()
	for d := 0; d < 9; d++ { // taeglich sichern (ungesicherte Stunden sind auf 24 begrenzt)
		day := base.Add(time.Duration(d) * 24 * time.Hour)
		fill(db, c, "k", day, day.Add(24*time.Hour), 10*time.Minute, func(i int) float64 { return float64(i % 7) })
		if err := db.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.sql.Query(`SELECT start, n FROM blk_1h`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	blocks, total := 0, 0
	for rows.Next() {
		var start int64
		var n int
		rows.Scan(&start, &n)
		if start%(7*86400) != 0 || n > 168 {
			t.Errorf("Block %d mit %d Punkten", start, n)
		}
		blocks++
		total += n
	}
	if blocks != 2 || total != 9*24-1 { // die letzte Stunde laeuft noch
		t.Errorf("%d Bloecke mit %d Stundenwerten", blocks, total)
	}
}

// F4-K3: Datei mit 30-Tage-Stundenbloecken (Version 0) wird beim Oeffnen umgebaut.
func TestMigrateHourBlocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	s30 := base.Unix() - base.Unix()%(30*86400)
	c := &clock{t: time.Unix(s30+21*86400, 0)}
	db := openTest(t, path, c, DefaultOptions())
	var pts []aggPt
	for h := int64(0); h < 20*24; h++ {
		v := float64(h % 24)
		pts = append(pts, aggPt{t: s30 + h*hour, min: v, avg: v + 0.5, max: v + 1, n: 60})
	}
	if _, err := db.sql.Exec(`INSERT INTO series(id, key, sealed) VALUES(1, ?, ?)`, "k", s30+20*86400); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(`INSERT INTO blk_1h(sid, start, n, data) VALUES(1, ?, ?, ?)`, s30, len(pts), encodeAgg(pts, 3)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(`PRAGMA user_version = 0`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = openTest(t, path, c, DefaultOptions())
	var ver, bad, total int
	db.sql.QueryRow(`PRAGMA user_version`).Scan(&ver)
	db.sql.QueryRow(`SELECT count(*) FROM blk_1h WHERE start % ? != 0 OR n > 168`, 7*86400).Scan(&bad)
	db.sql.QueryRow(`SELECT sum(n) FROM blk_1h`).Scan(&total)
	if ver != fileVersion || bad != 0 || total != len(pts) {
		t.Fatalf("Version %d, %d falsche Bloecke, %d Stundenwerte", ver, bad, total)
	}
	s := query(t, db, "k", time.Unix(s30, 0), time.Unix(s30+20*86400, 0), 1000)
	if s.Res != "1h" || len(s.Points) != len(pts) || s.Points[25].Avg != 1.5 {
		t.Fatalf("res %q, %d Punkte", s.Res, len(s.Points))
	}
	// neuere Dateiversion wird abgelehnt
	if _, err := db.sql.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if db, err := Open(path, Options{FlushInterval: -1}); err == nil {
		db.Close()
		t.Error("neuere Dateiversion ohne Fehler geoeffnet")
	}
}

// F4-K4: gemischte Aufloesung -> jeder Punkt meldet seine Breite (S).
func TestMixedResolutionWidth(t *testing.T) {
	c := &clock{t: base}
	opts := DefaultOptions()
	opts.RetentionRaw = 2 * time.Hour
	db := openTest(t, filepath.Join(t.TempDir(), "m.db"), c, opts)
	defer db.Close()
	ctx := context.Background()
	fill(db, c, "k", base, base.Add(5*time.Hour), time.Minute, func(i int) float64 { return float64(i) })
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Purge(ctx, c.Now()); err != nil {
		t.Fatal(err)
	}
	s := query(t, db, "k", base, base.Add(5*time.Hour), 1000)
	if s.Res != "raw" || s.Step != 0 || len(s.Points) != 24+180 {
		t.Fatalf("res %q step %d, %d Punkte", s.Res, s.Step, len(s.Points))
	}
	if s.Points[0].S != 300 || s.Points[23].S != 300 || s.Points[24].S != 0 {
		t.Errorf("Breiten %d/%d/%d, erwartet 300/300/0", s.Points[0].S, s.Points[23].S, s.Points[24].S)
	}
	// verdichtet: Breite mindestens der Schritt, aufgefuellte groebere Punkte behalten ihre
	pts := []aggPt{
		{t: 0, avg: 1, min: 1, max: 1, n: 60, w: hour},
		{t: hour, avg: 2, min: 2, max: 2, n: 60, w: hour},
		{t: 2 * hour, avg: 3, min: 3, max: 3, n: 5, w: 300},
		{t: 2*hour + 300, avg: 5, min: 5, max: 5, n: 5, w: 300},
	}
	out, step := downsample(pts, 0, 3*hour, 6)
	if step != 1800 || len(out) != 3 || out[0].w != hour || out[2].w != 1800 || out[2].avg != 4 {
		t.Fatalf("step %d, %+v", step, out)
	}
}

// F4-K5: nicht ausgerichtete Grenzen -> trotzdem maxPoints Fenster (Sparks: 48 Punkte fuer 24 h).
func TestDownsampleUnaligned(t *testing.T) {
	c := &clock{t: base}
	db := openTest(t, filepath.Join(t.TempDir(), "m.db"), c, DefaultOptions())
	defer db.Close()
	for h := 0; h < 27; h += 9 {
		fill(db, c, "k", base.Add(time.Duration(h)*time.Hour), base.Add(time.Duration(h+9)*time.Hour), time.Minute, func(i int) float64 { return float64(i % 13) })
		if err := db.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	from := base.Add(2*time.Hour + 17*time.Minute + 23*time.Second)
	s := query(t, db, "k", from, from.Add(24*time.Hour), 48)
	if len(s.Points) != 48 || s.Step != 1800 {
		t.Fatalf("%d Punkte, step %d, erwartet 48 und 1800", len(s.Points), s.Step)
	}
	for i, p := range s.Points {
		if p.T != from.Unix()+int64(i)*1800 || p.S != 1800 {
			t.Fatalf("Punkt %d: %+v", i, p)
		}
	}
	// ausgerichtete Grenzen wie bisher, Punkt genau bei to im letzten Fenster
	out, step := downsample([]aggPt{{t: 0, n: 1}, {t: 3600, n: 1}, {t: 7200, n: 1}}, 0, 7200, 2)
	if step != 3600 || len(out) != 2 || out[1].n != 2 {
		t.Errorf("step %d, %+v", step, out)
	}
}

// F4-K7: kleine Werte (Fehlerraten) behalten ihre Stellen.
func TestSmallValuesKeepDigits(t *testing.T) {
	c := &clock{t: base}
	db := openTest(t, filepath.Join(t.TempDir(), "m.db"), c, DefaultOptions())
	defer db.Close()
	vals := []float64{0.0012, 0, 0.0003, 0.00005, 0.0101}
	for i, v := range vals {
		db.Append("k", base.Add(time.Duration(i)*time.Minute), v)
	}
	c.Set(base.Add(2 * time.Hour))
	if err := db.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := query(t, db, "k", base, base.Add(time.Hour), 1000)
	for i, p := range s.Points {
		if p.Avg != vals[i] {
			t.Errorf("Wert %d: %v statt %v", i, p.Avg, vals[i])
		}
	}
	h := query(t, db, "k", base, base.Add(60*24*time.Hour), 0)
	if len(h.Points) != 1 || h.Points[0].Max != 0.0101 || h.Points[0].Min != 0 || math.Abs(h.Points[0].Avg-0.00233) > 1e-9 {
		t.Errorf("Stundenwert %+v", h.Points)
	}
}

// F4-K6: Purge direkt nach Open (offene Stunde aus einem Absturz noch im Speicher).
func TestPurgeRightAfterOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	c := &clock{t: base}
	ctx := context.Background()
	db := openTest(t, path, c, DefaultOptions())
	fill(db, c, "k", base, base.Add(30*time.Minute), time.Minute, func(int) float64 { return 1 })
	fill(db, c, "alt", base, base.Add(10*time.Minute), time.Minute, func(int) float64 { return 1 })
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	crash(db)
	c.Set(base.Add(3 * time.Hour))
	db = openTest(t, path, c, DefaultOptions())
	defer db.Close()
	if _, err := db.Purge(ctx, c.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if s := query(t, db, "k", base, base.Add(time.Hour), 0); len(s.Points) != 30 {
		t.Fatalf("%d Punkte nach Purge und Flush", len(s.Points))
	}
	if st := db.Stats(); st.Series != 2 {
		t.Errorf("Stats %+v", st)
	}
}
