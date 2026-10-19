package cdnedge

import (
	"testing"
	"time"
)

// Faire Drossel: unter 80 % nichts; darueber Max-Min-Verteilung von 90 % der Kapazitaet (der Kleine bleibt frei,
// der Grosse wird gebremst, nicht getrennt); ein neuer Account bekommt seinen Anteil; unter 60 % faellt sie weg.
func TestFairShare(t *testing.T) {
	now := time.Unix(1000, 0)
	var slept time.Duration
	w := newBandwidth()
	w.now = func() time.Time { return now }
	w.sleep = func(d time.Duration) { slept += d; now = now.Add(d) }
	w.setCapacity(8) // 1.000.000 B/s
	setRate := func(uid int, r float64) { w.b[uid] = &bucket{rate: r, winStart: now, last: now} }

	setRate(1, 700000) // 70 %: noch keine Drossel
	setRate(2, 50000)
	w.fairRound()
	if len(w.fair) != 0 {
		t.Fatalf("throttled below 80 %%: %v", w.fair)
	}
	setRate(1, 900000) // 95 %: der Grosse wird gebremst, der Kleine nicht
	w.fairRound()
	if w.fair[1] != 850000 || w.fair[2] != 0 {
		t.Fatalf("fair share: %v", w.fair)
	}
	// der Gedrosselte wartet beim Lesen (3 MB bei 0,85 MB/s), der Kleine nie
	slept = 0
	for i := 0; i < 30; i++ {
		w.take(1, 100000)
	}
	if slept < 3*time.Second || slept > 4*time.Second {
		t.Fatalf("throttled account slept %v", slept)
	}
	slept = 0
	w.take(2, 100000)
	if slept != 0 {
		t.Fatal("small account must not wait")
	}
	// zweiter Grosser kommt: beide haengen an der Drossel -> je die Haelfte
	setRate(1, 850000)
	setRate(3, 400000)
	w.fair[3] = 400000
	setRate(2, 0)
	w.fairRound()
	if w.fair[1] != 450000 || w.fair[3] != 450000 {
		t.Fatalf("two heavy accounts: %v", w.fair)
	}
	// Last faellt unter 60 %: Drossel weg
	setRate(1, 300000)
	setRate(3, 200000)
	w.fairRound()
	if len(w.fair) != 0 {
		t.Fatalf("still throttled at 50 %%: %v", w.fair)
	}
	if load, capMbit, _ := w.fairStatus(); load != 4 || capMbit != 8 {
		t.Fatalf("status: %v %v", load, capMbit)
	}
	// ohne Kapazitaet: nie
	w.setCapacity(-1)
	setRate(1, 5e6)
	w.fairRound()
	if len(w.fair) != 0 {
		t.Fatal("throttled without capacity")
	}
}
