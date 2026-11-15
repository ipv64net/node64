package tsdb

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// #165: Verlauf eines Dienstes an einen anderen Host haengen - gesicherte Bloecke und Punkte im Speicher ziehen mit,
// belegte Ziele bleiben, nach dem Neuoeffnen gilt der neue Schluessel.
func TestRenameSeriesPrefix(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ts.db")
	clock := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	opt := DefaultOptions()
	opt.FlushInterval = -1
	opt.Now = func() time.Time { return clock }
	db, err := Open(path, opt)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 90; i++ { // ueber eine Stundengrenze: abgeschlossener Block + laufender
		ts := clock.Add(-89*time.Minute + time.Duration(i)*time.Minute)
		db.Append("A|vm:101|running", ts, 1)
		db.Append("A|vm:101|cpu", ts, float64(i))
		db.Append("A|vm:1011|cpu", ts, 5)
		db.Append("B|vm:101|cpu", ts, 7) // am Ziel schon belegt
	}
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	db.Append("A|vm:101|running", clock.Add(30*time.Second), 1) // ungesichert
	n, err := db.RenameSeriesPrefix(ctx, "A|vm:101|", "B|vm:101|")
	if err != nil || n != 1 {
		t.Fatalf("umbenannt %d, %v", n, err)
	}
	q := func(db *DB, key string) int {
		s, err := db.Query(ctx, key, clock.Add(-2*time.Hour), clock.Add(time.Hour), 1000)
		if err != nil {
			t.Fatal(err)
		}
		return len(s.Points)
	}
	if got := q(db, "B|vm:101|running"); got < 90 {
		t.Errorf("neuer Schluessel: %d Punkte", got)
	}
	if q(db, "A|vm:101|running") != 0 || q(db, "A|vm:101|cpu") == 0 || q(db, "A|vm:1011|cpu") == 0 {
		t.Error("falsche Reihen umbenannt")
	}
	db.Append("B|vm:101|running", clock.Add(time.Minute), 1) // weiter unter dem neuen Schluessel
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(path, opt)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got := q(db, "B|vm:101|running"); got < 91 {
		t.Errorf("nach dem Neuoeffnen: %d Punkte", got)
	}
	if q(db, "A|vm:101|running") != 0 {
		t.Error("alter Schluessel nach dem Neuoeffnen")
	}
	if _, err := db.RenameSeriesPrefix(ctx, "", "B|"); err == nil {
		t.Error("leeres Praefix angenommen")
	}
}
