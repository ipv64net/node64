package dnsserver

import (
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/dns64/filter"
)

func TestTimeRules(t *testing.T) {
	loc := time.UTC
	mon := func(h, m int) time.Time { return time.Date(2026, 10, 19, h, m, 0, 0, loc) }         // Montag
	night := TimeRule{Label: "Schlaf", Days: 0b0011111, Start: 21 * 60, End: 7 * 60, Off: true} // Mo-Fr 21-7
	for _, tt := range []struct {
		at   time.Time
		want bool
	}{
		{mon(21, 30), true}, {mon(6, 59), false}, {mon(20, 59), false}, {mon(7, 0), false},
		{time.Date(2026, 10, 20, 6, 0, 0, 0, loc), true},   // Dienstag frueh: von Montag
		{time.Date(2026, 10, 25, 23, 0, 0, 0, loc), false}, // Sonntag abends: nicht
		{time.Date(2026, 10, 25, 6, 0, 0, 0, loc), false},  // Sonntag frueh: Samstag nicht drin
		{time.Date(2026, 10, 24, 6, 0, 0, 0, loc), true},   // Samstag frueh: von Freitag
	} {
		if _, got := night.active(tt.at); got != tt.want {
			t.Errorf("%s: %v, want %v", tt.at.Format("Mon 15:04"), got, tt.want)
		}
	}
	if until, _ := night.active(mon(22, 0)); !until.Equal(time.Date(2026, 10, 20, 7, 0, 0, 0, loc)) {
		t.Fatalf("until %v", until)
	}
	day := TimeRule{Days: 1, Start: 0, End: 0}
	if _, ok := day.active(mon(12, 0)); !ok {
		t.Fatal("whole day")
	}

	social := Category{Key: "social", Set: filter.GroupCategory("social")}
	p := &Policy{Loc: loc, Cats: []Category{{Key: "games", Set: filter.GroupCategory("games")}},
		Rules: []TimeRule{{Days: 0b1111111, Start: 0, End: 0, Cats: []Category{social}}}}
	if st := p.State(mon(12, 0)); st.Off || len(st.Cats) != 2 || len(p.Cats) != 1 {
		t.Fatalf("cats: %+v (policy %d)", st, len(p.Cats))
	}
	p.FreeUntil = mon(13, 0)
	if st := p.State(mon(12, 0)); !st.Free || len(st.Cats) != 0 {
		t.Fatalf("free: %+v", st)
	}
	p.BlockUntil = Forever
	if st := p.State(mon(12, 0)); !st.Off || st.Why != "off:hold" {
		t.Fatalf("hold: %+v", st)
	}
}
