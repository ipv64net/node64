package eval

import (
	"encoding/json"
	"testing"
	"time"
)

func berlin(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skipf("Zeitzonendaten fehlen: %v", err)
	}
	return loc
}

var nas = HostRef{ID: "h1", Name: "nas01", Group: "Keller", Tags: []string{"nas"}}

func sundays(from, to Clock) Window {
	return Window{Hosts: []string{"h1"}, Recurring: &Recurrence{Days: []time.Weekday{time.Sunday}, From: from, To: to}}
}

// activeMinutes zaehlt die aktiven Minuten zwischen a und b (echte Minuten, in UTC gezaehlt).
func activeMinutes(w Window, a, b time.Time, loc *time.Location) int {
	n := 0
	for at := a; at.Before(b); at = at.Add(time.Minute) {
		if w.Active(at, nas, loc) {
			n++
		}
	}
	return n
}

func TestMaintenanceWeekly(t *testing.T) {
	loc := berlin(t)
	w := sundays(At(2, 0), At(4, 0))
	cases := []struct {
		at   time.Time
		want bool
	}{
		{time.Date(2026, 11, 8, 1, 59, 59, 0, loc), false},
		{time.Date(2026, 11, 8, 2, 0, 0, 0, loc), true},
		{time.Date(2026, 11, 8, 3, 59, 59, 0, loc), true},
		{time.Date(2026, 11, 8, 4, 0, 0, 0, loc), false},
		{time.Date(2026, 11, 7, 3, 0, 0, 0, loc), false}, // Samstag
		{time.Date(2026, 11, 8, 2, 30, 0, 0, loc).UTC(), true},
	}
	for _, c := range cases {
		if got := w.Active(c.at, nas, loc); got != c.want {
			t.Errorf("%v: %v", c.at, got)
		}
	}
	// Normaler Sonntag: 120 Minuten
	day := time.Date(2026, 11, 8, 0, 0, 0, 0, loc)
	if n := activeMinutes(w, day, day.Add(24*time.Hour), loc); n != 120 {
		t.Fatalf("normaler Sonntag: %d min", n)
	}
}

func TestMaintenanceDST(t *testing.T) {
	loc := berlin(t)
	w := sundays(At(2, 0), At(4, 0))

	// 29.03.2026: 02:00 MEZ -> 03:00 MESZ, die Stunde 02-03 fehlt: Fenster dauert 60 min.
	spring := time.Date(2026, 3, 29, 0, 0, 0, 0, loc)
	if n := activeMinutes(w, spring, spring.Add(24*time.Hour), loc); n != 60 {
		t.Fatalf("Sommerzeit: %d min", n)
	}
	last := time.Date(2026, 3, 29, 1, 59, 0, 0, loc)
	if w.Active(last, nas, loc) || !w.Active(last.Add(time.Minute), nas, loc) {
		t.Fatal("Sommerzeit: Beginn nicht direkt nach 01:59 MEZ")
	}
	// Fenster komplett in der fehlenden Stunde gibt es an diesem Tag nicht.
	gone := sundays(At(2, 0), At(2, 30))
	if n := activeMinutes(gone, spring, spring.Add(24*time.Hour), loc); n != 0 {
		t.Fatalf("fehlende Stunde: %d min", n)
	}

	// 25.10.2026: 03:00 MESZ -> 02:00 MEZ, die Stunde 02-03 kommt zweimal: Fenster dauert 180 min.
	fall := time.Date(2026, 10, 25, 0, 0, 0, 0, loc)
	if n := activeMinutes(w, fall, fall.Add(25*time.Hour), loc); n != 180 {
		t.Fatalf("Winterzeit: %d min", n)
	}
	// Taeglich 01:00-02:00 ist am Umstellungstag im Herbst normal lang.
	daily := Window{Hosts: []string{"h1"}, Recurring: &Recurrence{From: At(1, 0), To: At(2, 0)}}
	if n := activeMinutes(daily, fall, fall.Add(25*time.Hour), loc); n != 60 {
		t.Fatalf("taeglich 01-02 im Herbst: %d min", n)
	}
}

func TestMaintenanceOvernightAndWholeDay(t *testing.T) {
	loc := berlin(t)
	w := Window{Groups: []string{"keller"}, Recurring: &Recurrence{Days: []time.Weekday{time.Saturday}, From: At(23, 0), To: At(1, 0)}}
	cases := []struct {
		at   time.Time
		want bool
	}{
		{time.Date(2026, 11, 7, 22, 59, 0, 0, loc), false},
		{time.Date(2026, 11, 7, 23, 0, 0, 0, loc), true},   // Samstag
		{time.Date(2026, 11, 8, 0, 59, 0, 0, loc), true},   // Sonntag frueh, Beginn Samstag
		{time.Date(2026, 11, 8, 1, 0, 0, 0, loc), false},   //
		{time.Date(2026, 11, 8, 23, 30, 0, 0, loc), false}, // Sonntag Abend
		{time.Date(2026, 11, 7, 0, 30, 0, 0, loc), false},  // Samstag frueh (Beginn waere Freitag)
	}
	for _, c := range cases {
		if got := w.Active(c.at, nas, loc); got != c.want {
			t.Errorf("%v: %v", c.at, got)
		}
	}
	// From == To: ganzer Tag ab From
	whole := Window{Tags: []string{"NAS"}, Recurring: &Recurrence{Days: []time.Weekday{time.Monday}, From: At(6, 0), To: At(6, 0)}}
	mon := time.Date(2026, 11, 9, 0, 0, 0, 0, loc)
	if n := activeMinutes(whole, mon, mon.Add(48*time.Hour), loc); n != 24*60 {
		t.Fatalf("ganzer Tag: %d min", n)
	}
	// Bis 24:00
	eod := Window{Hosts: []string{"h1"}, Recurring: &Recurrence{From: At(22, 0), To: At(24, 0)}}
	if !eod.Active(time.Date(2026, 11, 9, 23, 59, 0, 0, loc), nas, loc) || eod.Active(time.Date(2026, 11, 10, 0, 0, 0, 0, loc), nas, loc) {
		t.Fatal("bis 24:00")
	}
}

func TestMaintenanceOneShotAndScope(t *testing.T) {
	start, end := t0, t0.Add(2*time.Hour)
	w := Window{Hosts: []string{"h1"}, Start: start, End: end}
	if w.Active(start.Add(-time.Second), nas, nil) || !w.Active(start, nas, nil) || !w.Active(end.Add(-time.Second), nas, nil) || w.Active(end, nas, nil) {
		t.Fatal("geplant: Grenzen")
	}
	open := Window{Hosts: []string{"h1"}, Start: start}
	if !open.Active(start.Add(1000*time.Hour), nas, nil) {
		t.Fatal("jetzt bis beendet")
	}
	// wiederkehrend, begrenzt
	rec := Window{Hosts: []string{"h1"}, End: time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC), Recurring: &Recurrence{From: At(2, 0), To: At(4, 0)}}
	if !rec.Active(time.Date(2026, 11, 9, 3, 0, 0, 0, time.UTC), nas, nil) || rec.Active(time.Date(2026, 11, 10, 3, 0, 0, 0, time.UTC), nas, nil) {
		t.Fatal("wiederkehrend mit Ende")
	}
	// Geltungsbereich
	other := HostRef{ID: "h2", Group: "Buero", Tags: []string{"web"}}
	scopes := []Window{{Hosts: []string{"h1"}}, {Groups: []string{"KELLER"}}, {Tags: []string{"Nas"}}}
	for i, s := range scopes {
		if !s.Active(t0, nas, nil) || s.Active(t0, other, nil) {
			t.Errorf("Bereich %d", i)
		}
	}
	if (Window{Groups: []string{""}}).Applies(HostRef{ID: "x"}) {
		t.Fatal("leere Gruppe passt auf Host ohne Gruppe")
	}
	ok, win := InMaintenance([]Window{{Hosts: []string{"h2"}}, {ID: "b", Tags: []string{"nas"}}}, t0, nas, nil)
	if !ok || win.ID != "b" {
		t.Fatal("InMaintenance")
	}
	if ok, _ := InMaintenance(nil, t0, nas, nil); ok {
		t.Fatal("ohne Fenster")
	}
}

func TestClockJSON(t *testing.T) {
	w := Window{ID: "w", Hosts: []string{"h1"}, Start: t0, Recurring: &Recurrence{Days: []time.Weekday{0, 6}, From: At(2, 5), To: At(24, 0)}}
	b, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	var back Window
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Recurring.From != At(2, 5) || back.Recurring.To != At(24, 0) || !back.Start.Equal(t0) || len(back.Recurring.Days) != 2 {
		t.Fatalf("%s -> %+v", b, back)
	}
	for _, bad := range []string{`"25:00"`, `"24:01"`, `"ab"`, `"02:60"`, `"-1:00"`} {
		var c Clock
		if json.Unmarshal([]byte(bad), &c) == nil {
			t.Errorf("%s ohne Fehler", bad)
		}
	}
	if _, err := Clock(1441).MarshalText(); err == nil {
		t.Fatal("1441 ohne Fehler")
	}
}
