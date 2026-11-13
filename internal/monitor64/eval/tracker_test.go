package eval

import (
	"encoding/json"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func eff(kind string, svc *Rule) Effective {
	return Resolve(Defaults(), nil, HostRef{ID: "h"}, HostLevel{Service: svc}, kind)
}

type step struct {
	min   float64 // Minuten ab t0
	v     float64
	want  State
	label string
	gap   bool // keine Messungen seit dem vorigen Schritt (sonst jede Minute mit Wert v aufgefuellt)
}

func runSteps(t *testing.T, e Effective, tr *Tracker, steps []step) {
	t.Helper()
	for i, s := range steps {
		if i > 0 && !s.gap {
			for m := steps[i-1].min + 1; m < s.min; m++ {
				tr.Observe(e, Sample{At: t0.Add(time.Duration(m * float64(time.Minute))), Value: s.v})
			}
		}
		at := t0.Add(time.Duration(s.min * float64(time.Minute)))
		st := tr.Observe(e, Sample{At: at, Value: s.v})
		if st.State != s.want {
			t.Fatalf("%s (t=%vmin, v=%v): %v, erwartet %v (%+v)", s.label, s.min, s.v, st.State, s.want, st)
		}
	}
}

func TestTrackerThresholdsAndHysteresis(t *testing.T) {
	var tr Tracker
	runSteps(t, eff(KindFSUsed, nil), &tr, []step{
		{0, 79.999, OK, "knapp unter Warnung", false},
		{1, 80, Warn, "genau auf der Warnschwelle", false},
		{2, 78.5, Warn, "Hysterese haelt", false},
		{3, 78, Warn, "genau auf Schwelle minus Hysterese haelt noch", false},
		{4, 77.99, OK, "unter Schwelle minus Hysterese", false},
		{5, 90, Crit, "genau auf Kritisch", false},
		{6, 88, Crit, "Hysterese Kritisch", false},
		{7, 87.9, Warn, "zurueck auf Warnung", false},
		{8, 50, OK, "direkt OK", false},
		{9, 95, Crit, "Sprung direkt auf Kritisch", false},
		{10, 10, OK, "Sprung direkt auf OK", false},
	})
}

func TestTrackerDirectionDown(t *testing.T) {
	var tr Tracker
	runSteps(t, eff(KindPrinterSupply, nil), &tr, []step{
		{0, 25, OK, "voll", false},
		{1, 15, OK, "genau auf der Schwelle ist unten noch OK", false},
		{2, 14.9, Warn, "unter Warnung", false},
		{3, 4, Crit, "unter Kritisch", false},
		{4, 6, Crit, "Hysterese: erst ab 7 besser", false},
		{5, 7, Warn, "Kritisch + Hysterese erreicht", false},
		{6, 16, Warn, "Warnung + Hysterese noch nicht erreicht", false},
		{7, 17, OK, "zurueck", false},
	})
	// USV: Restlaufzeit in Sekunden (20/10 min), Hysterese 60 s
	tr = Tracker{}
	runSteps(t, eff(KindUPSRuntime, &Rule{Warn: L(1200)}), &tr, []step{ // Warnung am Dienst gesetzt (Standard: nur Kritisch)
		{0, 3600, OK, "volle Batterie", false},
		{1, 599, Crit, "unter 10 min", false},
		{2, 640, Crit, "Hysterese", false},
		{3, 660, Warn, "10 min + 60 s: noch unter 20 min", false},
		{4, 1260, OK, "20 min + 60 s", false},
	})
}

func TestTrackerDuration(t *testing.T) {
	e := eff(KindCPUUtil, nil) // 90/95, 15 min
	var tr Tracker
	for m := 0; m <= 7; m++ {
		st := tr.Observe(e, Sample{At: t0.Add(time.Duration(m) * time.Minute), Value: 92})
		if st.State != OK {
			t.Fatalf("min %d: %v", m, st.State)
		}
	}
	st := tr.Status(e, t0.Add(7*time.Minute))
	// "seit 7 Min. ueber 90 % – Warnung ab 15 Min."
	if st.Pending != Warn || !st.PendingSince.Equal(t0) || !st.PendingAt.Equal(t0.Add(15*time.Minute)) || st.PendingLimit.V != 90 {
		t.Fatalf("Wartet-Anzeige falsch: %+v", st)
	}
	for m := 8; m <= 14; m++ {
		tr.Observe(e, Sample{At: t0.Add(time.Duration(m) * time.Minute), Value: 92})
	}
	st = tr.Observe(e, Sample{At: t0.Add(15 * time.Minute), Value: 92})
	if st.State != Warn || st.Pending != OK || st.Threshold.V != 90 || !st.Since.Equal(t0.Add(15*time.Minute)) {
		t.Fatalf("nach 15 min: %+v", st)
	}

	// Kurze Spitze zaehlt nicht: ein Wert unter der Schwelle setzt die Dauer zurueck.
	tr = Tracker{}
	runSteps(t, e, &tr, []step{
		{0, 99, OK, "Spitze", false},
		{10, 99, OK, "10 min drueber", false},
		{11, 50, OK, "Einbruch", false},
		{12, 99, OK, "neu", false},
		{26, 99, OK, "14 min seit Neustart", false},
		{27, 99, Crit, "15 min seit Neustart -> direkt Kritisch", false},
	})

	// Kritisch wartet, Warnung ist schon aktiv
	tr = Tracker{}
	runSteps(t, e, &tr, []step{{0, 92, OK, "", false}, {15, 92, Warn, "", false}, {16, 97, Warn, "Kritisch wartet", false}})
	st = tr.Status(e, t0.Add(16*time.Minute))
	if st.Pending != Crit || !st.PendingAt.Equal(t0.Add(31*time.Minute)) {
		t.Fatalf("Kritisch-Wartezeit: %+v", st)
	}
	// Rueckkehr wartet nicht auf die Dauer
	runSteps(t, e, &tr, []step{{17, 10, OK, "sofort OK", false}})
}

func TestTrackerGapsAndClock(t *testing.T) {
	e := eff(KindCPUUtil, nil)

	// Kurze Luecke (2 Intervalle) haelt die Dauer.
	var tr Tracker
	runSteps(t, e, &tr, []step{{0, 99, OK, "", false}, {10, 99, OK, "", false}, {13, 99, OK, "Luecke 3 min = genau 3 Intervalle", true}, {15, 99, Crit, "", false}})

	// Luecke ueber 3 Intervalle, aber kuerzer als die Dauer: Dauer laeuft weiter (keine Messung darunter).
	tr = Tracker{}
	runSteps(t, e, &tr, []step{{0, 99, OK, "", false}, {10, 99, OK, "", false}, {14, 99, OK, "Luecke 4 min", true}, {15, 99, Crit, "15 min seit Beginn", false}})

	// Luecke laenger als die Dauer setzt sie neu an.
	tr = Tracker{}
	runSteps(t, e, &tr, []step{{0, 99, OK, "", false}, {10, 99, OK, "", false}, {26, 99, OK, "Luecke 16 min", true}, {40, 99, OK, "", false}, {41, 99, Crit, "15 min nach der Luecke", false}})

	// Messung unter der Schwelle vor der Luecke unterbricht die Dauer weiterhin.
	tr = Tracker{}
	runSteps(t, e, &tr, []step{{0, 99, OK, "", false}, {10, 50, OK, "darunter", false}, {14, 99, OK, "Luecke", true}, {28, 99, OK, "", false}, {29, 99, Crit, "15 min nach Wiederanstieg", false}})

	// Uhr springt vor: wirkt wie eine Luecke, kein sofortiges Kritisch.
	tr = Tracker{}
	runSteps(t, e, &tr, []step{{0, 99, OK, "", false}, {1, 99, OK, "", false}, {120, 99, OK, "Uhr springt 2 h vor", true}})

	// Uhr springt zurueck: Dauer neu, kein Fehler.
	tr = Tracker{}
	runSteps(t, e, &tr, []step{{0, 99, OK, "", false}, {10, 99, OK, "", false}, {2, 99, OK, "Uhr zurueck", true}, {16, 99, OK, "14 min seit Sprung", false}, {17, 99, Crit, "", false}})

	// Aktive Stufe bleibt ueber eine Luecke fuer die Hysterese erhalten.
	tr = Tracker{}
	ef := eff(KindFSUsed, nil)
	runSteps(t, ef, &tr, []step{{0, 91, Crit, "", false}, {30, 89, Crit, "nach Luecke im Hysteresebereich", true}})
}

// F5-K5: lange Dauer (Sicherheitsupdates, 24 h) mit taeglichen kurzen Luecken meldet trotzdem.
func TestTrackerLongDurationWithGaps(t *testing.T) {
	e := eff(KindUpdatesSecurity, nil)
	tr := Tracker{Interval: Dur(time.Minute)}
	var first time.Time
	for m := 0; m < 3*24*60; m++ {
		if m%(23*60) >= 23*60-4 { // 4 min ohne Daten je 23 h (Neustart Node oder Host)
			continue
		}
		at := t0.Add(time.Duration(m) * time.Minute)
		if st := tr.Observe(e, Sample{At: at, Value: Bool(true)}); st.State == Warn && first.IsZero() {
			first = at
		}
	}
	if !first.Equal(t0.Add(24 * time.Hour)) {
		t.Fatalf("Warnung ab %v, erwartet nach 24 h (%v)", first, t0.Add(24*time.Hour))
	}
	// Ausfall laenger als die Dauer: neu ansetzen.
	tr = Tracker{Interval: Dur(time.Minute)}
	tr.Observe(e, Sample{At: t0, Value: 1})
	if st := tr.Observe(e, Sample{At: t0.Add(25 * time.Hour), Value: 1}); st.State != OK || st.PendingSince != t0.Add(25*time.Hour) {
		t.Fatalf("nach 25 h Ausfall: %+v", st)
	}
}

func TestTrackerUnknown(t *testing.T) {
	e := eff(KindFSUsed, nil)
	var tr Tracker
	if st := tr.Status(e, t0); st.State != Unknown || !st.Since.IsZero() {
		t.Fatalf("ohne Messung: %+v", st)
	}
	tr.Observe(e, Sample{At: t0, Value: 95})
	if st := tr.Status(e, t0.Add(3*time.Minute)); st.State != Crit {
		t.Fatalf("genau 3 Intervalle: %v", st.State)
	}
	st := tr.Status(e, t0.Add(3*time.Minute+time.Second))
	if st.State != Unknown || st.Level != Crit || !st.Since.Equal(t0.Add(3*time.Minute)) {
		t.Fatalf("nach 3 Intervallen: %+v", st)
	}
	// eigenes Intervall (SMART 30 min)
	tr = Tracker{Interval: Dur(30 * time.Minute)}
	tr.Observe(e, Sample{At: t0, Value: 10})
	if tr.Status(e, t0.Add(89*time.Minute)).State != OK || tr.Status(e, t0.Add(91*time.Minute)).State != Unknown {
		t.Fatal("Intervall 30 min nicht beachtet")
	}
	// Daten kommen zurueck
	if st := tr.Observe(e, Sample{At: t0.Add(2 * time.Hour), Value: 10}); st.State != OK {
		t.Fatalf("nach Rueckkehr: %v", st.State)
	}
}

func TestTrackerFreeMode(t *testing.T) {
	e := eff(KindStoreUsed, &Rule{Mode: ptr(ModeFree), WarnFree: L(500), CritFree: L(100)})
	var tr Tracker
	cases := []struct {
		free float64
		want State
	}{
		{600 * GB, OK},
		{500 * GB, OK}, // genau auf der Schwelle: nicht "weniger als"
		{499 * GB, Warn},
		{99 * GB, Crit},
		{101 * GB, Crit}, // Hysterese 2 GB
		{102 * GB, Warn},
		{503 * GB, OK},
	}
	for i, c := range cases {
		st := tr.Observe(e, Sample{At: t0.Add(time.Duration(i) * time.Minute), Value: 99, Free: c.free})
		if st.State != c.want {
			t.Fatalf("frei %v GB: %v, erwartet %v", c.free/GB, st.State, c.want)
		}
		if st.Value != c.free/GB {
			t.Fatalf("Wert %v", st.Value)
		}
	}
}

func TestTrackerStateRules(t *testing.T) {
	// Sicherheitsupdates: Warnung erst nach 1 Tag
	e := eff(KindUpdatesSecurity, nil)
	var tr Tracker
	tr.Interval = Dur(time.Hour)
	for h := 0; h < 24; h++ {
		if st := tr.Observe(e, Sample{At: t0.Add(time.Duration(h) * time.Hour), Value: Bool(true)}); st.State != OK {
			t.Fatalf("Stunde %d: %v", h, st.State)
		}
	}
	if st := tr.Observe(e, Sample{At: t0.Add(24 * time.Hour), Value: Bool(true)}); st.State != Warn {
		t.Fatalf("nach 1 Tag: %v", st.State)
	}
	if st := tr.Observe(e, Sample{At: t0.Add(25 * time.Hour), Value: Bool(false)}); st.State != OK {
		t.Fatalf("installiert: %v", st.State)
	}

	// SMART FAILED: sofort Kritisch; "nicht melden" macht nichts schlechter
	tr = Tracker{}
	if st := tr.Observe(eff(KindSmartFailed, nil), Sample{At: t0, Value: 1}); st.State != Crit {
		t.Fatalf("SMART: %v", st.State)
	}
	tr = Tracker{}
	if st := tr.Observe(eff(KindSmartFailed, &Rule{Severity: ptr(SevOff)}), Sample{At: t0, Value: 1}); st.State != OK {
		t.Fatalf("nicht melden: %v", st.State)
	}
	tr = Tracker{}
	if st := tr.Observe(eff(KindRAIDDegraded, &Rule{Severity: ptr(SevWarn)}), Sample{At: t0, Value: 1}); st.State != Warn {
		t.Fatalf("RAID als Warnung: %v", st.State)
	}
}

func TestTrackerRecheckAndJSON(t *testing.T) {
	e := eff(KindCPUUtil, nil)
	var tr Tracker
	for m := 0; m <= 5; m++ {
		tr.Observe(e, Sample{At: t0.Add(time.Duration(m) * time.Minute), Value: 92})
	}
	b, err := json.Marshal(&tr)
	if err != nil {
		t.Fatal(err)
	}
	var back Tracker
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back != tr {
		t.Fatalf("Rundreise:\n%+v\n%+v\n%s", tr, back, b)
	}
	// Weiter mit dem geladenen Stand: nach 15 min Warnung
	for m := 6; m <= 15; m++ {
		back.Observe(e, Sample{At: t0.Add(time.Duration(m) * time.Minute), Value: 92})
	}
	if back.Level != Warn {
		t.Fatalf("nach Laden: %v", back.Level)
	}
	// Schwelle angehoben -> sofort neu bewertet
	e2 := eff(KindCPUUtil, &Rule{Warn: L(95), Crit: L(99)})
	if st := back.Recheck(e2, t0.Add(15*time.Minute)); st.State != OK {
		t.Fatalf("Recheck hoeher: %v", st.State)
	}
	// Schwelle gesenkt, ohne Dauer -> sofort
	e3 := eff(KindCPUUtil, &Rule{Warn: L(50), For: D(0)})
	if st := back.Recheck(e3, t0.Add(15*time.Minute)); st.State != Warn {
		t.Fatalf("Recheck niedriger: %v", st.State)
	}
	// Recheck ohne Messung aendert nichts
	var empty Tracker
	if st := empty.Recheck(e, t0); st.State != Unknown {
		t.Fatalf("leer: %v", st.State)
	}
}

// Issue #109: Im Modus "GB frei" galt die geerbte Hysterese (2, gedacht in Prozentpunkten) als 2 GB – eine Schwelle
// von 1 GB hielt die Warnung bis 3 GB frei ("nur noch 1,2 GB frei (Schwelle 1 GB)"). Geerbt gilt sie hoechstens als
// ein Zehntel der Schwelle; eine zusammen mit "GB frei" gesetzte Hysterese gilt unveraendert in GB.
func TestTrackerFreeModeSmallLimit(t *testing.T) {
	run := func(e Effective, cases []struct {
		free float64
		want State
	}) {
		t.Helper()
		var tr Tracker
		for i, c := range cases {
			st := tr.Observe(e, Sample{At: t0.Add(time.Duration(i) * time.Minute), Value: 99, Free: c.free * GB})
			if st.State != c.want {
				t.Fatalf("frei %v GB: %v, erwartet %v", c.free, st.State, c.want)
			}
		}
	}
	type cs = []struct {
		free float64
		want State
	}
	inherited := eff(KindFSUsed, &Rule{Mode: ptr(ModeFree), WarnFree: L(1)})
	if h := inherited.HystAt(1); h != 0.1 {
		t.Fatalf("geerbte Hysterese bei 1 GB = %v", h)
	}
	run(inherited, cs{{5, OK}, {0.9, Warn}, {1.05, Warn}, {1.2, OK}, {0.99, Warn}, {1.11, OK}})
	explicit := eff(KindFSUsed, &Rule{Mode: ptr(ModeFree), WarnFree: L(1), Hyst: F(0.5)})
	run(explicit, cs{{5, OK}, {0.9, Warn}, {1.2, Warn}, {1.49, Warn}, {1.6, OK}})
	// Abweichung stellt auf "GB frei", der Dienst setzt nur die Hysterese: gilt in GB
	std := Defaults()
	ovr := []Override{{ID: "o", Group: "g", Kind: KindFSUsed, Rule: Rule{Mode: ptr(ModeFree), WarnFree: L(10)}}}
	e := Resolve(std, ovr, HostRef{ID: "h", Group: "g"}, HostLevel{Service: &Rule{Hyst: F(3)}}, KindFSUsed)
	if h := e.HystAt(10); h != 3 {
		t.Fatalf("Hysterese vom Dienst = %v", h)
	}
	// Fuellstand in Prozent: unveraendert 2 Prozentpunkte
	if h := eff(KindFSUsed, nil).HystAt(80); h != DefaultHyst {
		t.Fatalf("Hysterese in Prozent = %v", h)
	}
}
