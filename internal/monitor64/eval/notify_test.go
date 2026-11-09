package eval

import (
	"encoding/json"
	"slices"
	"testing"
	"time"
)

// Kanaele: mail bekommt Warnung und Kritisch, push nur Kritisch.
func testRouting() Routing {
	cfg := NotifyConfig{
		Channels:   []ChannelRoute{{ID: "mail", Warn: true, Crit: true}, {ID: "push", Crit: true}},
		RemindCrit: Dur(24 * time.Hour),
	}
	return ResolveRouting(cfg, nil, nas)
}

type rig struct {
	t  *testing.T
	n  Notifier
	rt Routing
}

func newRig(t *testing.T) *rig { return &rig{t: t, rt: testRouting()} }

type opt func(*Round)

func unreachable(r *Round) { r.Unreachable = true }
func maint(r *Round)       { r.Maintenance = true }
func quiet(r *Round)       { r.Quiet = true }

func svc(key string, s State) ServiceInput { return ServiceInput{Key: key, Name: key, State: s} }

func (g *rig) at(min float64, svcs []ServiceInput, opts ...opt) Result {
	r := Round{At: t0.Add(time.Duration(min * float64(time.Minute))), Host: nas, Services: svcs}
	for _, o := range opts {
		o(&r)
	}
	return g.n.Round(r, g.rt)
}

func (g *rig) one(min float64, key string, s State, opts ...opt) Result {
	return g.at(min, []ServiceInput{svc(key, s)}, opts...)
}

// chanLines: je Kanal die Zeilenarten (Kontrolle, wer was bekommt).
func chanKinds(res Result) map[string][]LineKind {
	out := map[string][]LineKind{}
	for _, m := range res.Messages {
		for _, c := range m.Channels {
			for _, l := range m.Lines {
				out[c] = append(out[c], l.Kind)
			}
		}
	}
	return out
}

func wantChans(t *testing.T, label string, res Result, want map[string][]LineKind) {
	t.Helper()
	got := chanKinds(res)
	if len(got) != len(want) {
		t.Fatalf("%s: Kanaele %v, erwartet %v", label, got, want)
	}
	for c, kinds := range want {
		if !slices.Equal(got[c], kinds) {
			t.Fatalf("%s: %s bekommt %v, erwartet %v", label, c, got[c], kinds)
		}
	}
}

func TestNotifyWorsenAndRecover(t *testing.T) {
	g := newRig(t)
	if res := g.one(0, "fs:/", OK); len(res.Messages) != 0 {
		t.Fatal("OK am Anfang meldet")
	}
	res := g.one(1, "fs:/", Warn)
	wantChans(t, "OK->Warn", res, map[string][]LineKind{"mail": {LineProblem}})
	if m := res.Messages[0]; m.Event != EvProblem || m.Severity != Warn || m.Counts.Warn != 1 || m.Lines[0].Prev != OK {
		t.Fatalf("%+v", m)
	}
	res = g.one(2, "fs:/", Crit)
	wantChans(t, "Warn->Crit", res, map[string][]LineKind{"mail": {LineProblem}, "push": {LineProblem}})
	if len(res.Messages) != 1 || !slices.Equal(res.Messages[0].Channels, []string{"mail", "push"}) {
		t.Fatalf("gleiche Zeilen muessen eine Meldung sein: %+v", res.Messages)
	}
	if res := g.one(3, "fs:/", Crit); len(res.Messages) != 0 {
		t.Fatal("unveraendert meldet")
	}
	// Kritisch -> Warnung: "besser, aber noch Warnung" an alle, die das Problem kennen
	res = g.one(4, "fs:/", Warn)
	wantChans(t, "Crit->Warn", res, map[string][]LineKind{"mail": {LineBetter}, "push": {LineBetter}})
	if m := res.Messages[0]; m.Event != EvOK || m.Severity != Warn {
		t.Fatalf("besser: %+v", m)
	}
	// Entwarnung an genau die Kanaele, die das Problem bekommen haben (push kennt es noch)
	res = g.one(5, "fs:/", OK)
	wantChans(t, "->OK", res, map[string][]LineKind{"mail": {LineOK}, "push": {LineOK}})
	l := res.Messages[0].Lines[0]
	if res.Messages[0].Event != EvOK || res.Messages[0].Severity != OK || !l.Since.Equal(t0.Add(time.Minute)) || l.Prev != Warn {
		t.Fatalf("Entwarnung: %+v", res.Messages[0])
	}
	// Neues Warnproblem: push hat es nie bekommen, also auch keine Entwarnung
	g.one(40, "fs:/", Warn)
	res = g.one(41, "fs:/", OK)
	wantChans(t, "Warn->OK", res, map[string][]LineKind{"mail": {LineOK}})
	if res.Lines[0].Since != t0.Add(40*time.Minute) {
		t.Fatalf("Problem seit: %v", res.Lines[0].Since)
	}
}

func TestNotifyRecoveryOnlyToNotifiedChannels(t *testing.T) {
	g := newRig(t)
	g.rt = ResolveRouting(NotifyConfig{Channels: []ChannelRoute{{ID: "mail", Warn: true}, {ID: "push", Crit: true}}}, nil, nas)
	res := g.one(0, "disk", Crit)
	wantChans(t, "Crit", res, map[string][]LineKind{"push": {LineProblem}})
	res = g.one(1, "disk", OK)
	wantChans(t, "OK", res, map[string][]LineKind{"push": {LineOK}})
	// Warnung ohne passenden Kanal: niemand bekommt etwas, auch keine Entwarnung
	g.rt.Channels = []ChannelRoute{{ID: "push", Crit: true}}
	if res := g.one(2, "disk", Warn); len(res.Messages) != 0 || len(res.Lines) != 1 {
		t.Fatalf("ohne Kanal: %+v", res)
	}
	if res := g.one(3, "disk", OK); len(res.Messages) != 0 {
		t.Fatalf("Entwarnung an Unbeteiligte: %+v", res.Messages)
	}
}

func TestNotifyBundling(t *testing.T) {
	g := newRig(t)
	g.at(0, []ServiceInput{svc("a", OK), svc("b", OK), svc("c", OK)})
	res := g.at(1, []ServiceInput{svc("a", Crit), svc("b", Warn), svc("c", Warn)})
	// mail bekommt alles in einer Meldung, push nur die Kritisch-Zeile
	wantChans(t, "Runde", res, map[string][]LineKind{"mail": {LineProblem, LineProblem, LineProblem}, "push": {LineProblem}})
	if len(res.Messages) != 2 {
		t.Fatalf("%d Meldungen", len(res.Messages))
	}
	for _, m := range res.Messages {
		switch m.Channels[0] {
		case "mail":
			if m.Counts != (Counts{Crit: 1, Warn: 2}) || m.Severity != Crit {
				t.Fatalf("mail: %+v", m)
			}
		case "push":
			if m.Counts != (Counts{Crit: 1}) || m.Lines[0].Key != "a" {
				t.Fatalf("push: %+v", m)
			}
		}
		for _, l := range m.Lines {
			if l.Channels != nil {
				t.Fatal("Kanaele in Meldungszeilen")
			}
		}
	}
	// Gemischte Runde: Entwarnung und neues Problem -> Problem-Meldung
	res = g.at(2, []ServiceInput{svc("a", OK), svc("b", Crit), svc("c", Warn)})
	for _, m := range res.Messages {
		if m.Event != EvProblem {
			t.Fatalf("gemischt: %+v", m)
		}
	}
	if len(res.Lines) != 2 {
		t.Fatalf("Zeilen: %+v", res.Lines)
	}
}

func TestNotifyUnreachable(t *testing.T) {
	g := newRig(t)
	g.at(0, []ServiceInput{svc("a", Warn), svc("b", OK)})
	// nicht erreichbar: eine Meldung, Dienste (Unbekannt) nicht
	res := g.at(1, []ServiceInput{svc("a", Unknown), svc("b", Unknown)}, unreachable)
	wantChans(t, "nicht erreichbar", res, map[string][]LineKind{"mail": {LineUnreachable}, "push": {LineUnreachable}})
	if m := res.Messages[0]; m.Event != EvUnreachable || m.Severity != Crit || m.Counts != (Counts{}) {
		t.Fatalf("%+v", m)
	}
	if res := g.at(2, []ServiceInput{svc("a", Unknown), svc("b", Unknown)}, unreachable); len(res.Messages) != 0 {
		t.Fatal("zweite Meldung")
	}
	// wieder erreichbar: eine Meldung mit allem, was noch offen ist
	res = g.at(10, []ServiceInput{svc("a", OK), svc("b", Crit)})
	wantChans(t, "wieder erreichbar", res, map[string][]LineKind{"mail": {LineReachable, LineOpen}, "push": {LineReachable, LineOpen}})
	m := res.Messages[0]
	if m.Event != EvReachable || !m.Lines[0].Since.Equal(t0.Add(time.Minute)) || m.Lines[1].Key != "b" || m.Counts != (Counts{Crit: 1}) {
		t.Fatalf("%+v", m)
	}
	// a war vorher als Warnung gemeldet und ist jetzt OK: keine eigene Entwarnung mehr
	if res := g.at(11, []ServiceInput{svc("a", OK), svc("b", Crit)}); len(res.Messages) != 0 {
		t.Fatalf("Nachzuegler: %+v", res.Messages)
	}
	res = g.at(12, []ServiceInput{svc("a", OK), svc("b", OK)})
	wantChans(t, "b OK", res, map[string][]LineKind{"mail": {LineOK}, "push": {LineOK}})

	// wieder erreichbar ohne Offenes: nur die Host-Zeile; Warnung nur an Warn-Kanaele zusaetzlich
	g.at(20, nil, unreachable)
	res = g.at(21, []ServiceInput{svc("a", Warn), svc("b", OK)})
	wantChans(t, "erreichbar mit Warnung", res, map[string][]LineKind{"mail": {LineReachable, LineOpen}, "push": {LineReachable, LineOpen}})
}

func TestNotifyMaintenance(t *testing.T) {
	g := newRig(t)
	g.at(0, []ServiceInput{svc("a", OK), svc("b", Crit), svc("c", OK)})
	// in der Wartung: nichts, auch nicht nicht-erreichbar
	for m := 1; m <= 5; m++ {
		s := Crit
		if m%2 == 0 {
			s = OK
		}
		if res := g.at(float64(m), []ServiceInput{svc("a", s), svc("b", OK), svc("c", Warn)}, maint); len(res.Messages) != 0 {
			t.Fatal("Meldung in der Wartung")
		}
	}
	if res := g.at(6, nil, maint, unreachable); len(res.Messages) != 0 {
		t.Fatal("nicht erreichbar in der Wartung gemeldet")
	}
	// Ende: noch offen ist c (Warnung); b wurde in der Wartung OK (still), a ist OK
	res := g.at(7, []ServiceInput{svc("a", OK), svc("b", OK), svc("c", Warn)})
	wantChans(t, "nach Wartung", res, map[string][]LineKind{"mail": {LineOpen}})
	if m := res.Messages[0]; !m.AfterMaintenance || m.Event != EvProblem || m.Lines[0].Key != "c" || !m.Lines[0].Since.Equal(t0.Add(time.Minute)) {
		t.Fatalf("%+v", m)
	}
	// danach normal weiter; kein Flattern aus den Wechseln in der Wartung
	res = g.at(8, []ServiceInput{svc("a", OK), svc("b", OK), svc("c", OK)})
	wantChans(t, "c OK", res, map[string][]LineKind{"mail": {LineOK}})

	// Ende ohne Offenes: keine Meldung
	g.at(10, []ServiceInput{svc("a", Crit)}, maint)
	if res := g.at(11, []ServiceInput{svc("a", OK)}); len(res.Messages) != 0 {
		t.Fatalf("Ende ohne Offenes: %+v", res.Messages)
	}
	// Ende, waehrend der Host nicht erreichbar ist: die Host-Meldung kommt dann
	g.at(20, nil, maint, unreachable)
	res = g.at(21, nil, unreachable)
	wantChans(t, "nach Wartung nicht erreichbar", res, map[string][]LineKind{"mail": {LineUnreachable}, "push": {LineUnreachable}})
	if !res.Messages[0].AfterMaintenance {
		t.Fatal("AfterMaintenance fehlt")
	}
}

func TestNotifyFlapping(t *testing.T) {
	g := newRig(t)
	g.one(-1, "p", OK)
	n := 0
	for m := 0; m <= 4; m++ { // 5 Wechsel: jeder wird gemeldet
		s := Crit
		if m%2 == 1 {
			s = OK
		}
		res := g.one(float64(m), "p", s)
		n += len(res.Lines)
	}
	if n != 5 {
		t.Fatalf("%d Zeilen vor dem Flattern", n)
	}
	res := g.one(5, "p", OK) // 6. Wechsel in 30 min
	wantChans(t, "flattert", res, map[string][]LineKind{"mail": {LineFlapping}, "push": {LineFlapping}})
	if res.Messages[0].Event != EvFlapping {
		t.Fatalf("%+v", res.Messages[0])
	}
	for m := 6; m <= 10; m++ { // weiter Wechsel: Ruhe
		s := Crit
		if m%2 == 1 {
			s = OK
		}
		if res := g.one(float64(m), "p", s); len(res.Lines) != 0 {
			t.Fatalf("min %d: Meldung waehrend Flattern", m)
		}
	}
	// stabil Kritisch seit min 10: erst nach 30 min die Meldung mit dem aktuellen Zustand
	for m := 11; m < 40; m++ {
		if res := g.one(float64(m), "p", Crit); len(res.Lines) != 0 {
			t.Fatalf("min %d: zu frueh", m)
		}
	}
	res = g.one(40, "p", Crit)
	wantChans(t, "stabil", res, map[string][]LineKind{"mail": {LineFlapEnd}, "push": {LineFlapEnd}})
	if m := res.Messages[0]; m.Event != EvProblem || m.Lines[0].State != Crit {
		t.Fatalf("%+v", m)
	}
	// danach normal
	res = g.one(41, "p", OK)
	wantChans(t, "OK", res, map[string][]LineKind{"mail": {LineOK}, "push": {LineOK}})

	// Stabil OK nach dem Flattern: Meldung an die, die das Problem kennen
	g2 := newRig(t)
	for m := 0; m <= 5; m++ {
		s := Warn
		if m%2 == 1 {
			s = OK
		}
		g2.one(float64(m), "p", s)
	}
	res = g2.one(35, "p", OK)
	wantChans(t, "stabil OK", res, map[string][]LineKind{"mail": {LineFlapEnd}})
	if res.Messages[0].Event != EvOK {
		t.Fatalf("%+v", res.Messages[0])
	}

	// Langsame Wechsel (alle 7 min) flattern nie
	g3 := newRig(t)
	for i := 0; i < 20; i++ {
		s := Warn
		if i%2 == 1 {
			s = OK
		}
		res := g3.one(float64(i*7), "p", s)
		for _, l := range res.Lines {
			if l.Kind == LineFlapping {
				t.Fatalf("Wechsel %d: flattert", i)
			}
		}
	}
}

func TestNotifyReminder(t *testing.T) {
	g := newRig(t)
	g.at(0, []ServiceInput{svc("c", Crit), svc("w", Warn)})
	day := 24 * 60.0
	if res := g.at(day-1, []ServiceInput{svc("c", Crit), svc("w", Warn)}); len(res.Lines) != 0 {
		t.Fatal("Erinnerung zu frueh")
	}
	res := g.at(day, []ServiceInput{svc("c", Crit), svc("w", Warn)})
	wantChans(t, "Erinnerung", res, map[string][]LineKind{"mail": {LineReminder}, "push": {LineReminder}})
	if res.Messages[0].Event != EvReminder || res.Lines[0].Key != "c" {
		t.Fatalf("%+v", res.Messages[0])
	}
	// Warnung: Standard nie
	if res := g.at(10*day, []ServiceInput{svc("c", Crit), svc("w", Warn)}); len(res.Lines) != 1 || res.Lines[0].Key != "c" {
		t.Fatalf("Warnung erinnert: %+v", res.Lines)
	}

	// Ruhezeit: keine Erinnerung; die naechste kommt einen Tag nach der Ruhezeit
	g = newRig(t)
	g.one(0, "c", Crit)
	for m := day; m <= day+8*60; m += 60 { // 8 h Ruhezeit ab Faelligkeit
		if res := g.one(m, "c", Crit, quiet); len(res.Lines) != 0 {
			t.Fatalf("Erinnerung in der Ruhezeit (min %v)", m)
		}
	}
	if res := g.one(day+8*60+1, "c", Crit); len(res.Lines) != 0 {
		t.Fatal("Erinnerung direkt nach der Ruhezeit")
	}
	if res := g.one(2*day+8*60, "c", Crit); len(res.Lines) != 1 || res.Lines[0].Kind != LineReminder {
		t.Fatalf("Erinnerung einen Tag nach der Ruhezeit fehlt: %+v", res.Lines)
	}

	// Quittiert: keine Erinnerung
	g = newRig(t)
	g.one(0, "c", Crit)
	if res := g.at(2*day, []ServiceInput{{Key: "c", State: Crit, Acked: true}}); len(res.Lines) != 0 {
		t.Fatal("Erinnerung trotz Quittierung")
	}

	// Abweichung: Warnung alle 4 Std.
	g = newRig(t)
	g.rt = ResolveRouting(NotifyConfig{Channels: []ChannelRoute{{ID: "mail", Warn: true, Crit: true}}},
		[]NotifyOverride{{Tag: "nas", RemindWarn: D(4 * time.Hour)}}, nas)
	g.one(0, "w", Warn)
	if res := g.one(239, "w", Warn); len(res.Lines) != 0 {
		t.Fatal("4 h zu frueh")
	}
	if res := g.one(240, "w", Warn); len(res.Lines) != 1 {
		t.Fatal("4 h Erinnerung fehlt")
	}
	if res := g.one(240+day, "w", Unknown); len(res.Lines) != 1 || res.Lines[0].Kind != LineProblem {
		t.Fatalf("Unbekannt: %+v", res.Lines)
	}
}

func TestNotifyAck(t *testing.T) {
	g := newRig(t)
	ack := func(key string, s State) []ServiceInput {
		return []ServiceInput{{Key: key, Name: key, State: s, Acked: true}}
	}
	g.one(0, "a", Warn)
	if res := g.at(1, ack("a", Warn)); len(res.Lines) != 0 || len(res.Unack) != 0 {
		t.Fatal("quittiert, unveraendert")
	}
	// Verschlechterung hebt die Quittierung auf und wird gemeldet
	res := g.at(2, ack("a", Crit))
	if len(res.Lines) != 1 || res.Lines[0].Kind != LineProblem || !slices.Equal(res.Unack, []string{"a"}) {
		t.Fatalf("%+v", res)
	}
	// Besser, aber quittiert: still
	if res := g.at(3, ack("a", Warn)); len(res.Lines) != 0 {
		t.Fatalf("besser trotz Quittierung gemeldet: %+v", res.Lines)
	}
	// Erledigt: Entwarnung an alle, die das Problem kennen
	res = g.at(4, ack("a", OK))
	wantChans(t, "OK nach Quittierung", res, map[string][]LineKind{"mail": {LineOK}, "push": {LineOK}})
}

func TestNotifyShowOnlyAndUnknown(t *testing.T) {
	g := newRig(t)
	show := []ServiceInput{{Key: "t", State: Crit, ShowOnly: true}}
	if res := g.at(0, show); len(res.Lines) != 0 {
		t.Fatal("nur anzeigen meldet")
	}
	show[0].State = OK
	if res := g.at(1, show); len(res.Lines) != 0 {
		t.Fatal("nur anzeigen meldet Entwarnung")
	}
	// Unbekannt wird wie Warnung geroutet
	res := g.one(2, "u", Unknown)
	wantChans(t, "Unbekannt", res, map[string][]LineKind{"mail": {LineProblem}})
	if m := res.Messages[0]; m.Severity != Unknown || m.Counts.Unknown != 1 {
		t.Fatalf("%+v", m)
	}
	res = g.one(3, "u", Warn)
	wantChans(t, "Unbekannt->Warn", res, map[string][]LineKind{"mail": {LineBetter}})
	res = g.one(4, "u", Crit)
	wantChans(t, "->Crit", res, map[string][]LineKind{"mail": {LineProblem}, "push": {LineProblem}})
	// Dienst verschwindet: vergessen
	g.at(5, nil)
	if len(g.n.Hosts["h1"].Svcs) != 0 {
		t.Fatal("verschwundener Dienst bleibt")
	}
	g.n.Forget("h1")
	if _, ok := g.n.Hosts["h1"]; ok {
		t.Fatal("Forget")
	}
}

func TestNotifyClockBackwards(t *testing.T) {
	g := newRig(t)
	g.one(1000, "c", Crit)
	if res := g.one(10, "c", Crit); len(res.Lines) != 0 { // Uhr 990 min zurueck
		t.Fatal("Sprung meldet")
	}
	if res := g.one(10+24*60, "c", Crit); len(res.Lines) != 1 || res.Lines[0].Kind != LineReminder {
		t.Fatalf("Erinnerung nach Uhrsprung: %+v", res.Lines)
	}
}

func TestRouting(t *testing.T) {
	base := DefaultNotifyConfig([]string{"mail", "push"})
	if base.RemindCrit != Dur(24*time.Hour) || base.RemindWarn != 0 || len(base.Channels) != 2 || !base.Channels[1].Warn {
		t.Fatalf("Standard: %+v", base)
	}
	ovs := []NotifyOverride{
		{ID: "web", Tag: "web", Channels: []ChannelRoute{{ID: "x", Crit: true}}, Replace: true},
		{ID: "keller", Group: "keller", Channels: []ChannelRoute{{ID: "tg", Warn: true, Crit: true}, {ID: "push", Crit: true}},
			OnlyCrit: ptr(true), CritInQuiet: ptr(true)},
		{ID: "nas", Tag: "nas", Channels: []ChannelRoute{{ID: "y", Crit: true}}, Replace: true}, // passt auch, aber unten
	}
	rt := ResolveRouting(base, ovs, nas)
	if rt.Override != 1 || rt.OverrideID != "keller" || !rt.OnlyCrit || !rt.CritInQuiet {
		t.Fatalf("%+v", rt)
	}
	if got := rt.Route(Crit); !slices.Equal(got, []string{"mail", "push", "tg"}) {
		t.Fatalf("Kritisch: %v", got)
	}
	if got := rt.Route(Warn); len(got) != 0 {
		t.Fatalf("nur Kritisch, Warnung geht an %v", got)
	}
	rt = ResolveRouting(base, ovs, HostRef{ID: "w", Tags: []string{"web"}})
	if got := rt.Route(Crit); !slices.Equal(got, []string{"x"}) {
		t.Fatalf("statt: %v", got)
	}
	rt = ResolveRouting(base, ovs, HostRef{ID: "z"})
	if rt.Override != -1 || !slices.Equal(rt.Route(Unknown), []string{"mail", "push"}) {
		t.Fatalf("ohne Treffer: %+v", rt)
	}
	// Grundeinstellung wird nicht veraendert
	if len(base.Channels) != 2 || base.Channels[1].Warn != true {
		t.Fatal("ResolveRouting veraendert die Grundeinstellung")
	}

	// Kritisch-in-Ruhezeit nur fuer kritische Meldungen
	g := newRig(t)
	g.rt = ResolveRouting(base, ovs, nas)
	res := g.one(0, "a", Crit)
	if len(res.Messages) != 1 || !res.Messages[0].CritInQuiet {
		t.Fatalf("%+v", res.Messages)
	}
	res = g.one(1, "a", OK)
	if res.Messages[0].CritInQuiet {
		t.Fatal("Entwarnung als Kritisch-in-Ruhezeit")
	}
	res = g.at(2, nil, unreachable)
	if !res.Messages[0].CritInQuiet {
		t.Fatal("nicht erreichbar zaehlt als Kritisch")
	}
}

func TestNotifierJSON(t *testing.T) {
	g := newRig(t)
	for m := 0; m <= 5; m++ {
		s := Crit
		if m%2 == 1 {
			s = OK
		}
		g.at(float64(m), []ServiceInput{svc("p", s), svc("q", Warn)})
	}
	b, err := json.Marshal(&g.n)
	if err != nil {
		t.Fatal(err)
	}
	var back Notifier
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	b2, _ := json.Marshal(&back)
	if string(b) != string(b2) {
		t.Fatalf("Rundreise:\n%s\n%s", b, b2)
	}
	g.n = back
	if !g.n.Hosts["h1"].Svcs["p"].Flapping {
		t.Fatal("Flattern nach Laden verloren")
	}
	res := g.at(36, []ServiceInput{svc("p", OK), svc("q", OK)})
	kinds := map[string]LineKind{}
	for _, l := range res.Lines {
		kinds[l.Key] = l.Kind
	}
	if kinds["p"] != LineFlapEnd || kinds["q"] != LineOK {
		t.Fatalf("nach Laden: %+v", res.Lines)
	}
	// leerer Notifier ist benutzbar
	var z Notifier
	z.Round(Round{At: t0, Host: nas}, testRouting())
}
