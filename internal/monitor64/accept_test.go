package monitor64

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// "Zustand ist in Ordnung": Ein Port ohne Link meldet, bis man den Zustand bestaetigt - "bis sich der Zustand
// aendert" (bekommt der Port Link, ist die Ausnahme erledigt und der naechste Ausfall meldet wieder) oder
// "dauerhaft" (Regel aus, bis man es zuruecknimmt). Gilt fuer jede Zustandsregel.
func TestAcceptState(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	down := model.Service{Key: "if:eth1", Name: "eth1", Kind: "if", Default: true, Text: "kein Link", Facts: []model.Fact{{Code: "if_down", Text: "eth1 ohne Link"}}}
	up := model.Service{Key: "if:eth1", Name: "eth1", Kind: "if", Default: true, Text: "1 Gbit/s"}
	fake := &fakeCol{svcs: []model.Service{down}}
	rt := hostWithFake(t, e.m, fake)
	uid := rt.host.UID
	view := func() SvcView {
		t.Helper()
		for _, s := range rt.getView().Services {
			if s.Key == "if:eth1" {
				return s
			}
		}
		t.Fatal("Dienst fehlt")
		return SvcView{}
	}
	poll := func() SvcView { e.m.poll(ctx, rt); return view() }
	accept := func(mode string) int {
		return e.do("PUT", "/api/monitor64/hosts/"+uid+"/service", map[string]any{"key": "if:eth1", "accept": map[string]any{"kind": eval.KindIfDown, "mode": mode}}).Code
	}
	hostRule := func() string {
		return e.col(`SELECT host_rule FROM m64_services WHERE host_uid = ? AND key = 'if:eth1'`, uid)
	}

	e.m.poll(ctx, rt)
	adoptAll(t, e.m, uid)
	if s := poll(); s.State != eval.Warn || !slices.Contains(s.Firing, eval.KindIfDown) {
		t.Fatalf("ohne Link: %s %v", s.State, s.Firing)
	}
	// bis sich der Zustand aendert
	if c := accept("change"); c != 200 {
		t.Fatalf("accept change: %d", c)
	}
	if s := poll(); s.State != eval.OK || !slices.Contains(s.Accepted, eval.KindIfDown) || len(s.Firing) != 0 {
		t.Fatalf("bestaetigt: %s %v %v", s.State, s.Accepted, s.Firing)
	}
	if len(e.m.loadOpen(ctx, uid)) != 0 {
		t.Fatal("Problem offen trotz bestaetigtem Zustand")
	}
	// Port bekommt Link: Ausnahme erledigt
	fake.set([]model.Service{up}, nil)
	if s := poll(); s.State != eval.OK || len(s.Accepted) != 0 || strings.Contains(hostRule(), "accepted") {
		t.Fatalf("mit Link: %s %v %q", s.State, s.Accepted, hostRule())
	}
	// faellt er wieder aus, meldet er wieder
	fake.set([]model.Service{down}, nil)
	if s := poll(); s.State != eval.Warn {
		t.Fatalf("erneuter Ausfall: %s", s.State)
	}
	// dauerhaft: auch nach Link und erneutem Ausfall still
	if c := accept("always"); c != 200 || !strings.Contains(hostRule(), `"severity":"off"`) {
		t.Fatalf("accept always: %d %q", c, hostRule())
	}
	for _, svc := range []model.Service{down, up, down} {
		fake.set([]model.Service{svc}, nil)
		if s := poll(); s.State != eval.OK {
			t.Fatalf("dauerhaft: %s", s.State)
		}
	}
	// aufheben
	if c := accept(""); c != 200 || hostRule() != "" {
		t.Fatalf("aufheben: %d %q", c, hostRule())
	}
	if s := poll(); s.State != eval.Warn {
		t.Fatalf("nach dem Aufheben: %s", s.State)
	}
	// nur Zustandsregeln dieses Dienstes
	for _, k := range []string{"cpu.util", eval.KindGuestDown, "gibts.nicht"} {
		if c := e.do("PUT", "/api/monitor64/hosts/"+uid+"/service", map[string]any{"key": "if:eth1", "accept": map[string]any{"kind": k, "mode": "change"}}).Code; c != 400 {
			t.Errorf("%s angenommen: %d", k, c)
		}
	}
	if c := accept("bald"); c != 400 {
		t.Errorf("unbekannter Modus: %d", c)
	}
}

// "Wert ist in Ordnung" bei Zahlenwerten: SSD-Verschleiss 100 % meldet kritisch, bis man den Wert bestaetigt - dann
// OK bis zu diesem Wert (Hoechstwert: bleibt so). Wird der Wert schlechter oder faellt er unter die Warnschwelle, ist
// die Ausnahme erledigt; "dauerhaft" schaltet Warnung und Kritisch am Dienst ab.
func TestAcceptNumber(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	disk := func(wear float64) model.Service {
		return model.Service{Key: "disk:nvme0", Name: "nvme0", Kind: "disk", Default: true, Metrics: []model.Metric{{Name: "wear", Value: wear, Unit: "%", Rule: model.RuleWear}}}
	}
	fake := &fakeCol{svcs: []model.Service{disk(100)}}
	rt := hostWithFake(t, e.m, fake)
	uid := rt.host.UID
	poll := func() SvcView {
		t.Helper()
		e.m.poll(ctx, rt)
		for _, s := range rt.getView().Services {
			if s.Key == "disk:nvme0" {
				return s
			}
		}
		t.Fatal("Dienst fehlt")
		return SvcView{}
	}
	accept := func(mode string) int {
		return e.do("PUT", "/api/monitor64/hosts/"+uid+"/service", map[string]any{"key": "disk:nvme0", "accept": map[string]any{"kind": model.RuleWear, "mode": mode}}).Code
	}
	hostRule := func() string {
		return e.col(`SELECT host_rule FROM m64_services WHERE host_uid = ? AND key = 'disk:nvme0'`, uid)
	}
	e.m.poll(ctx, rt)
	adoptAll(t, e.m, uid)
	if s := poll(); s.State != eval.Crit || !slices.Contains(s.Firing, model.RuleWear) {
		t.Fatalf("100 %%: %s %v", s.State, s.Firing)
	}
	// in Ordnung bis zum aktuellen Wert
	if c := accept("change"); c != 200 || !strings.Contains(hostRule(), `"accepted_at":100`) {
		t.Fatalf("accept change: %d %q", c, hostRule())
	}
	for range 2 {
		if s := poll(); s.State != eval.OK || !slices.Contains(s.Accepted, model.RuleWear) || len(s.Firing) != 0 {
			t.Fatalf("bestaetigt: %s %v %v", s.State, s.Accepted, s.Firing)
		}
	}
	if len(e.m.loadOpen(ctx, uid)) != 0 {
		t.Fatal("Problem offen trotz bestaetigtem Wert")
	}
	// leichtes Schwanken innerhalb der Hysterese beendet die Ausnahme nicht
	fake.set([]model.Service{disk(99)}, nil)
	if s := poll(); s.State != eval.OK || !strings.Contains(hostRule(), "accepted_at") {
		t.Fatalf("99 %%: %s %q", s.State, hostRule())
	}
	// unter die Warnschwelle (neue Platte): erledigt, ein spaeterer Anstieg meldet wieder
	fake.set([]model.Service{disk(5)}, nil)
	if s := poll(); s.State != eval.OK || len(s.Accepted) != 0 || hostRule() != "" {
		t.Fatalf("neue Platte: %s %v %q", s.State, s.Accepted, hostRule())
	}
	fake.set([]model.Service{disk(95)}, nil)
	if s := poll(); s.State != eval.Crit {
		t.Fatalf("erneut 95 %%: %s", s.State)
	}
	// bestaetigt bei 85 % (Warnung), dann schlechter: Ausnahme erledigt, meldet wieder
	fake.set([]model.Service{disk(85)}, nil)
	poll()
	if c := accept("change"); c != 200 {
		t.Fatalf("accept 85: %d", c)
	}
	if s := poll(); s.State != eval.OK {
		t.Fatalf("85 bestaetigt: %s", s.State)
	}
	fake.set([]model.Service{disk(95)}, nil)
	if s := poll(); s.State != eval.Crit || hostRule() != "" {
		t.Fatalf("schlechter: %s %q", s.State, hostRule())
	}
	// dauerhaft: Warnung und Kritisch aus, auch bei 100 %
	if c := accept("always"); c != 200 || !strings.Contains(hostRule(), `"crit":"off"`) {
		t.Fatalf("accept always: %d %q", c, hostRule())
	}
	fake.set([]model.Service{disk(100)}, nil)
	if s := poll(); s.State != eval.OK {
		t.Fatalf("dauerhaft: %s", s.State)
	}
	// aufheben
	if c := accept(""); c != 200 || hostRule() != "" {
		t.Fatalf("aufheben: %d %q", c, hostRule())
	}
	if s := poll(); s.State != eval.Crit {
		t.Fatalf("nach dem Aufheben: %s", s.State)
	}
}

// "In Ordnung, bis der Wert schlechter wird" endet auch nahe 100 % und im Modus "GB frei" (Vergleich in der Einheit
// der Schwellen; at bleibt wie gespeichert "belegt in %").
func TestAcceptWorseUnits(t *testing.T) {
	used := eval.Effective{Dir: eval.Up, Hyst: eval.DefaultHyst, Warn: eval.Limit{V: 80}, Crit: eval.Limit{V: 90}}
	fs := func(v float64) model.Metric {
		return model.Metric{Name: "used", Value: v, Unit: "%", Rule: model.RuleFS, Max: 4000e9}
	}
	for _, c := range []struct {
		at, v float64
		want  bool
	}{
		{90, 91, false}, {90, 92.5, true}, // Spielraum 2 Prozentpunkte
		{99, 99.4, false}, {99, 100, true}, // nahe 100 %: hoechstens die Haelfte des Rests
		{98.6, 100, true},
	} {
		if got := acceptWorse(used, c.at, fs(c.v)); got != c.want {
			t.Errorf("belegt %%: at %v, Wert %v: %v", c.at, c.v, got)
		}
	}
	// SSD-Verschleiss ueber 100 % moeglich: bei 100 % bleibt der volle Spielraum
	wear := func(v float64) model.Metric {
		return model.Metric{Name: "wear", Value: v, Unit: "%", Rule: model.RuleWear}
	}
	if acceptWorse(used, 100, wear(101)) || !acceptWorse(used, 100, wear(103)) {
		t.Error("Verschleiss 100 %")
	}
	// Druckerfarbe (unten): nahe 0 % ebenso
	down := eval.Effective{Dir: eval.Down, Hyst: eval.DefaultHyst, Warn: eval.Limit{V: 15}, Crit: eval.Limit{V: 5}}
	toner := func(v float64) model.Metric {
		return model.Metric{Name: "level", Value: v, Unit: "%", Rule: model.RulePrinterSupply}
	}
	if acceptWorse(down, 1, toner(0.6)) || !acceptWorse(down, 1, toner(0)) {
		t.Error("Toner nahe 0 %")
	}
	// GB frei (4 TB, Warnung 50 GB frei, geerbte Hysterese 2 GB): 99 % belegt = 40 GB frei
	free := eval.Effective{Dir: eval.Up, Hyst: eval.DefaultHyst, Mode: eval.ModeFree, WarnFree: eval.Limit{V: 50}, CritFree: eval.Limit{V: 20},
		Origin: map[string]eval.Stage{eval.FieldMode: eval.StageService}}
	if acceptWorse(free, 99, fs(99.04)) { // 1,6 GB weniger frei: im Spielraum (2 GB)
		t.Error("GB frei: innerhalb des Spielraums beendet")
	}
	if !acceptWorse(free, 99, fs(99.1)) { // 4 GB weniger frei
		t.Error("GB frei: schlechterer Wert beendet die Ausnahme nicht")
	}
	if acceptWorse(free, 99, fs(90)) { // mehr frei
		t.Error("GB frei: mehr frei beendet die Ausnahme")
	}
}
