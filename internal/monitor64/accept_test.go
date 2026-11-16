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
