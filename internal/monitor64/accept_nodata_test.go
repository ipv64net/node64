package monitor64

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// #272: "In Ordnung, bis sich der Zustand aendert" an einem Port ohne Link bleibt, wenn dazwischen Runden ohne Daten
// liegen - Zugang nicht erreichbar (HTTP 502) bzw. Dienst ohne Daten (UniFi-Switch laut Controller offline). Vorher
// down und hinterher down ist keine Aenderung; erst Link beendet die Ausnahme.
func TestAcceptStateSurvivesNoData(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	const key = "port:fc:ec:da:11:22:33:4"
	down := model.Service{Key: key, Name: "Switch · Port 4", Kind: "if", Text: "down", Facts: []model.Fact{{Code: "if_down", Text: "Switch Port 4 ohne Link"}}}
	offline := model.Service{Key: key, Name: "Switch · Port 4", Kind: "if", Text: "Gerät nicht verbunden", Facts: []model.Fact{{Code: model.FactNoData}}}
	up := model.Service{Key: key, Name: "Switch · Port 4", Kind: "if", Text: "1 Gbit/s"}
	fake := &fakeCol{svcs: []model.Service{down}}
	rt := hostWithFake(t, e.m, fake)
	uid := rt.host.UID
	poll := func() SvcView {
		t.Helper()
		e.m.poll(ctx, rt)
		for _, s := range rt.getView().Services {
			if s.Key == key {
				return s
			}
		}
		t.Fatal("Dienst fehlt")
		return SvcView{}
	}
	hostRule := func() string {
		return e.col(`SELECT host_rule FROM m64_services WHERE host_uid = ? AND key = ?`, uid, key)
	}
	e.m.poll(ctx, rt)
	adoptAll(t, e.m, uid)
	if s := poll(); s.State != eval.Warn {
		t.Fatalf("ohne Link: %s", s.State)
	}
	if c := e.do("PUT", "/api/monitor64/hosts/"+uid+"/service", map[string]any{"key": key, "accept": map[string]any{"kind": eval.KindIfDown, "mode": "change"}}).Code; c != 200 {
		t.Fatalf("accept change: %d", c)
	}
	if s := poll(); s.State != eval.OK || !slices.Contains(s.Accepted, eval.KindIfDown) {
		t.Fatalf("bestaetigt: %s %v", s.State, s.Accepted)
	}
	// Controller nicht erreichbar, danach Switch offline (Ports ohne Daten): Ausnahme bleibt
	fake.set(nil, errors.New("UniFi: HTTP 502 (Bad Gateway)"))
	e.m.poll(ctx, rt)
	if !strings.Contains(hostRule(), "accepted") {
		t.Fatalf("nach Runde ohne Zugang: %q", hostRule())
	}
	fake.set([]model.Service{offline}, nil)
	for range 2 {
		if s := poll(); s.State != eval.OK || !strings.Contains(hostRule(), "accepted") {
			t.Fatalf("Switch offline: %s %q", s.State, hostRule())
		}
	}
	// wieder online, Port weiter ohne Link: keine Aenderung, keine Meldung
	fake.set([]model.Service{down}, nil)
	for range 3 {
		if s := poll(); s.State != eval.OK || !slices.Contains(s.Accepted, eval.KindIfDown) || len(s.Firing) != 0 {
			t.Fatalf("wieder online, weiter down: %s %v %v", s.State, s.Accepted, s.Firing)
		}
	}
	if len(e.m.loadOpen(ctx, uid)) != 0 {
		t.Fatal("Problem offen trotz bestaetigtem Zustand")
	}
	// Link: Ausnahme erledigt, der naechste Ausfall meldet wieder
	fake.set([]model.Service{up}, nil)
	if s := poll(); len(s.Accepted) != 0 || strings.Contains(hostRule(), "accepted") {
		t.Fatalf("mit Link: %v %q", s.Accepted, hostRule())
	}
	fake.set([]model.Service{down}, nil)
	if s := poll(); s.State != eval.Warn {
		t.Fatalf("erneuter Ausfall: %s", s.State)
	}
}
