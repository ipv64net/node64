package monitor64

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/notify"
)

// fakeCol liefert vorgegebene Dienste bzw. einen Fehler (Regressionstests aus dem Review).
type fakeCol struct {
	mu   sync.Mutex
	svcs []model.Service
	err  error
}

func (f *fakeCol) collect(context.Context) ([]model.Service, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]model.Service(nil), f.svcs...)
	return out, f.err
}
func (f *fakeCol) close() {}
func (f *fakeCol) set(svcs []model.Service, err error) {
	f.mu.Lock()
	f.svcs, f.err = svcs, err
	f.mu.Unlock()
}

// hostWithFake legt einen Host an, plant ihn ein und ersetzt seine Zugaenge durch fake.
func hostWithFake(t *testing.T, m *Module, fake *fakeCol) *hostRT {
	t.Helper()
	ctx := context.Background()
	h := &Host{Name: "h1", Address: "192.0.2.1", IntervalSec: 60}
	if err := m.store.SaveHost(ctx, h, SystemActor); err != nil {
		t.Fatal(err)
	}
	m.ReloadHost(ctx, h.UID)
	m.rtMu.Lock()
	rt := m.rts[h.UID]
	m.rtMu.Unlock()
	rt.accs = []*accRT{{row: &Access{UID: "acc1", HostUID: h.UID, Type: "pve", Enabled: true}, col: fake}}
	return rt
}

func svc(key, kind string, metrics ...model.Metric) model.Service {
	return model.Service{Key: key, Name: key, Kind: kind, Default: true, Metrics: metrics}
}

func adoptAll(t *testing.T, m *Module, hostUID string) {
	t.Helper()
	rows, _ := m.store.Services(context.Background(), hostUID)
	for _, r := range rows {
		_ = m.store.SetAdopted(context.Background(), hostUID, r.Key, 1, SystemActor)
	}
}

func vanished(t *testing.T, m *Module, hostUID, key string) bool {
	t.Helper()
	rows, _ := m.store.Services(context.Background(), hostUID)
	for _, r := range rows {
		if r.Key == key {
			return !r.VanishedAt.IsZero()
		}
	}
	t.Fatalf("service %s missing", key)
	return false
}

func TestVanishedNeedsRoundsPartialAndClears(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	cpu := model.Metric{Name: "util", Value: 10, Unit: "%", Rule: model.RuleCPU}
	fake := &fakeCol{svcs: []model.Service{svc("cpu", "cpu", cpu), svc("vm:101", "vm")}}
	rt := hostWithFake(t, m, fake)
	uid := rt.host.UID
	m.poll(ctx, rt)
	adoptAll(t, m, uid)
	m.poll(ctx, rt)

	// Teilfehler: vm:101 fehlt, der Zugang antwortet nur teilweise -> nie "verschwunden"
	fake.set([]model.Service{svc("cpu", "cpu", cpu)}, errors.New("qemu: timeout"))
	for i := 0; i < 5; i++ {
		m.poll(ctx, rt)
	}
	if vanished(t, m, uid, "vm:101") {
		t.Fatal("partial error marked service as vanished")
	}
	// vollstaendige Antwort ohne vm:101: erst nach vanishRounds Runden
	fake.set([]model.Service{svc("cpu", "cpu", cpu)}, nil)
	for i := 0; i < vanishRounds-1; i++ {
		m.poll(ctx, rt)
	}
	if vanished(t, m, uid, "vm:101") {
		t.Fatal("vanished too early")
	}
	m.poll(ctx, rt)
	if !vanished(t, m, uid, "vm:101") {
		t.Fatal("not vanished after rounds")
	}
	// wieder geliefert: sofort zurueck (nicht erst bei der stuendlichen Erkennung)
	fake.set([]model.Service{svc("cpu", "cpu", cpu), svc("vm:101", "vm")}, nil)
	m.poll(ctx, rt)
	if vanished(t, m, uid, "vm:101") {
		t.Fatal("vanished not cleared when delivered again")
	}
}

func TestMissingMetricKeepsStateUntilUnknown(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	hot := model.Metric{Name: "util", Value: 99, Unit: "%", Rule: model.RuleCPU}
	fake := &fakeCol{svcs: []model.Service{svc("cpu", "cpu", hot)}}
	rt := hostWithFake(t, m, fake)
	uid := rt.host.UID
	m.poll(ctx, rt)
	adoptAll(t, m, uid)
	// CPU-Dauer 15 min: Tracker direkt auf Kritisch setzen (wie nach 15 min ueber 95 %)
	m.poll(ctx, rt)
	tr := rt.Trackers["cpu|util"]
	if tr == nil {
		t.Fatal("no tracker")
	}
	tr.Level, tr.Changed = eval.Crit, time.Now().Add(-time.Hour)
	tr.WarnSince, tr.CritSince = time.Now().Add(-time.Hour), time.Now().Add(-time.Hour)
	m.poll(ctx, rt)
	if st := svcState(rt, "cpu"); st != eval.Crit {
		t.Fatalf("expected crit, got %v", st)
	}
	// Dienst kommt ohne die Messgroesse (z. B. erste Runde nach Neuladen, keine Rate): bleibt Kritisch
	fake.set([]model.Service{svc("cpu", "cpu")}, nil)
	m.poll(ctx, rt)
	if st := svcState(rt, "cpu"); st != eval.Crit {
		t.Fatalf("missing metric must keep last state, got %v", st)
	}
	if len(m.loadOpen(ctx, uid)) == 0 {
		t.Fatal("problem closed although metric only missing")
	}
}

func svcState(rt *hostRT, key string) eval.State {
	for _, s := range rt.getView().Services {
		if s.Key == key {
			return s.State
		}
	}
	return eval.Unknown
}

func TestDispatchDefaultAndExplicitChannels(t *testing.T) {
	m, alerts, mu := newTestModule(t)
	h := &Host{UID: "h1", Name: "nas01"}
	msg := eval.Message{At: time.Now(), Event: eval.EvProblem, Severity: eval.Crit, Channels: []string{"7", defaultChannels},
		Lines: []eval.Line{{Kind: eval.LineProblem, Key: "fs:/", Name: "fs", State: eval.Crit}}}
	m.dispatch(context.Background(), h, msg, "")
	mu.Lock()
	defer mu.Unlock()
	if len(*alerts) != 2 {
		t.Fatalf("want 2 alerts (default + explicit), got %d", len(*alerts))
	}
	var gotDefault, gotSeven bool
	for _, a := range *alerts {
		if a.Check.Channels == nil {
			gotDefault = true
		}
		if len(a.Check.Channels) == 1 && a.Check.Channels[0] == 7 {
			gotSeven = true
		}
		if a.Kind != notify.KindMonitorProblem || a.Data["key"] != "fs:/" {
			t.Fatalf("alert %+v", a)
		}
	}
	if !gotDefault || !gotSeven {
		t.Fatalf("default=%v seven=%v", gotDefault, gotSeven)
	}
}

func TestNonFiniteMetricsDropped(t *testing.T) {
	nan := model.Metric{Name: "l1", Value: 0}
	nan.Value = nan.Value / nan.Value // NaN
	out := finiteMetrics([]model.Metric{{Name: "ok", Value: 1}, nan})
	if len(out) != 1 || out[0].Name != "ok" {
		t.Fatalf("got %+v", out)
	}
}
