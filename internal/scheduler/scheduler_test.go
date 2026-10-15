package scheduler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/checks"
)

// scripted liefert vorgegebene Ergebnisse, das letzte wiederholt sich.
type scripted struct {
	mu  sync.Mutex
	seq []checks.Status
	i   int
}

func (s *scripted) Type() checks.Type { return checks.TypeHTTP }
func (s *scripted) Check(_ context.Context, _ checks.Definition, _ net.IP) checks.Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.seq[min(s.i, len(s.seq)-1)]
	s.i++
	if st == checks.Up {
		return checks.Result{Status: checks.Up, Reason: checks.ReasonOK, Message: "ok", Latency: 5 * time.Millisecond}
	}
	return checks.Result{Status: checks.Down, Reason: checks.ReasonStatusMismatch, Message: "HTTP 500"}
}
func (s *scripted) set(seq ...checks.Status) { s.mu.Lock(); s.seq = seq; s.i = 0; s.mu.Unlock() }

type localResolver struct{}

func (localResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
}

// memStore sammelt alles im Speicher.
type memStore struct {
	mu           sync.Mutex
	measurements []Measurement
	events       []Event
	runtime      map[string]Runtime
	incidents    map[int64]bool
	maintenance  bool
	nextID       int64
}

func newMemStore() *memStore {
	return &memStore{runtime: map[string]Runtime{}, incidents: map[int64]bool{}}
}
func (m *memStore) SaveMeasurement(_ context.Context, x Measurement) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.measurements = append(m.measurements, x)
	return nil
}
func (m *memStore) SaveRuntime(_ context.Context, t string, rt Runtime) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runtime[t] = rt
	return nil
}
func (m *memStore) OpenIncident(context.Context, string, time.Time, checks.Reason, string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	m.incidents[m.nextID] = true
	return m.nextID, nil
}
func (m *memStore) CloseIncident(_ context.Context, id int64, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.incidents[id] = false
	return nil
}
func (m *memStore) SaveEvent(_ context.Context, e Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	return nil
}
func (m *memStore) InMaintenance(context.Context, string, time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.maintenance
}
func (m *memStore) count(token string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, x := range m.measurements {
		if x.Token == token {
			n++
		}
	}
	return n
}
func (m *memStore) kinds(token string) []EventKind {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []EventKind
	for _, e := range m.events {
		if e.Token == token {
			out = append(out, e.Kind)
		}
	}
	return out
}

type memNotifier struct {
	mu     sync.Mutex
	events []Event
}

func (n *memNotifier) Notify(_ context.Context, e Event, _ Check) {
	n.mu.Lock()
	n.events = append(n.events, e)
	n.mu.Unlock()
}
func (n *memNotifier) loud() []Event {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []Event
	for _, e := range n.events {
		if !e.Silent {
			out = append(out, e)
		}
	}
	return out
}

func newTestScheduler(t *testing.T, fake *scripted, opts Options) (*Scheduler, *memStore, *memNotifier) {
	t.Helper()
	r := checks.NewRunner()
	r.Resolver = localResolver{}
	r.Register(fake)
	st := newMemStore()
	n := &memNotifier{}
	if opts.Workers == 0 {
		opts.Workers = 4
	}
	s := New(st, n, r, slog.New(slog.NewTextHandler(io.Discard, nil)), opts)
	t.Cleanup(s.Stop)
	return s, st, n
}

func httpCheck(token string, retries, stabilize int) Check {
	return Check{Token: token, Name: token, Def: checks.Definition{Token: token, Type: checks.TypeHTTP, Target: "http://localhost/", Timeouts: checks.Timeouts{Connect: time.Second, Total: time.Second}},
		Interval: 30 * time.Millisecond, RetryInterval: 10 * time.Millisecond, Retries: retries, Stabilize: stabilize}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestRetriesDownStabilizeUp(t *testing.T) {
	fake := &scripted{seq: []checks.Status{checks.Up, checks.Down, checks.Down, checks.Down, checks.Up, checks.Up, checks.Up}}
	s, st, n := newTestScheduler(t, fake, Options{})
	s.Upsert(httpCheck("a", 2, 2), nil)
	s.Start(context.Background())
	waitFor(t, func() bool { return st.count("a") >= 7 }, "7 measurements")
	rt, _ := s.Runtime("a")
	if rt.State != StateUp {
		t.Fatalf("state = %s, want up", rt.State)
	}
	kinds := st.kinds("a")
	want := []EventKind{EventUp, EventDown, "stabilizing", EventUp}
	if len(kinds) != len(want) {
		t.Fatalf("events = %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("events = %v, want %v", kinds, want)
		}
	}
	loud := n.loud()
	if len(loud) != 2 || loud[0].Kind != EventDown || loud[1].Kind != EventUp || loud[1].Duration <= 0 || loud[1].Incident == 0 {
		t.Fatalf("notifications: %+v", loud)
	}
	if st.incidents[loud[0].Incident] {
		t.Fatal("incident should be closed")
	}
	// Retry-Intervall solange gestoert: die zweite Messung kam schnell
	st.mu.Lock()
	m := st.measurements
	st.mu.Unlock()
	if m[1].Status != checks.Down || m[3].Status != checks.Down {
		t.Fatal("measurements must be stored even during retries")
	}
}

func TestStabilizingFallsBackWithoutAlarm(t *testing.T) {
	fake := &scripted{seq: []checks.Status{checks.Down, checks.Up, checks.Down, checks.Up, checks.Up, checks.Up}}
	s, st, n := newTestScheduler(t, fake, Options{})
	s.Upsert(httpCheck("b", 0, 3), nil)
	s.Start(context.Background())
	waitFor(t, func() bool {
		rt, _ := s.Runtime("b")
		return rt.State == StateUp
	}, "up after stabilization")
	kinds := st.kinds("b")
	// down, stabilizing, unstable (zurueck auf down), stabilizing, up
	if len(kinds) != 5 || kinds[2] != "unstable" || kinds[4] != EventUp {
		t.Fatalf("events = %v", kinds)
	}
	if loud := n.loud(); len(loud) != 2 {
		t.Fatalf("expected exactly one down and one up notification, got %+v", loud)
	}
}

func TestFlapping(t *testing.T) {
	fake := &scripted{seq: []checks.Status{checks.Up, checks.Down, checks.Up, checks.Down, checks.Up, checks.Up, checks.Up, checks.Up, checks.Up, checks.Up}}
	s, st, n := newTestScheduler(t, fake, Options{FlapThreshold: 2, FlapWindow: time.Hour, FlapCalm: 80 * time.Millisecond})
	s.Upsert(httpCheck("c", 0, 1), nil)
	s.Start(context.Background())
	waitFor(t, func() bool {
		rt, _ := s.Runtime("c")
		return rt.State == StateFlapping
	}, "flapping")
	waitFor(t, func() bool {
		rt, _ := s.Runtime("c")
		return rt.State == StateUp
	}, "calm again")
	kinds := st.kinds("c")
	var start, end bool
	for _, k := range kinds {
		if k == EventFlappingStart {
			start = true
		}
		if k == EventFlappingEnd {
			end = true
		}
	}
	if !start || !end {
		t.Fatalf("expected flapping start and end, got %v", kinds)
	}
	loud := n.loud()
	var starts int
	for _, e := range loud {
		if e.Kind == EventFlappingStart && e.Flaps < 3 {
			t.Fatalf("flap count: %+v", e)
		}
		if e.Kind == EventFlappingStart {
			starts++
		}
	}
	if starts != 1 {
		t.Fatalf("expected one flapping notification, got %+v", loud)
	}
}

func TestDependency(t *testing.T) {
	parent := &scripted{seq: []checks.Status{checks.Down}}
	// Beide Checks nutzen denselben Typ; fuer das Kind einen eigenen Runner-Trick:
	// Kind-Ergebnisse haengen am selben Fake. Reihenfolge der Aufrufe ist nicht
	// deterministisch, daher liefert der Fake fuer alle down.
	s, st, n := newTestScheduler(t, parent, Options{})
	p := httpCheck("p", 0, 1)
	c := httpCheck("k", 0, 1)
	c.Parent = "p"
	s.Upsert(p, nil)
	s.Start(context.Background())
	waitFor(t, func() bool {
		rp, _ := s.Runtime("p")
		return rp.State == StateDown
	}, "parent down")
	s.Upsert(c, nil)
	waitFor(t, func() bool {
		rk, _ := s.Runtime("k")
		return rk.State == StateDependent
	}, "child dependent")
	for _, e := range n.loud() {
		if e.Token == "k" {
			t.Fatalf("child must not alarm while parent is down: %+v", e)
		}
	}
	st.mu.Lock()
	var dep bool
	for _, m := range st.measurements {
		if m.Token == "k" && m.Dependent {
			dep = true
		}
	}
	st.mu.Unlock()
	if !dep {
		t.Fatal("child measurements should be flagged dependent")
	}
	// Erholung: alles up, Kind durchlaeuft Stabilisierung (stabilize 1 = direkt up)
	parent.set(checks.Up)
	waitFor(t, func() bool {
		rp, _ := s.Runtime("p")
		rk, _ := s.Runtime("k")
		return rp.State == StateUp && rk.State == StateUp
	}, "recovery")
}

func TestMaintenanceSilences(t *testing.T) {
	fake := &scripted{seq: []checks.Status{checks.Down}}
	s, st, n := newTestScheduler(t, fake, Options{})
	st.maintenance = true
	s.Upsert(httpCheck("m", 0, 1), nil)
	s.Start(context.Background())
	waitFor(t, func() bool { return len(st.kinds("m")) >= 1 }, "down event")
	if loud := n.loud(); len(loud) != 0 {
		t.Fatalf("no notification during maintenance, got %+v", loud)
	}
	st.mu.Lock()
	ev := st.events[0]
	m := st.measurements[0]
	st.mu.Unlock()
	if !ev.Maintenance || !m.Maintenance {
		t.Fatal("event and measurement must be flagged maintenance")
	}
}

func TestInvertAndPause(t *testing.T) {
	fake := &scripted{seq: []checks.Status{checks.Down}}
	s, st, _ := newTestScheduler(t, fake, Options{})
	c := httpCheck("i", 0, 1)
	c.Invert = true
	s.Upsert(c, nil)
	pc := httpCheck("z", 0, 1)
	pc.Paused = true
	s.Upsert(pc, nil)
	s.Start(context.Background())
	waitFor(t, func() bool {
		rt, _ := s.Runtime("i")
		return rt.State == StateUp
	}, "inverted up")
	time.Sleep(60 * time.Millisecond)
	if st.count("z") != 0 {
		t.Fatal("paused check must not run")
	}
	if rt, _ := s.Runtime("z"); rt.State != StatePaused {
		t.Fatalf("paused state: %s", rt.State)
	}
	// Entpausen per Upsert
	pc.Paused = false
	s.Upsert(pc, nil)
	waitFor(t, func() bool { return st.count("z") > 0 }, "resumed check runs")
	s.Remove("z")
	if _, ok := s.Runtime("z"); ok {
		t.Fatal("removed check still present")
	}
}

func TestPushWatchdog(t *testing.T) {
	fake := &scripted{seq: []checks.Status{checks.Up}}
	s, st, n := newTestScheduler(t, fake, Options{})
	params, _ := json.Marshal(map[string]int{"period_seconds": 1, "grace_seconds": 0})
	c := Check{Token: "push", Name: "push", Def: checks.Definition{Token: "push", Type: checks.TypePush, Params: params}, Stabilize: 1}
	s.Upsert(c, nil)
	s.Start(context.Background())
	if !s.Push(context.Background(), "push", "", "", nil) {
		t.Fatal("push should be accepted")
	}
	waitFor(t, func() bool {
		rt, _ := s.Runtime("push")
		return rt.State == StateUp
	}, "up after push")
	// Keine weitere Meldung: nach period+grace (1 s, Kulanz 0 → Standard 600 s? nein: grace 0 explizit) down
	waitFor(t, func() bool {
		rt, _ := s.Runtime("push")
		return rt.State == StateDown
	}, "down after missing push")
	// der Alarm folgt dem Zustandswechsel (unter Last etwas spaeter): darauf warten statt sofort zu lesen
	waitFor(t, func() bool {
		loud := n.loud()
		return len(loud) > 0 && loud[len(loud)-1].Kind == EventDown && loud[len(loud)-1].Reason == checks.ReasonPushMissing
	}, "push_missing alarm")
	if !s.Push(context.Background(), "push", checks.Up, "", nil) {
		t.Fatal("push")
	}
	waitFor(t, func() bool {
		rt, _ := s.Runtime("push")
		return rt.State == StateUp
	}, "up again")
	if st.count("push") < 3 {
		t.Fatalf("expected at least 3 measurements, got %d", st.count("push"))
	}
	if s.Push(context.Background(), "unknown", "", "", nil) {
		t.Fatal("unknown token must be rejected")
	}
}

func TestCombineBothFamilies(t *testing.T) {
	c := Check{Token: "x"}
	res := []checks.Result{
		{Status: checks.Up, Family: "ipv4", Latency: 10 * time.Millisecond, Message: "ok", Details: map[string]any{"ip": "1.1.1.1"}},
		{Status: checks.Down, Family: "ipv6", Reason: checks.ReasonTimeout, Latency: 2 * time.Second, Message: "timeout", Details: map[string]any{"ip": "::1"}},
	}
	m := combine(c, res, time.Now())
	if m.Status != checks.Down || m.Reason != checks.ReasonTimeout || m.Latency != 2*time.Second || m.Details["ipv6"] == nil {
		t.Fatalf("combine: %+v", m)
	}
	c.Invert = true
	if m := combine(c, res, time.Now()); m.Status != checks.Up {
		t.Fatalf("invert: %+v", m)
	}
}
