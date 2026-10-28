package sonar

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testToken  = "s64_0123456789abcdefghijABCDEFGHIJ0123456789"
	testNodeID = "nabc123def45"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeProber misst nichts, merkt sich die Ziele.
type fakeProber struct {
	mu     sync.Mutex
	pings  []Target
	traces []Target
	lossTo map[string]bool
	noICMP bool
}

func (f *fakeProber) Ping(_ context.Context, t Target, round time.Time) Result {
	f.mu.Lock()
	f.pings = append(f.pings, t)
	loss := f.lossTo[t.ID]
	f.mu.Unlock()
	r := Result{Sent: t.Count, Recv: t.Count, MinMs: 1, AvgMs: 2, MaxMs: 3, JitterMs: 0.5, At: time.Now()}
	if loss {
		r.Recv, r.MinMs, r.AvgMs, r.MaxMs = 0, 0, 0, 0
	}
	return r
}

func (f *fakeProber) Trace(_ context.Context, t Target, round time.Time) Result {
	f.mu.Lock()
	f.traces = append(f.traces, t)
	f.mu.Unlock()
	return Result{Sent: 3, Recv: 3, Hops: []Hop{{TTL: 1, Addr: "192.168.1.1", RTTMs: 1}, {TTL: 2, Addr: "80.1.2.3", RTTMs: 4}}}
}

func (f *fakeProber) ICMPAllowed() bool { return !f.noICMP }

func (f *fakeProber) all() []Target {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append(append([]Target(nil), f.pings...), f.traces...)
}

// fakeAPI spielt ipv64 (API v2 /sonar/*).
type fakeAPI struct {
	t        *testing.T
	mu       sync.Mutex
	planKey  ed25519.PrivateKey
	nodePub  ed25519.PublicKey
	nodeID   string
	plan     []byte // roh, wird signiert
	tmpl     *Plan
	tmplAt   time.Time
	planSig  string // leer = korrekt signieren
	planCode int    // 0 = 200
	etag     string
	inm      []string
	planGets int
	regs     int
	reports  []Report
	results  int // Status fuer /results (0 = 200)
	me       Me
	puts     []meWrite
	rawPuts  []string
	since    []string
	token    string   // leer = testToken
	revoked  int      // 401 = invalid_token, 403 = node_disabled auf allen Token-Pfaden
	calls    []string // "METHOD /pfad"
	delCode  int      // Status fuer DELETE /sonar/me (0 = 204)
	srv      *httptest.Server
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{t: t, nodeID: testNodeID, etag: `"abc123"`}
	_, f.planKey, _ = ed25519.GenerateKey(nil)
	f.me = Me{NodeID: testNodeID, Name: "Sonar-Test-1", Budget: BudgetLow}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) pub() string {
	return base64.StdEncoding.EncodeToString(f.planKey.Public().(ed25519.PublicKey))
}

func data(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"data": v})
}

func (f *fakeAPI) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	tok := f.token
	if tok == "" {
		tok = testToken
	}
	if r.URL.Path != "/sonar/tokens" && r.Header.Get("Authorization") != "Bearer "+tok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if f.revoked != 0 && r.URL.Path != "/sonar/tokens" {
		code := "invalid_token"
		if f.revoked == http.StatusForbidden {
			code = "node_disabled"
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(f.revoked)
		io.WriteString(w, `{"title":"x","status":`+itoa(f.revoked)+`,"detail":"revoked","code":"`+code+`"}`)
		return
	}
	switch r.URL.Path {
	case "/sonar/register":
		var reg Register
		json.NewDecoder(r.Body).Decode(&reg)
		b, _ := base64.StdEncoding.DecodeString(reg.PubKey)
		f.nodePub = b
		f.regs++
		data(w, Me{NodeID: f.nodeID})
	case "/sonar/me":
		if r.Method == http.MethodDelete {
			code := f.delCode
			if code == 0 {
				code = http.StatusNoContent
			}
			w.WriteHeader(code)
			return
		}
		if r.Method == http.MethodPut {
			var m meWrite
			b, _ := io.ReadAll(r.Body)
			json.Unmarshal(b, &m)
			f.puts = append(f.puts, m)
			f.rawPuts = append(f.rawPuts, string(b))
			f.me.Measured, f.me.Budget = m.Measured, m.Budget
		}
		data(w, f.me)
	case "/sonar/plan":
		f.planGets++
		f.inm = append(f.inm, r.Header.Get("If-None-Match"))
		f.buildPlan()
		if f.planCode != 0 {
			w.WriteHeader(f.planCode)
			return
		}
		if f.plan == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Header.Get("If-None-Match") == f.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		sig := f.planSig
		if sig == "" {
			sig = signRaw(f.planKey, f.plan)
		}
		w.Header().Set("ETag", f.etag)
		// Plan roh einbetten (exakte Bytes)
		io.WriteString(w, `{"data":{"plan":`+string(f.plan)+`,"kid":"abcdefgh","sig":"`+sig+`"}}`)
	case "/sonar/results":
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if len(body) > 256<<10 {
			f.t.Errorf("report body too large: %d", len(body))
		}
		var sr SignedReport
		if err := json.Unmarshal(body, &sr); err != nil {
			f.t.Errorf("report not JSON: %v", err)
			return
		}
		sig, _ := base64.StdEncoding.DecodeString(sr.Sig)
		if !ed25519.Verify(f.nodePub, sr.Report, sig) {
			f.t.Errorf("report signature invalid")
		}
		var rep Report
		json.Unmarshal(sr.Report, &rep)
		if n := len(f.reports); n > 0 && rep.Seq <= f.reports[n-1].Seq {
			f.t.Errorf("seq not increasing: %d after %d", rep.Seq, f.reports[n-1].Seq)
		}
		if f.results != 0 {
			w.WriteHeader(f.results)
			return
		}
		f.reports = append(f.reports, rep)
		data(w, map[string]any{"accepted": len(rep.Results), "rejected": 0, "reasons": map[string]int{}})
	case "/sonar/inbound":
		f.since = append(f.since, r.URL.Query().Get("since"))
		data(w, []InboundRow{{From: "nzzz000000aa", Name: "X", Family: 4, Method: "udp", AvgMs: 9}})
	case "/sonar/tokens":
		if r.Header.Get("Authorization") != "Bearer KEY0123456789abcdef" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		data(w, map[string]any{"id": 7, "token": testToken})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// setPlan legt den Plan fest; beim Abruf werden alle Zeiten um die seitdem vergangene Zeit verschoben (Tests
// haengen so nicht von der Dauer der Anmeldung ab).
func (f *fakeAPI) setPlan(p Plan) {
	f.mu.Lock()
	f.tmpl, f.tmplAt = &p, time.Now()
	f.mu.Unlock()
}

// buildPlan erzeugt die Plan-Bytes beim Abruf. f.mu gehalten.
func (f *fakeAPI) buildPlan() {
	if f.tmpl == nil {
		return
	}
	d := time.Since(f.tmplAt)
	p := *f.tmpl
	f.tmpl = nil
	p.Issued, p.Expires = p.Issued.Add(d), p.Expires.Add(d)
	p.Rounds = append([]Round(nil), p.Rounds...)
	for i := range p.Rounds {
		p.Rounds[i].Start = p.Rounds[i].Start.Add(d)
	}
	b, _ := json.Marshal(p)
	f.plan = []byte(strings.Replace(string(b), `"v":1,`, `"v": 1 ,`, 1))
}

func (f *fakeAPI) snapshot() (reports []Report, regs, gets int, inm []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Report(nil), f.reports...), f.regs, f.planGets, append([]string(nil), f.inm...)
}

// newTestRunner baut einen Runner mit kurzen Zeiten.
func newTestRunner(t *testing.T, f *fakeAPI, dir string, p Prober, mod func(*Config)) *Runner {
	t.Helper()
	cfg := Config{APIBase: f.srv.URL, Token: testToken, DataDir: dir, Mode: ModeHeadless, Version: "test",
		Log: quietLog(), Prober: p, PlanKeys: []string{f.pub()}, HTTPClient: f.srv.Client()}
	if mod != nil {
		mod(&cfg)
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.roundLen = time.Second
	r.planEvery = time.Hour
	r.reportEvery = 150 * time.Millisecond
	r.reportGap = 20 * time.Millisecond
	r.retryMin = 30 * time.Millisecond
	r.revokedEvery = 150 * time.Millisecond
	r.tick = 10 * time.Millisecond
	r.bucket = newBucket(1000, time.Now) // nur Tests: schneller als 2/s
	return r
}

func runFor(t *testing.T, r *Runner, cond func() bool, max time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()
	deadline := time.Now().Add(max)
	for !cond() {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("condition not reached in %v; status %+v", max, r.Status())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not end with ctx")
	}
}

func publicTargets(n int, method string, count int) []Target {
	var ts []Target
	for i := range n {
		ts = append(ts, Target{ID: "n" + pad11(i+1), Addr: "1.1.1." + itoa(i+1), Family: 4, Method: method, Count: count})
	}
	return ts
}

func testPlan(rounds ...Round) Plan {
	now := time.Now().UTC()
	return Plan{V: 1, NodeID: testNodeID, Issued: now, Expires: now.Add(30 * time.Minute), Rounds: rounds,
		Anchors: []Target{{ID: "a_fsn", Addr: "5.9.1.1", Family: 4, Method: MethodICMP, Count: 3}}}
}

func TestRunnerEndToEnd(t *testing.T) {
	f := newFakeAPI(t)
	ts := publicTargets(12, MethodUDP, 1)
	ts[0].Count = 99
	ts = append([]Target{
		{ID: "nprivate0001", Addr: "10.0.0.1", Family: 4, Method: MethodICMP, Count: 1},
		{ID: "nprivate0002", Addr: "192.168.1.1", Family: 4, Method: MethodICMP, Count: 1},
		{ID: "nprivate0003", Addr: "fe80::1", Family: 6, Method: MethodICMP, Count: 1},
		{ID: "nprivate0004", Addr: "::ffff:127.0.0.1", Family: 6, Method: MethodICMP, Count: 1},
		{ID: testNodeID, Addr: "9.9.9.9", Family: 4, Method: MethodICMP, Count: 1},
	}, ts...)
	f.setPlan(testPlan(Round{Start: time.Now().UTC().Add(-10 * time.Millisecond), Targets: ts}))
	dir := t.TempDir()
	fp := &fakeProber{}
	r := newTestRunner(t, f, dir, fp, nil)
	runFor(t, r, func() bool {
		reps, _, _, _ := f.snapshot()
		n := 0
		for _, x := range reps {
			n += len(x.Results)
		}
		return n >= MaxTargetsLow
	}, 10*time.Second)

	got := fp.all()
	if len(got) != MaxTargetsLow {
		t.Fatalf("expected %d measurements (budget sparsam), got %d", MaxTargetsLow, len(got))
	}
	for _, x := range got {
		if strings.HasPrefix(x.ID, "nprivate") || x.ID == testNodeID || x.Count > MaxCount {
			t.Fatalf("forbidden measurement %+v", x)
		}
	}
	reps, regs, _, _ := f.snapshot()
	if regs != 1 {
		t.Fatalf("registered %d times", regs)
	}
	for _, rep := range reps {
		if rep.NodeID != testNodeID || rep.V != 1 || rep.Health.Version != "test" || rep.Health.Mode != ModeHeadless {
			t.Fatalf("bad report %+v", rep)
		}
		for _, res := range rep.Results {
			if res.Sent < 1 || res.Recv > res.Sent || res.Target == "" {
				t.Fatalf("bad result %+v", res)
			}
		}
	}
	st := r.Status()
	if !st.Registered || st.NodeID != testNodeID || st.PlanIssued.IsZero() || st.SentToday < MaxTargetsLow {
		t.Fatalf("status %+v", st)
	}
	res, _ := r.Recent(3)
	if len(res) != 3 || res[0].At.Before(res[2].At) {
		t.Fatalf("recent %+v", res)
	}
	// Zustand gespeichert, Schluessel 0600
	stt, err := loadState(dir)
	if err != nil || stt.NodeID != testNodeID || stt.Seq == 0 || len(stt.PlanRaw) == 0 {
		t.Fatalf("state %+v %v", stt, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, stateFile))
	if strings.Contains(string(b), testToken) {
		t.Fatal("token in state file")
	}

	// Neustart: keine neue Anmeldung, Seq steigt weiter, gespeicherter Plan mit ETag
	lastSeq := reps[len(reps)-1].Seq
	r2 := newTestRunner(t, f, dir, fp, nil)
	if !r2.Status().Registered || r2.Status().PlanIssued.IsZero() {
		t.Fatalf("restart lost state: %+v", r2.Status())
	}
	runFor(t, r2, func() bool {
		reps, _, gets, _ := f.snapshot()
		return len(reps) > 0 && reps[len(reps)-1].Seq > lastSeq && gets >= 2
	}, 5*time.Second)
	_, regs, _, inm := f.snapshot()
	if regs != 1 {
		t.Fatalf("re-registered after restart (%d)", regs)
	}
	if inm[len(inm)-1] != f.etag {
		t.Fatalf("ETag not sent: %q", inm)
	}
}

func TestRunnerPlanRejectedAndNoPlan(t *testing.T) {
	f := newFakeAPI(t)
	f.setPlan(testPlan(Round{Start: time.Now().UTC(), Targets: publicTargets(3, MethodICMP, 1)}))
	f.planSig = base64.StdEncoding.EncodeToString(make([]byte, 64))
	fp := &fakeProber{}
	r := newTestRunner(t, f, "", fp, nil)
	runFor(t, r, func() bool { return strings.Contains(r.Status().LastError, "plan rejected") }, 5*time.Second)
	if len(fp.all()) != 0 {
		t.Fatal("measured with a forged plan")
	}
	if r.Status().Paused != "no_plan" {
		t.Fatalf("paused %q", r.Status().Paused)
	}

	// 204: kein Plan
	f2 := newFakeAPI(t)
	r2 := newTestRunner(t, f2, "", fp, nil)
	runFor(t, r2, func() bool {
		reps, _, _, _ := f2.snapshot()
		return len(reps) > 0 && reps[0].Health.Paused == "no_plan"
	}, 5*time.Second)
}

func TestRunnerAnchorsOnlyFallback(t *testing.T) {
	f := newFakeAPI(t)
	p := testPlan(Round{Start: time.Now().UTC(), Targets: publicTargets(3, MethodICMP, 1)})
	p.Issued, p.Expires = p.Issued.Add(-40*time.Minute), p.Issued.Add(-10*time.Minute) // abgelaufen, < 2 h
	p.Anchors = append(p.Anchors, Target{ID: "a_nbg", Addr: "2a01:4f8::1", Family: 6, Method: MethodTrace, Count: 1},
		Target{ID: "a_bad", Addr: "127.0.0.1", Family: 4, Method: MethodICMP, Count: 1})
	f.setPlan(p)
	fp := &fakeProber{}
	r := newTestRunner(t, f, "", fp, nil)
	runFor(t, r, func() bool { return len(fp.all()) >= 1 && r.Status().AnchorsOnly }, 5*time.Second)
	for _, x := range fp.all() {
		if x.ID != "a_fsn" {
			t.Fatalf("anchors-only mode measured %+v", x)
		}
	}
}

func TestRunnerSelfBrake(t *testing.T) {
	f := newFakeAPI(t)
	now := time.Now().UTC()
	anchor := Target{ID: "a_fsn", Addr: "5.9.1.1", Family: 4, Method: MethodICMP, Count: 2}
	f.setPlan(testPlan(
		Round{Start: now, Targets: []Target{anchor}},
		Round{Start: now.Add(time.Second), Targets: []Target{anchor}},
		Round{Start: now.Add(2 * time.Second), Targets: []Target{anchor}},
	))
	fp := &fakeProber{lossTo: map[string]bool{"a_fsn": true}}
	r := newTestRunner(t, f, "", fp, nil)
	sawUplink := false
	runFor(t, r, func() bool {
		if r.Status().Paused == "uplink" {
			sawUplink = true
		}
		return len(fp.all()) >= 2
	}, 5*time.Second)
	if !sawUplink {
		t.Fatal("no uplink pause after full loss to anchors")
	}
	if n := len(fp.all()); n != 2 { // Runde 1 misst, Runde 2 Pause, Runde 3 misst
		t.Fatalf("expected 2 measurements, got %d", n)
	}
}

func TestRunnerQuietAndDayLimit(t *testing.T) {
	f := newFakeAPI(t)
	f.setPlan(testPlan(Round{Start: time.Now().UTC(), Targets: publicTargets(3, MethodICMP, 1)}))
	fp := &fakeProber{}
	h := time.Now().Hour()
	r := newTestRunner(t, f, "", fp, func(c *Config) { c.Quiet = [2]int{h, (h + 1) % 24} })
	runFor(t, r, func() bool { return r.Status().Paused == "quiet" }, 5*time.Second)
	if len(fp.all()) != 0 {
		t.Fatal("measured in quiet hours")
	}

	f.setPlan(testPlan(Round{Start: time.Now().UTC(), Targets: publicTargets(3, MethodICMP, 1)}))
	r2 := newTestRunner(t, f, "", fp, nil)
	r2.st.Day, r2.st.SentToday = time.Now().UTC().Format("2006-01-02"), DayLimitLow
	runFor(t, r2, func() bool { return r2.Status().Paused == "budget" }, 5*time.Second)
	if len(fp.all()) != 0 {
		t.Fatal("measured over the day limit")
	}
}

func TestRunnerTraceLimitAndICMPDenied(t *testing.T) {
	f := newFakeAPI(t)
	ts := publicTargets(4, MethodTrace, 1)
	ts = append(ts, Target{ID: "nicmp0000001", Addr: "8.8.8.8", Family: 4, Method: MethodICMP, Count: 1})
	f.setPlan(testPlan(Round{Start: time.Now().UTC(), Targets: ts}))
	fp := &fakeProber{noICMP: true}
	r := newTestRunner(t, f, "", fp, func(c *Config) { c.Budget = BudgetHigh })
	runFor(t, r, func() bool {
		reps, _, _, _ := f.snapshot()
		n := 0
		for _, x := range reps {
			n += len(x.Results)
		}
		return n >= 5
	}, 5*time.Second)
	fp.mu.Lock()
	nt, np := len(fp.traces), len(fp.pings)
	fp.mu.Unlock()
	if nt != MaxTracesPerHour || np != 0 {
		t.Fatalf("traces %d (max %d), pings %d", nt, MaxTracesPerHour, np)
	}
	reps, _, _, _ := f.snapshot()
	budget, denied := 0, 0
	for _, rep := range reps {
		if rep.Health.ICMPDenied {
			denied++
		}
		for _, x := range rep.Results {
			if x.Error == "budget" {
				budget++
			}
			for _, h := range x.Hops {
				if h.Addr == "192.168.1.1" {
					t.Fatal("private hop reported")
				}
			}
		}
	}
	if budget != 2 || denied == 0 {
		t.Fatalf("budget errors %d, icmp denied reports %d", budget, denied)
	}
}

type fakeResponder struct {
	mu      sync.Mutex
	running bool
	stopped int
}

func (f *fakeResponder) Run(ctx context.Context) error {
	f.mu.Lock()
	f.running = true
	f.mu.Unlock()
	<-ctx.Done()
	f.mu.Lock()
	f.running, f.stopped = false, f.stopped+1
	f.mu.Unlock()
	return nil
}

func (f *fakeResponder) Drain() []Inbound {
	return []Inbound{{From: "deadbeef", Family: 4, At: time.Now(), Count: 3}, {From: "../evil", Family: 4, Count: 1}}
}

func TestRunnerResponderAndUpdateMe(t *testing.T) {
	fr := &fakeResponder{}
	old := openResponder
	openResponder = func(addr, id string) (responderIface, error) {
		if id != testNodeID {
			t.Errorf("responder for %q", id)
		}
		return fr, nil
	}
	defer func() { openResponder = old }()
	f := newFakeAPI(t)
	fp := &fakeProber{}
	r := newTestRunner(t, f, "", fp, func(c *Config) { c.Measured = true })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	wait := func(what string, cond func() bool) {
		t.Helper()
		for i := 0; !cond(); i++ {
			if i > 500 {
				cancel()
				t.Fatalf("timeout: %s (status %+v)", what, r.Status())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	wait("responder on", func() bool { return r.Status().Responder })
	wait("inbound reported", func() bool {
		reps, _, _, _ := f.snapshot()
		for _, x := range reps {
			if len(x.Inbound) > 0 {
				return x.Inbound[0].From == "deadbeef" && len(x.Inbound) == 1 && x.Health.Responder
			}
		}
		return false
	})
	f.mu.Lock()
	puts := len(f.puts)
	f.mu.Unlock()
	if puts == 0 {
		t.Fatal("measured not synced to ipv64")
	}
	lat, lon := 50.1, 8.6
	m, err := r.UpdateMe(ctx, Me{Name: "Mein Knoten", Lat: &lat, Lon: &lon, Access: "fiber", Device: "pi", Measured: false, Budget: BudgetNormal})
	if err != nil || m.NodeID != testNodeID {
		t.Fatalf("update me: %v", err)
	}
	f.mu.Lock()
	sync0, last := f.rawPuts[0], f.rawPuts[len(f.rawPuts)-1]
	f.mu.Unlock()
	if strings.Contains(sync0, `"lat"`) || !strings.Contains(last, `"lat":50.1`) {
		t.Fatalf("location in PUT /sonar/me: sync %s, update %s", sync0, last)
	}
	if _, err := r.UpdateMe(ctx, Me{Measured: false, Budget: BudgetNormal}); err != nil {
		t.Fatalf("clear location: %v", err)
	}
	f.mu.Lock()
	last = f.rawPuts[len(f.rawPuts)-1]
	f.mu.Unlock()
	if !strings.Contains(last, `"lat":null`) || !strings.Contains(last, `"lon":null`) || strings.Contains(last, `"name"`) {
		t.Fatalf("clear location must send lat/lon null: %s", last)
	}
	wait("responder off", func() bool { return !r.Status().Responder })
	if st := r.Status(); st.Measured || st.Budget != BudgetNormal {
		t.Fatalf("not applied locally: %+v", st)
	}
	_, in := r.Recent(10)
	if len(in) == 0 || in[0].From != "deadbeef" {
		t.Fatalf("recent inbound %+v", in)
	}
	far := 500.0
	for _, bad := range []Me{{Name: "<b>"}, {Name: " abc"}, {Name: "a  b"}, {Device: "Pi"}, {Lat: &lat}, {Lat: &lon, Lon: &far}, {Access: "warp"}, {Budget: "alles"}, {Device: "a b c"}} {
		if _, err := r.UpdateMe(ctx, bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	rows, err := r.Inbound(ctx, time.Now().Add(-48*time.Hour))
	if err != nil || len(rows) != 1 {
		t.Fatalf("inbound %v %v", rows, err)
	}
	f.mu.Lock()
	since, _ := time.Parse(time.RFC3339, f.since[0])
	f.mu.Unlock()
	if time.Since(since) > 24*time.Hour+time.Minute {
		t.Fatalf("since not clamped: %v", since)
	}
	cancel()
	<-done
}

func TestRunnerReportChunkAndErrors(t *testing.T) {
	f := newFakeAPI(t)
	r := newTestRunner(t, f, "", &fakeProber{}, nil)
	ctx := context.Background()
	if err := r.ensureRegistered(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := range 2500 {
		r.store(Result{Round: now, Target: "n" + pad11(i), Family: 4, Method: MethodUDP, Sent: 5, Recv: 5, AvgMs: 12.345, At: now})
	}
	r.store(Result{Target: "nold00000000", At: now.Add(-7 * time.Hour)}) // wird hinten angehaengt, bleibt bis vorne
	more, _ := r.report(ctx)
	reps, _, _, _ := f.snapshot()
	if !more || len(reps) != 1 || len(reps[0].Results) == 0 || len(reps[0].Results) > 1000 {
		t.Fatalf("chunk: more=%v reports=%d", more, len(reps))
	}
	left := r.Status().Buffered
	f.mu.Lock()
	f.results = http.StatusServiceUnavailable
	f.mu.Unlock()
	r.report(ctx)
	if r.Status().Buffered != left {
		t.Fatal("buffer dropped on 503")
	}
	f.mu.Lock()
	f.results = http.StatusBadRequest
	f.mu.Unlock()
	r.report(ctx)
	if r.Status().Buffered >= left {
		t.Fatal("refused batch kept forever")
	}
}

func TestRunnerHostileServer(t *testing.T) {
	big := strings.Repeat("A", 3<<20)
	var mode string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		m := mode
		mu.Unlock()
		switch {
		case r.URL.Path == "/sonar/register" && m == "badid":
			data(w, Me{NodeID: "../../etc"})
		case r.URL.Path == "/sonar/register":
			data(w, Me{NodeID: testNodeID})
		case r.URL.Path == "/sonar/plan" && m == "big":
			io.WriteString(w, `{"data":{"plan":"`+big+`"}}`)
		case r.URL.Path == "/sonar/plan":
			io.WriteString(w, `{"data":{"plan":[1,2,{"x":`)
		case r.URL.Path == "/sonar/results":
			w.Header().Set("Retry-After", "999999999")
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"detail":"`+strings.Repeat("\x1b[31m", 100)+`"}`)
		default:
			io.WriteString(w, `null`)
		}
	}))
	defer srv.Close()
	cfg := Config{APIBase: srv.URL, Token: testToken, Log: quietLog(), Prober: &fakeProber{}, PlanKeys: []string{base64.StdEncoding.EncodeToString(make([]byte, 32))}, HTTPClient: srv.Client()}

	mode = "badid"
	r, _ := New(cfg)
	r.retryMin = 10 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	r.Run(ctx)
	cancel()
	if st := r.Status(); st.Registered || st.LastError == "" {
		t.Fatalf("bad node id accepted: %+v", st)
	}

	for _, m := range []string{"big", "garbage"} {
		mu.Lock()
		mode = m
		mu.Unlock()
		r, _ := New(cfg)
		r.retryMin = 20 * time.Millisecond
		r.reportEvery, r.reportGap = 20*time.Millisecond, 20*time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		r.Run(ctx)
		cancel()
		st := r.Status()
		if !st.PlanIssued.IsZero() || st.LastError == "" || strings.ContainsAny(st.LastError, "\x1b") {
			t.Fatalf("%s: %+v", m, st)
		}
	}
	if _, err := r.Me(context.Background()); err == nil {
		t.Fatal("null data accepted")
	}
}

func TestNewChecks(t *testing.T) {
	ok := Config{Token: testToken, Log: quietLog(), PlanKeys: []string{}}
	if _, err := New(ok); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]Config{
		"token":       {Token: "s64_kurz"},
		"anchortoken": {Token: testToken, Mode: ModeAnchor},
		"nodemode":    {Token: "s64a_0123456789abcdefghijABCDEFGHIJ0123456789", Mode: ModeHeadless},
		"mode":        {Token: testToken, Mode: "evil"},
		"budget":      {Token: testToken, Budget: "unendlich"},
		"quiet":       {Token: testToken, Quiet: [2]int{25, 3}},
		"http":        {Token: testToken, APIBase: "http://ipv64.net/api/v2"},
		"planKey":     {Token: testToken, PlanKeys: []string{"xx"}},
	} {
		c.Log = quietLog()
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	a, err := New(Config{Token: "s64a_0123456789abcdefghijABCDEFGHIJ0123456789", Mode: ModeAnchor, Log: quietLog(), PlanKeys: []string{}})
	if err != nil || !a.Status().Measured || a.limits().targets != MaxTargetsAnchor {
		t.Fatalf("anchor: %v", err)
	}
}

func TestCheckBase(t *testing.T) {
	for base, want := range map[string]bool{
		"": true, "https://ipv64.net/api/v2": true, "http://127.0.0.1:8080": true, "http://localhost:1": true,
		"http://ipv64.net": false, "ftp://x": false, "https://u:p@ipv64.net": false, "https://ipv64.net/?a=1": false,
	} {
		if _, err := checkBase(base); (err == nil) != want {
			t.Errorf("%q: %v", base, err)
		}
	}
}

func TestNoRedirect(t *testing.T) {
	var leaked bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked = true
		}
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/x", http.StatusFound)
	}))
	defer srv.Close()
	c := &client{base: srv.URL, http: defaultHTTPClient(), ua: "t"}
	if err := c.call(context.Background(), http.MethodGet, "/sonar/me", testToken, nil, smallLimit, &Me{}); err == nil {
		t.Fatal("redirect followed")
	}
	if leaked {
		t.Fatal("token sent to redirect target")
	}
}

func TestCreateToken(t *testing.T) {
	f := newFakeAPI(t)
	tok, err := CreateToken(context.Background(), f.srv.URL, "KEY0123456789abcdef", "node64-home")
	if err != nil || tok != testToken {
		t.Fatalf("%q %v", tok, err)
	}
	if _, err := CreateToken(context.Background(), f.srv.URL, "KEY0123456789abcdeX", "node64-home"); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := CreateToken(context.Background(), f.srv.URL, "key\r\nX-Evil: 1", "x"); err == nil {
		t.Fatal("bad key format accepted")
	}
	if _, err := CreateToken(context.Background(), f.srv.URL, "KEY0123456789abcdef", "<script>"); err == nil {
		t.Fatal("bad name accepted")
	}
	if _, err := CreateToken(context.Background(), "http://example.com", "KEY0123456789abcdef", "x"); err == nil {
		t.Fatal("plain http accepted")
	}
}

func TestDueRoundSpacingAndRestart(t *testing.T) {
	f := newFakeAPI(t)
	dir := t.TempDir()
	r := newTestRunner(t, f, dir, &fakeProber{}, nil)
	r.roundLen = time.Minute
	now := time.Now().UTC().Truncate(time.Minute)
	ts := publicTargets(1, MethodICMP, 1)
	p := testPlan(Round{Start: now, Targets: ts}, Round{Start: now.Add(10 * time.Second), Targets: ts},
		Round{Start: now.Add(time.Minute), Targets: ts})
	ap := &activePlan{plan: p, validUntil: now.Add(time.Hour), anchorsUntil: now.Add(2 * time.Hour)}
	due := func(r *Runner, at time.Time) (time.Time, bool) {
		r.mu.Lock()
		defer r.mu.Unlock()
		s, _, _, ok := r.dueRound(at)
		return s, ok
	}
	r.plan = ap
	if s, ok := due(r, now.Add(20*time.Second)); !ok || !s.Equal(now) {
		t.Fatalf("first round: %v %v", s, ok)
	}
	if _, ok := due(r, now.Add(30*time.Second)); ok {
		t.Fatal("overlapping round measured as well")
	}
	r.saveState()
	// Neustart in derselben Runde: nicht noch einmal
	r2 := newTestRunner(t, f, dir, &fakeProber{}, nil)
	r2.roundLen, r2.plan = time.Minute, ap
	if _, ok := due(r2, now.Add(40*time.Second)); ok {
		t.Fatal("round measured again after restart")
	}
	if s, ok := due(r2, now.Add(61*time.Second)); !ok || !s.Equal(now.Add(time.Minute)) {
		t.Fatalf("next round: %v %v", s, ok)
	}
	// Uhr zurueckgestellt: gespeicherte Runde in der Zukunft blockiert nicht
	r2.st.LastRound = now.Add(48 * time.Hour).UnixMilli()
	if _, ok := due(r2, now.Add(5*time.Second)); !ok {
		t.Fatal("future last round blocks measuring")
	}
}

func TestInboundMerge(t *testing.T) {
	f := newFakeAPI(t)
	r := newTestRunner(t, f, "", &fakeProber{}, nil)
	r.responder = &fakeResponder{}
	for range 3 {
		r.Recent(5) // fragt den Antworter live ab
	}
	r.mu.Lock()
	n, cnt, rin := len(r.inbuf), 0, len(r.recentIn)
	if n > 0 {
		cnt = r.inbuf[0].Count
	}
	r.inSending = r.inOff + uint64(len(r.inbuf)) // laufende Meldung: nicht mehr hineinzaehlen
	r.mu.Unlock()
	if n != 1 || cnt != 9 || rin != 3 {
		t.Fatalf("inbuf %d (count %d), recent %d", n, cnt, rin)
	}
	r.drainResponder()
	r.mu.Lock()
	n = len(r.inbuf)
	r.mu.Unlock()
	if n != 2 {
		t.Fatalf("merged into a report in flight: %d", n)
	}
}

func (f *fakeAPI) callsSince(i int) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls[min(i, len(f.calls)):]...)
}

func (f *fakeAPI) set(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

// Abgemeldet (401 invalid_token): nicht mehr messen, Antworter zu, Puffer weg, nur GET /sonar/me; danach wieder normal.
func TestRunnerRevokedAndBack(t *testing.T) {
	fr := &fakeResponder{}
	old := openResponder
	openResponder = func(string, string) (responderIface, error) { return fr, nil }
	defer func() { openResponder = old }()
	f := newFakeAPI(t)
	now := time.Now().UTC()
	var rounds []Round
	for i := range 60 {
		rounds = append(rounds, Round{Start: now.Add(time.Duration(i) * time.Second), Targets: publicTargets(1, MethodICMP, 1)})
	}
	f.setPlan(testPlan(rounds...))
	fp := &fakeProber{}
	r := newTestRunner(t, f, t.TempDir(), fp, func(c *Config) { c.Measured = true })
	r.planEvery = 200 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	wait := func(what string, cond func() bool) {
		t.Helper()
		for i := 0; !cond(); i++ {
			if i > 800 {
				t.Fatalf("timeout: %s (status %+v)", what, r.Status())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	wait("measuring", func() bool {
		reps, _, _, _ := f.snapshot()
		return len(fp.all()) >= 1 && r.Status().Responder && len(reps) > 0
	})
	f.set(func() { f.revoked = http.StatusUnauthorized })
	wait("revoked", func() bool { st := r.Status(); return st.Paused == "revoked" && !st.Responder })
	time.Sleep(50 * time.Millisecond)
	n := len(fp.all())
	f.mu.Lock()
	mark := len(f.calls)
	f.mu.Unlock()
	time.Sleep(700 * time.Millisecond)
	if len(fp.all()) != n {
		t.Fatalf("measured while revoked: %d -> %d", n, len(fp.all()))
	}
	calls := f.callsSince(mark)
	if len(calls) < 2 || len(calls) > 8 {
		t.Fatalf("checks while revoked: %v", calls)
	}
	for _, c := range calls {
		if c != "GET /sonar/me" {
			t.Fatalf("request while revoked: %v", calls)
		}
	}
	if st := r.Status(); st.Buffered != 0 || st.Responder {
		t.Fatalf("status while revoked: %+v", st)
	}
	if _, err := r.Me(ctx); !errors.Is(err, ErrRevoked) {
		t.Fatalf("me while revoked: %v", err)
	}
	fr.mu.Lock()
	stopped := fr.stopped
	fr.mu.Unlock()
	if stopped == 0 {
		t.Fatal("responder not closed")
	}
	select {
	case <-done:
		t.Fatal("Run ended while revoked")
	default:
	}
	// Account wieder frei: normal weiter, Antworter wieder an
	f.set(func() { f.revoked = 0 })
	wait("back", func() bool { st := r.Status(); return st.Paused != "revoked" && st.Responder && len(fp.all()) > n })
	cancel()
	<-done
}

// Nur 401 invalid_token und 403 node_disabled melden ab; 401 ohne Code, 429 und 409 nicht.
func TestRunnerRevokedCodes(t *testing.T) {
	f := newFakeAPI(t)
	r := newTestRunner(t, f, "", &fakeProber{}, nil)
	ctx := context.Background()
	if err := r.ensureRegistered(ctx); err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusConflict, http.StatusForbidden} {
		f.set(func() { f.planCode = code })
		r.fetchPlan(ctx)
		if r.isRevoked() {
			t.Fatalf("%d without code revoked the node", code)
		}
	}
	for _, c := range []struct {
		status int
		code   string
		want   bool
	}{{401, "invalid_token", true}, {403, "node_disabled", true}, {401, "unauthenticated", false}, {403, "invalid_token", false}, {429, "rate_limited", false}} {
		if got := revokedErr(&APIError{Status: c.status, Code: c.code}); got != c.want {
			t.Errorf("%d %s: %v", c.status, c.code, got)
		}
	}
	f.set(func() { f.planCode = 0 })
	r.store(Result{Target: "a_fsn", Family: 4, Method: MethodICMP, Sent: 1, Recv: 1, MinMs: 1, AvgMs: 1, MaxMs: 1, At: time.Now()})
	f.set(func() { f.revoked = http.StatusForbidden })
	r.fetchPlan(ctx)
	if st := r.Status(); !r.isRevoked() || st.Paused != "revoked" || st.Buffered != 0 {
		t.Fatalf("403 node_disabled: %+v", st)
	}
	r.checkBack(ctx)
	if !r.isRevoked() {
		t.Fatal("back while still disabled")
	}
	f.set(func() { f.revoked = 0 })
	r.checkBack(ctx)
	if r.isRevoked() || r.Status().Paused == "revoked" {
		t.Fatal("not back after 200")
	}

	// noch nicht angemeldet und Token widerrufen: stuendlich (hier 150 ms) GET /sonar/me statt Register
	f2 := newFakeAPI(t)
	f2.revoked = http.StatusUnauthorized
	r2 := newTestRunner(t, f2, "", &fakeProber{}, nil)
	ctx2, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	r2.Run(ctx2)
	cancel()
	calls := f2.callsSince(0)
	if len(calls) < 3 || calls[0] != "POST /sonar/register" || r2.Status().Registered || r2.Status().Paused != "revoked" {
		t.Fatalf("unregistered revoked: %v %+v", calls, r2.Status())
	}
	for _, c := range calls[1:] {
		if c != "GET /sonar/me" {
			t.Fatalf("unregistered revoked: %v", calls)
		}
	}
	f2.set(func() { f2.revoked = 0 })
	runFor(t, r2, func() bool { return r2.Status().Registered }, 5*time.Second)
}

// Leave: DELETE /sonar/me, Run endet, sonar64.json und sonar64.key weg; Fehler laesst alles stehen, Forget nur lokal.
func TestRunnerLeave(t *testing.T) {
	f := newFakeAPI(t)
	dir := t.TempDir()
	r := newTestRunner(t, f, dir, &fakeProber{}, nil)
	ctx := context.Background()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	exists := func(d, name string) bool { _, err := os.Stat(filepath.Join(d, name)); return err == nil }
	for i := 0; !r.Status().Registered || !exists(dir, stateFile); i++ {
		if i > 500 {
			t.Fatal("not registered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.set(func() { f.delCode = http.StatusBadGateway })
	if err := r.Leave(ctx); err == nil {
		t.Fatal("leave with 502 must fail")
	}
	select {
	case <-done:
		t.Fatal("Run ended after a failed leave")
	case <-time.After(50 * time.Millisecond):
	}
	if !exists(dir, stateFile) || !exists(dir, keyFile) {
		t.Fatal("files removed after a failed leave")
	}
	f.set(func() { f.delCode = 0 })
	if err := r.Leave(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not end after leave")
	}
	time.Sleep(50 * time.Millisecond)
	if exists(dir, stateFile) || exists(dir, keyFile) {
		t.Fatal("state or key kept after leave")
	}
	deleted := false
	for _, c := range f.callsSince(0) {
		deleted = deleted || c == "DELETE /sonar/me"
	}
	if !deleted {
		t.Fatalf("no DELETE /sonar/me: %v", f.callsSince(0))
	}
	if err := r.Run(ctx); !errors.Is(err, errLeft) {
		t.Fatalf("run after leave: %v", err)
	}

	// 401 und 404 gelten als erledigt (schon abgemeldet)
	for _, code := range []int{http.StatusUnauthorized, http.StatusNotFound} {
		d := t.TempDir()
		f.set(func() { f.delCode = code })
		r := newTestRunner(t, f, d, &fakeProber{}, nil)
		if err := r.Leave(ctx); err != nil || exists(d, keyFile) {
			t.Fatalf("%d: %v", code, err)
		}
	}

	// ohne Verbindung: Fehler, nichts geloescht; Forget loescht lokal
	d := t.TempDir()
	f2 := newFakeAPI(t)
	r3 := newTestRunner(t, f2, d, &fakeProber{}, nil)
	f2.srv.Close()
	if err := r3.Leave(ctx); err == nil || !exists(d, keyFile) {
		t.Fatalf("offline leave: %v", err)
	}
	if err := r3.Forget(); err != nil || exists(d, keyFile) {
		t.Fatalf("forget: %v", err)
	}
}

func TestIntervals(t *testing.T) {
	n, err := New(Config{Token: testToken, Log: quietLog(), PlanKeys: []string{}})
	if err != nil || n.planEvery != 2*time.Minute || n.reportEvery != 5*time.Minute || n.revokedEvery != time.Hour {
		t.Fatalf("node: %v", err)
	}
	a, err := New(Config{Token: "s64a_0123456789abcdefghijABCDEFGHIJ0123456789", Mode: ModeAnchor, Log: quietLog(), PlanKeys: []string{}})
	if err != nil || a.planEvery != time.Minute || a.reportEvery != time.Minute {
		t.Fatalf("anchor: %v", err)
	}
	lo, hi := time.Hour, time.Duration(0)
	for range 5000 {
		d := jitter(time.Minute)
		lo, hi = min(lo, d), max(hi, d)
	}
	if lo < 48*time.Second || hi > 72*time.Second || lo > 52*time.Second || hi < 68*time.Second {
		t.Fatalf("jitter range %v..%v", lo, hi)
	}
}

// Anker melden jede Minute nur, wenn etwas zu melden ist; Health spaetestens nach heartbeat.
func TestAnchorReportsOnlyWithData(t *testing.T) {
	const anchorTok = "s64a_0123456789abcdefghijABCDEFGHIJ0123456789"
	f := newFakeAPI(t)
	f.token = anchorTok
	r := newTestRunner(t, f, "", &fakeProber{}, func(c *Config) { c.Mode, c.Token = ModeAnchor, anchorTok })
	r.heartbeat = time.Hour
	ctx := context.Background()
	if err := r.ensureRegistered(ctx); err != nil {
		t.Fatal(err)
	}
	count := func() int { reps, _, _, _ := f.snapshot(); return len(reps) }
	r.report(ctx) // erste Meldung (Health)
	r.report(ctx) // nichts zu melden
	if n := count(); n != 1 {
		t.Fatalf("reports %d, want 1", n)
	}
	r.store(Result{Round: time.Now().UTC(), Target: "nabc000000001", Family: 4, Method: MethodUDP, Sent: 1, Recv: 1, MinMs: 1, AvgMs: 1, MaxMs: 1, At: time.Now()})
	r.report(ctx)
	if n := count(); n != 2 {
		t.Fatalf("reports %d, want 2", n)
	}
	r.heartbeat = 0
	r.report(ctx)
	if n := count(); n != 3 {
		t.Fatalf("heartbeat: reports %d, want 3", n)
	}
}
