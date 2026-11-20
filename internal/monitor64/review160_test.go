package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/monitor64/transport"
)

// Befunde aus dem Code-Review v1.6.0..1.7.10: je Punkt ein Test, der den Fehler vorher zeigt.

// "Darf ausgeschaltet sein" (#229): nur echte Nichterreichbarkeit heisst "ausgeschaltet". Weist der laufende Host den
// Zugang ab (geaenderter Hostschluessel, falsches Passwort), wird das wie sonst als "nicht erreichbar" gemeldet.
func TestReview160OfflineOKOnlyUnreachable(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	fake := &fakeCol{svcs: []model.Service{svc("cpu", "cpu")}}
	rt := hostWithFake(t, m, fake)
	rt.host.OfflineOK = true
	m.poll(ctx, rt)
	for _, c := range []struct {
		name string
		err  error
		want eval.HostView
	}{
		{"aus", errors.New("dial tcp 192.0.2.1:6465: connect: no route to host"), eval.ViewOffline},
		{"Hostschluessel", &transport.HostKeyError{Want: "SHA256:alt", Got: "SHA256:neu"}, eval.ViewUnreachable},
		{"Anmeldung", errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain"), eval.ViewUnreachable},
		{"wieder aus", errors.New("dial tcp 192.0.2.1:6465: i/o timeout"), eval.ViewOffline},
	} {
		fake.set(nil, c.err)
		m.poll(ctx, rt)
		m.poll(ctx, rt)
		if v := rt.getView(); v.View != c.want {
			t.Errorf("%s: %s, erwartet %s", c.name, v.View, c.want)
		}
	}
}

// Quittierung im Cluster: ist die eigene Zeile juenger (Zustandswechsel), ohne dass hier quittiert oder aufgehoben
// wurde, gilt die auf der anderen Node gesetzte Quittierung. Ein hier juengeres Aufheben bleibt (Review 6).
func TestReview160ClusterAckLocalNewer(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	t1, t2, t3 := "2026-11-15T10:00:00.000Z", "2026-11-15T10:05:00.000Z", "2026-11-15T10:06:00.000Z"
	ack := `{"by":{"kind":"user","name":"dennis"},"at":"` + t1 + `"}`
	put := func(uid, key string) {
		t.Helper()
		if _, err := m.st.Writer().Exec(`INSERT INTO m64_problems (uid, node_id, host_uid, service_key, state, worst, opened_at, ack, updated_at)
			VALUES (?, 'nodeA', 'hostUID000000001', ?, 'crit', 'crit', ?, '', ?)`, uid, key, t1, t2); err != nil {
			t.Fatal(err)
		}
	}
	apply := func(uid, key string) *problemEntry {
		t.Helper()
		in, _ := json.Marshal(problemEntry{Node: "nodeA", Host: "hostUID000000001", Key: key, State: "warn", Worst: "warn", Opened: t1,
			Ack: ack, Updated: t1, Notified: []string{},
			Events: []eventEntry{{UID: "evAck" + uid[len(uid)-4:], Node: "nodeB", Problem: uid, Host: "hostUID000000001", Key: key, TS: t1, Kind: "ack", Text: "ok"}}})
		if err := m.problemApply(ctx, uid, in, false); err != nil {
			t.Fatal(err)
		}
		p, err := m.problemRow(ctx, uid)
		if err != nil || p == nil {
			t.Fatal(err)
		}
		return p
	}
	// hier nur ein Zustandswechsel (juengere Zeile): die Quittierung der anderen Node bleibt
	put("probUID000000ack1", "cpu")
	if p := apply("probUID000000ack1", "cpu"); p.Ack != ack || p.Updated != t2 {
		t.Fatalf("Quittierung verloren: ack=%q updated=%s", p.Ack, p.Updated)
	}
	// hier nach der Quittierung aufgehoben: bleibt aufgehoben
	put("probUID000000ack2", "mem")
	m.event(ctx, "probUID000000ack2", "hostUID000000001", "mem", "unack", "", SystemActor, parseTS(t3))
	if p := apply("probUID000000ack2", "mem"); p.Ack != "" {
		t.Fatalf("Aufheben zurueckgedreht: ack=%q", p.Ack)
	}
}

// Eine bestaetigte SMART-Zustandsregel bleibt, wenn SMART in einer Runde nicht gelesen wurde (schlafende Platte
// nach dem Neustart, smartctl scheitert einmal); erst eine gelesene Runde ohne die Bedingung erledigt sie.
func TestReview160SmartAcceptKeptWithoutSmart(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	disk := func(facts ...model.Fact) model.Service {
		return model.Service{Key: "disk:S1", Name: "sda", Kind: "disk", Default: true, Facts: facts}
	}
	failed := model.Fact{Code: "smart_failed", Text: "SMART FAILED"}
	fake := &fakeCol{svcs: []model.Service{disk(failed)}}
	rt := hostWithFake(t, e.m, fake)
	uid := rt.host.UID
	hostRule := func() string {
		return e.col(`SELECT host_rule FROM m64_services WHERE host_uid = ? AND key = 'disk:S1'`, uid)
	}
	e.m.poll(ctx, rt)
	adoptAll(t, e.m, uid)
	e.m.poll(ctx, rt)
	if c := e.do("PUT", "/api/monitor64/hosts/"+uid+"/service", map[string]any{"key": "disk:S1", "accept": map[string]any{"kind": eval.KindSmartFailed, "mode": "change"}}).Code; c != 200 {
		t.Fatalf("accept: %d", c)
	}
	e.m.poll(ctx, rt)
	if !strings.Contains(hostRule(), "accepted") {
		t.Fatalf("nicht bestaetigt: %q", hostRule())
	}
	for _, f := range []model.Fact{{Code: "smart_standby"}, {Code: "smart_unreadable", Text: "SMART nicht lesbar"}} {
		fake.set([]model.Service{disk(f)}, nil)
		e.m.poll(ctx, rt)
		if !strings.Contains(hostRule(), "accepted") {
			t.Fatalf("%s: Bestaetigung entfernt: %q", f.Code, hostRule())
		}
	}
	fake.set([]model.Service{disk()}, nil) // gelesen, Platte wieder in Ordnung
	e.m.poll(ctx, rt)
	if strings.Contains(hostRule(), "accepted") {
		t.Fatalf("Bedingung entfallen, Bestaetigung bleibt: %q", hostRule())
	}
}

// Schlafende Platte nach dem Neustart (kein Vorstand): der Dienst kommt ueber diskstats, mit Vermerk smart_standby.
func TestReview160MapDisksStandbyFact(t *testing.T) {
	cur := &m64proto.Report{Disks: []m64proto.DiskIO{{Name: "sda", Serial: "S1"}},
		SMART: []m64proto.SMART{{Device: "/dev/sda", Error: "Device is in STANDBY mode"}}}
	for _, s := range mapDisks(nil, cur, 0) {
		if s.Key == "disk:S1" {
			if !slices.ContainsFunc(s.Facts, func(f model.Fact) bool { return f.Code == "smart_standby" }) {
				t.Fatalf("ohne smart_standby: %+v", s.Facts)
			}
			return
		}
	}
	t.Fatal("Platte fehlt")
}

// "Dienst verschwunden" laesst sich als in Ordnung bestaetigen (die Oberflaeche bietet es an).
func TestReview160AcceptVanished(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	fake := &fakeCol{svcs: []model.Service{svc("cpu", "cpu"), svc("if:eth1", "if")}}
	rt := hostWithFake(t, e.m, fake)
	uid := rt.host.UID
	e.m.poll(ctx, rt)
	adoptAll(t, e.m, uid)
	fake.set([]model.Service{svc("cpu", "cpu")}, nil)
	for range vanishRounds + 1 {
		e.m.poll(ctx, rt)
	}
	if !vanished(t, e.m, uid, "if:eth1") {
		t.Fatal("nicht verschwunden")
	}
	if rec := e.do("PUT", "/api/monitor64/hosts/"+uid+"/service", map[string]any{"key": "if:eth1", "accept": map[string]any{"kind": eval.KindServiceGone, "mode": "change"}}); rec.Code != 200 {
		t.Fatalf("bestaetigen: %d %s", rec.Code, rec.Body)
	}
	e.m.poll(ctx, rt)
	for _, s := range rt.getView().Services {
		if s.Key == "if:eth1" && (!slices.Contains(s.Accepted, eval.KindServiceGone) || slices.Contains(s.Firing, eval.KindServiceGone)) {
			t.Fatalf("bestaetigt: %v %v", s.Accepted, s.Firing)
		}
	}
}

// Nach dem Ausschalten von "SMART-Werte abfragen" fehlen Temperatur und Verschleiss gewollt: eine Warnung dazu gilt
// nicht mehr (statt 7 Tage "unbekannt"). Mit SMART bleibt ein fehlender Wert "unbekannt".
func TestReview160SmartOffForgetsValues(t *testing.T) {
	for _, c := range []struct {
		name string
		cfg  string
		want eval.State
	}{{"SMART an", `{}`, eval.Unknown}, {"SMART aus", `{"no_smart":true}`, eval.OK}} {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			m, _, _ := newTestModule(t)
			if err := m.Start(ctx); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = m.Stop(ctx) })
			hot := model.Metric{Name: "temp", Value: 70, Unit: "°C", Rule: model.RuleDiskTemp}
			fake := &fakeCol{svcs: []model.Service{svc("disk:S1", "disk", hot)}}
			rt := hostWithFake(t, m, fake)
			m.poll(ctx, rt)
			adoptAll(t, m, rt.host.UID)
			m.poll(ctx, rt)
			tr := rt.Trackers["disk:S1|temp"]
			if tr == nil {
				t.Fatal("kein Tracker")
			}
			tr.Level, tr.Changed = eval.Crit, time.Now().Add(-time.Hour)
			tr.WarnSince, tr.CritSince = time.Now().Add(-time.Hour), time.Now().Add(-time.Hour)
			m.poll(ctx, rt)
			if st := svcState(rt, "disk:S1"); st != eval.Crit {
				t.Fatalf("erwartet kritisch, %v", st)
			}
			rt.accs[0].row.Config = json.RawMessage(c.cfg)
			fake.set([]model.Service{svc("disk:S1", "disk")}, nil)
			rt.mu.Lock()
			rt.Trackers["disk:S1|temp"].LastAt = time.Now().Add(-5 * time.Minute)
			rt.mu.Unlock()
			m.poll(ctx, rt)
			if st := svcState(rt, "disk:S1"); st != c.want {
				t.Fatalf("Platte nach fehlender Temperatur: %v, erwartet %v", st, c.want)
			}
		})
	}
}

// Datenbankfehler beim Schliessen eines Problems: kein Absturz der Runde (res ist dann nil).
func TestReview160CloseProblemDBError(t *testing.T) {
	m, _, _ := newTestModule(t)
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := &Host{UID: "hostUID000000001", Name: "h1"}
	m.closeHostProblem(cctx, h, map[string]*openProblem{"": {UID: "probUID00000db01", State: "unreachable"}}, time.Now())
	m.syncProblems(cctx, h, map[string]*openProblem{"cpu": {UID: "probUID00000db02", State: "warn"}}, nil, eval.HostResult{}, "", time.Now())
}
