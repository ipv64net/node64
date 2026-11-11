package monitor64

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Nach RunNow (z. B. "alle neu pruefen" nach dem Speichern) liegt der naechste Lauf wieder auf dem eigenen Versatz -
// sonst liefen alle Hosts fuer immer im Gleichschritt.
func TestSchedulerBackOnGridAfterRunNow(t *testing.T) {
	s := NewScheduler(1)
	now := time.Date(2026, 11, 11, 12, 0, 7, 0, time.UTC)
	j := &job{key: "host:abc", interval: time.Minute, next: now, idx: -1}
	j.running.Store(true) // nur planen, nicht ausfuehren
	s.dispatchLocked(context.Background(), j, now)
	if want := firstRun(now, j.key, j.interval); !j.next.Equal(want) {
		t.Fatalf("next %v, want %v (grid)", j.next, want)
	}
}

// Ein ausdruecklich gewaehlter Kanal bekommt die Meldung auch, wenn "Standardkanaele" fuer diese Stufe nicht
// gewaehlt ist (vorher fiel er weg, sobald "Standardkanaele" irgendwo im Routing stand).
func TestDispatchExplicitChannelWithoutDefault(t *testing.T) {
	ctx := context.Background()
	m, alerts, mu := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	h := &Host{UID: "dispatch-host-1", Name: "nas01", Address: "192.0.2.9"}
	m.dispatch(ctx, h, eval.Message{At: time.Now(), Host: hostRef(h), Event: eval.EvProblem, Severity: eval.Warn,
		Lines: []eval.Line{{Kind: eval.LineProblem, Key: "fs:/", Name: "fs", State: eval.Warn}}, Channels: []string{"5"}}, "")
	mu.Lock()
	defer mu.Unlock()
	if len(*alerts) != 1 || len((*alerts)[0].Check.Channels) != 1 || (*alerts)[0].Check.Channels[0] != 5 {
		t.Fatalf("alerts: %+v", *alerts)
	}
}

// Pausieren: die Ansicht zeigt den neuen Host (pausiert) und keine alten Probleme mehr.
func TestPausedHostViewUpdated(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	fake := &fakeCol{svcs: []model.Service{svc("cpu", "cpu", model.Metric{Name: "util", Value: 10, Unit: "%", Rule: model.RuleCPU})}}
	rt := hostWithFake(t, m, fake)
	m.poll(ctx, rt)
	h := *rt.host
	h.Paused = true
	if err := m.store.SaveHost(ctx, &h, SystemActor); err != nil {
		t.Fatal(err)
	}
	m.ReloadHost(ctx, h.UID)
	for _, v := range m.Views() {
		if v.Host.UID == h.UID && !v.Host.Paused {
			t.Fatal("view still shows the host as not paused")
		}
	}
}

// Cluster: ein Problem mit mehr als 500 Eintraegen gibt die neuesten weiter (vorher immer die aeltesten 500).
func TestProblemGetSendsNewestEvents(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	t0 := time.Now().Add(-time.Hour)
	if _, err := m.st.Writer().Exec(`INSERT INTO m64_problems (uid, host_uid, service_key, state, worst, opened_at, updated_at) VALUES ('prob-many-1', 'host-many-0001', 'fs:/', 'warn', 'warn', ?, ?)`,
		ts(t0), tsNow()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < problemEventsMax+20; i++ {
		m.event(ctx, "prob-many-1", "host-many-0001", "fs:/", "warn", "", SystemActor, t0.Add(time.Duration(i)*time.Second))
	}
	raw, ok, err := m.problemGet(ctx, "prob-many-1")
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	var p problemEntry
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Events) != problemEventsMax {
		t.Fatalf("events: %d", len(p.Events))
	}
	last := p.Events[len(p.Events)-1]
	if b, _ := json.Marshal(last); !json.Valid(b) || p.Events[0].TS >= last.TS {
		t.Fatalf("order: first %v last %v", p.Events[0].TS, last.TS)
	}
	if want := ts(t0.Add(time.Duration(problemEventsMax+19) * time.Second)); last.TS != want {
		t.Fatalf("newest event missing: %s, want %s", last.TS, want)
	}
}

// API-Zugaenge ohne eigene URL: ein Port in der Adresse des Hosts (SSH) gilt nicht fuer die API.
func TestAPIHostPortIgnoresHostPort(t *testing.T) {
	for in, want := range map[string]string{"nas:2222": "nas:8006", "[2001:db8::1]:2222": "[2001:db8::1]:8006", "fe80::1%eth0": "[fe80::1%eth0]:8006", "nas": "nas:8006"} {
		if got := apiHostPort(in, 8006); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// Export ohne Passwort: Push-Token nicht im Klartext; mit Passwort verschluesselt und beim Import zurueck.
func TestExportSealsPushToken(t *testing.T) {
	cfg := `{"mode":"push","token":"m64p_secret_token_value"}`
	if out := sealPushToken(nil, cfg); strings.Contains(out, "secret_token") || strings.Contains(out, "token_sealed") {
		t.Fatalf("without password: %s", out)
	}
	if out := sealPushToken(nil, `{"mode":"pull"}`); out != `{"mode":"pull"}` {
		t.Fatalf("other access changed: %s", out)
	}
}
