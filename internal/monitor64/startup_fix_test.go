package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/monitor64/model/modeltest"
	"github.com/ipv64net/node64/internal/notify"
)

// Anlaufzeit nach dem Wiederkommen (#275, #274), keine Meldungen ohne Zugang bzw. fuer geloeschte Hosts (#263).

// shiftRT verschiebt alle Zeiten des Laufzeitstands (Tracker, Wiederkommen) - wie eine lange Pause zwischen zwei Runden.
func shiftRT(rt *hostRT, d time.Duration) {
	for _, tr := range rt.Trackers {
		for _, p := range []*time.Time{&tr.LastAt, &tr.Changed, &tr.WarnSince, &tr.CritSince} {
			if !p.IsZero() {
				*p = p.Add(d)
			}
		}
	}
	for _, p := range []*time.Time{&rt.Seen, &rt.Back, &rt.Away} {
		if !p.IsZero() {
			*p = p.Add(d)
		}
	}
}

func alertCount(alerts *[]notify.Alert, mu *sync.Mutex) int {
	mu.Lock()
	defer mu.Unlock()
	return len(*alerts)
}

func alertLines(t *testing.T, a notify.Alert) []notify.MonitorLine {
	t.Helper()
	var ls []notify.MonitorLine
	if err := json.Unmarshal([]byte(a.Data["lines"]), &ls); err != nil {
		t.Fatal(err)
	}
	return ls
}

func svcAt(t *testing.T, rt *hostRT, key string) SvcView {
	t.Helper()
	s := svcView(rt, key)
	if s == nil {
		t.Fatalf("Dienst %s fehlt in der Ansicht", key)
	}
	return *s
}

// Windows-PC mit "Darf ausgeschaltet sein": nach dem Einschalten fehlen die Updates (der Agent sucht noch). Das ist
// kein "Unbekannt" mit Entwarnung eine Minute spaeter; bleiben sie ueber die Anlaufzeit aus, wird wie sonst gemeldet -
// mit "keine Daten" statt "Firmware-Update verfuegbar".
func TestStartupGraceAfterOffline(t *testing.T) {
	ctx := context.Background()
	m, alerts, amu := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	cpu := svc("cpu", "cpu", model.Metric{Name: "util", Value: 10, Unit: "%", Rule: model.RuleCPU})
	upd := svc("updates", "updates")
	fake := &fakeCol{svcs: []model.Service{cpu, upd}}
	rt := hostWithFake(t, m, fake)
	rt.host.OfflineOK = true
	m.poll(ctx, rt)
	adoptAll(t, m, rt.host.UID)
	m.poll(ctx, rt)
	if s := svcAt(t, rt, "updates"); s.State != eval.OK {
		t.Fatalf("Updates vor dem Ausschalten: %s", s.State)
	}

	// ausgeschaltet, lange aus
	fake.set(nil, errors.New("dial tcp 192.0.2.1:6465: connect: no route to host"))
	m.poll(ctx, rt)
	m.poll(ctx, rt)
	if v := rt.getView(); v.View != eval.ViewOffline {
		t.Fatalf("erwartet ausgeschaltet, %s", v.View)
	}
	shiftRT(rt, -2*time.Hour)
	n := alertCount(alerts, amu)

	// eingeschaltet, Updates noch nicht ermittelt: letzter Stand, keine Meldung
	fake.set([]model.Service{cpu}, nil)
	m.poll(ctx, rt)
	if s := svcAt(t, rt, "updates"); s.State != eval.OK {
		t.Fatalf("Updates in der Anlaufzeit: %s (%s), erwartet OK", s.State, modeltest.DE(s.Cause))
	}
	fake.set([]model.Service{cpu, upd}, nil)
	m.poll(ctx, rt)
	if got := alertCount(alerts, amu); got != n {
		t.Fatalf("%d Meldung(en) nach dem Einschalten, erwartet keine", got-n)
	}

	// erneut aus und an, Updates kommen diesmal nicht: nach der Anlaufzeit "Unbekannt - keine Daten"
	fake.set(nil, errors.New("dial tcp 192.0.2.1:6465: connect: no route to host"))
	m.poll(ctx, rt)
	m.poll(ctx, rt)
	shiftRT(rt, -2*time.Hour)
	fake.set([]model.Service{cpu}, nil)
	m.poll(ctx, rt)
	if s := svcAt(t, rt, "updates"); s.State != eval.OK {
		t.Fatalf("Updates in der Anlaufzeit: %s", s.State)
	}
	rt.Back = rt.Back.Add(-startupFor(time.Minute) - time.Second) // Anlaufzeit vorbei
	m.poll(ctx, rt)
	s := svcAt(t, rt, "updates")
	if s.State != eval.Unknown {
		t.Fatalf("Updates nach der Anlaufzeit: %s, erwartet unbekannt", s.State)
	}
	if de, en := modeltest.DE(s.Cause), modeltest.EN(s.Cause); de != "keine Daten" || en != "no data" {
		t.Errorf("Ursache %q / %q, erwartet \"keine Daten\"", de, en)
	}
	if got := alertCount(alerts, amu); got == n {
		t.Fatal("keine Meldung, obwohl die Updates nach der Anlaufzeit fehlen")
	}
}

// Ohne "Darf ausgeschaltet sein": die Meldung "wieder erreichbar" fuehrt Werte, die noch nicht wieder kamen, nicht als
// "noch offen - Unbekannt". Werte, die schon vor dem Ausfall fehlten, bekommen keine Anlaufzeit.
func TestStartupGraceAfterUnreachable(t *testing.T) {
	ctx := context.Background()
	m, alerts, amu := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	cpu := svc("cpu", "cpu", model.Metric{Name: "util", Value: 10, Unit: "%", Rule: model.RuleCPU})
	upd := svc("updates", "updates")
	old := svc("reboot", "reboot")
	fake := &fakeCol{svcs: []model.Service{cpu, upd, old}}
	rt := hostWithFake(t, m, fake)
	m.poll(ctx, rt)
	adoptAll(t, m, rt.host.UID)
	m.poll(ctx, rt)
	// "reboot" fehlt schon lange vor dem Ausfall (unbekannt)
	fake.set([]model.Service{cpu, upd}, nil)
	m.poll(ctx, rt)
	for k, tr := range rt.Trackers {
		if strings.HasPrefix(k, "reboot|") {
			tr.LastAt = tr.LastAt.Add(-10 * time.Minute)
		}
	}
	m.poll(ctx, rt)
	if s := svcAt(t, rt, "reboot"); s.State != eval.Unknown {
		t.Fatalf("reboot vor dem Ausfall: %s, erwartet unbekannt", s.State)
	}
	fake.set(nil, errors.New("dial tcp 192.0.2.1:6465: i/o timeout"))
	m.poll(ctx, rt)
	m.poll(ctx, rt)
	if v := rt.getView(); v.View != eval.ViewUnreachable {
		t.Fatalf("erwartet nicht erreichbar, %s", v.View)
	}
	shiftRT(rt, -2*time.Hour)
	n := alertCount(alerts, amu)
	fake.set([]model.Service{cpu}, nil)
	m.poll(ctx, rt)
	amu.Lock()
	news := append([]notify.Alert(nil), (*alerts)[n:]...)
	amu.Unlock()
	reach := false
	for _, a := range news {
		if a.Kind != notify.KindMonitorReachable {
			continue
		}
		reach = true
		for _, l := range alertLines(t, a) {
			if l.Key == "updates" {
				t.Errorf("Updates in \"wieder erreichbar\": %+v", l)
			}
		}
	}
	if !reach {
		t.Fatal("keine Meldung \"wieder erreichbar\"")
	}
	if s := svcAt(t, rt, "updates"); s.State != eval.OK {
		t.Errorf("Updates in der Anlaufzeit: %s", s.State)
	}
	if s := svcAt(t, rt, "reboot"); s.State != eval.Unknown {
		t.Errorf("schon vorher fehlender Wert in der Anlaufzeit: %s, erwartet weiter unbekannt", s.State)
	}
}

// Unbekannt mangels Daten: "keine Daten" statt der Bezeichnung der Regel (#275: "Unbekannt - Firmware-Update
// verfuegbar"); Messgroessen behalten ihre Bezeichnung.
func TestDescribeNoData(t *testing.T) {
	unk := eval.Status{State: eval.Unknown, Level: eval.OK, Threshold: eval.Limit{Off: true}}
	for _, c := range []struct {
		ms     eval.MetricStatus
		kind   string
		de, en string
	}{
		{eval.MetricStatus{Name: eval.KindFirmwareUpdate, Status: unk}, "", "keine Daten", "no data"},
		{eval.MetricStatus{Name: eval.KindSmartFailed, Status: unk}, "", "keine Daten", "no data"},
		{eval.MetricStatus{Name: "util", Status: unk}, model.RuleCPU, "CPU-Auslastung: keine Daten", "CPU utilisation: no data"},
	} {
		got := describe(c.ms, c.kind, false)
		if de, en := modeltest.DE(got), modeltest.EN(got); de != c.de || en != c.en {
			t.Errorf("%s/%s: de %q, en %q", c.ms.Name, c.kind, de, en)
		}
	}
	// gemeldeter Zustand (Regel greift): weiter die Bezeichnung der Regel
	warn := eval.Status{State: eval.Warn, Level: eval.Warn, Threshold: eval.Limit{Off: true}}
	if de := modeltest.DE(describe(eval.MetricStatus{Name: eval.KindFirmwareUpdate, Status: warn}, "", false)); de == "keine Daten" {
		t.Errorf("Warnung beschrieben als %q", de)
	}
}

// Letzter Zugang entfernt, waehrend der Host nicht erreichbar ist: kein "wieder erreichbar" mit allen Diensten
// "noch offen - Unbekannt" (#263).
func TestNoAccessNoReachable(t *testing.T) {
	ctx := context.Background()
	m, alerts, amu := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	cpu := svc("cpu", "cpu", model.Metric{Name: "util", Value: 10, Unit: "%", Rule: model.RuleCPU})
	fake := &fakeCol{svcs: []model.Service{cpu}}
	rt := hostWithFake(t, m, fake)
	m.poll(ctx, rt)
	adoptAll(t, m, rt.host.UID)
	m.poll(ctx, rt)
	fake.set(nil, errors.New("dial tcp 192.0.2.1:6465: i/o timeout"))
	m.poll(ctx, rt)
	m.poll(ctx, rt)
	if v := rt.getView(); v.View != eval.ViewUnreachable {
		t.Fatalf("erwartet nicht erreichbar, %s", v.View)
	}
	shiftRT(rt, -time.Hour)
	n := alertCount(alerts, amu)
	rt.accs = nil
	m.poll(ctx, rt)
	m.poll(ctx, rt)
	amu.Lock()
	defer amu.Unlock()
	for _, a := range (*alerts)[n:] {
		t.Errorf("Meldung ohne Zugang: %s %s", a.Kind, a.Data["lines"])
	}
}

// Host entfernen: aus dem Planer, Loeschvermerk, kein Gedaechtnis der Meldungen mehr (#263).
func TestDeleteHostStopsRounds(t *testing.T) {
	ctx := context.Background()
	m, alerts, amu := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	fake := &fakeCol{svcs: []model.Service{svc("cpu", "cpu", model.Metric{Name: "util", Value: 10, Unit: "%", Rule: model.RuleCPU})}}
	rt := hostWithFake(t, m, fake)
	m.poll(ctx, rt)
	adoptAll(t, m, rt.host.UID)
	m.poll(ctx, rt)
	n := alertCount(alerts, amu)
	if err := m.deleteHost(ctx, rt.host, SystemActor); err != nil {
		t.Fatal(err)
	}
	if _, err := m.store.Host(ctx, rt.host.UID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Host nicht geloescht: %v", err)
	}
	m.rtMu.Lock()
	_, still := m.rts[rt.host.UID]
	m.rtMu.Unlock()
	if still || !rt.removed {
		t.Fatal("Host noch eingeplant")
	}
	m.poll(ctx, rt) // eine noch wartende Runde tut nichts
	m.notifyMu.Lock()
	_, mem := m.notifier.Hosts[rt.host.UID]
	m.notifyMu.Unlock()
	if mem {
		t.Error("Gedaechtnis der Meldungen des geloeschten Hosts noch da")
	}
	if got := alertCount(alerts, amu); got != n {
		t.Errorf("%d Meldung(en) nach dem Entfernen", got-n)
	}
	// Fehler beim Loeschen (schon geloescht): ErrNotFound
	if err := m.deleteHost(ctx, rt.host, SystemActor); !errors.Is(err, ErrNotFound) {
		t.Errorf("zweites Entfernen: %v", err)
	}
}
