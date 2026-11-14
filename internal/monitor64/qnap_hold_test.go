package monitor64

import (
	"context"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/apis"
	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// ageTrackers stellt die letzte Messung aller Tracker eines Hosts um d zurueck (Zeit vergeht, ohne zu warten).
func ageTrackers(rt *hostRT, d time.Duration) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, tr := range rt.Trackers {
		if !tr.LastAt.IsZero() {
			tr.LastAt = tr.LastAt.Add(-d)
		}
	}
}

func qhState(rt *hostRT, key string) eval.State {
	for _, s := range rt.getView().Services {
		if s.Key == key {
			return s.State
		}
	}
	return eval.State(255)
}

// #136 im Kern: Fehlen Platten und Volumes eines SNMP-Zugangs laenger als drei Intervalle (Teilfehler der Tabelle),
// werden sie "Unbekannt" – so bisher bei QNAP. Liefert der Sammler den gehaltenen Stand (ohne Messwerte, mit
// Zustand), bleiben sie OK.
func TestQNAPHoldKeepsState(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	temp := model.Metric{Name: "temp", Value: 35, Unit: "°C", Rule: model.RuleDiskTemp}
	disk := model.Service{Key: "disk:HDD1", Name: "Platte HDD1", Kind: "disk", Default: true, Metrics: []model.Metric{temp}, Text: "35 °C · SMART gut"}
	vol := model.Service{Key: "store:DataVol1", Name: "Volume DataVol1", Kind: "store", Default: true, Text: "Status Ready"}
	up := svc("uptime", "uptime", model.Metric{Name: "uptime", Value: 1000, Unit: "s"})
	fake := &fakeCol{svcs: []model.Service{up, disk, vol}}
	rt := hostWithFake(t, m, fake)
	m.poll(ctx, rt)
	adoptAll(t, m, rt.host.UID)
	m.poll(ctx, rt)
	if qhState(rt, "disk:HDD1") != eval.OK || qhState(rt, "store:DataVol1") != eval.OK {
		t.Fatalf("Ausgang: %s %s", qhState(rt, "disk:HDD1"), qhState(rt, "store:DataVol1"))
	}
	part := &apis.PartialError{Errs: []string{"Profil QNAP QTS, Tabelle 1: request timeout"}, Prefixes: []string{"disk:", "store:"}}

	// bisher: Tabelle fehlt (Teilfehler) – nach mehr als drei Intervallen "Unbekannt"
	fake.set([]model.Service{up}, part)
	m.poll(ctx, rt)
	ageTrackers(rt, 4*time.Minute)
	m.poll(ctx, rt)
	if qhState(rt, "disk:HDD1") != eval.Unknown || qhState(rt, "store:DataVol1") != eval.Unknown {
		t.Fatalf("ohne Halten: %s %s (erwartet Unbekannt)", qhState(rt, "disk:HDD1"), qhState(rt, "store:DataVol1"))
	}

	// neu: der Sammler liefert den gehaltenen Stand – Zustand bleibt OK, keine alten Zahlen im Verlauf
	fake.set([]model.Service{up, disk, vol}, nil)
	m.poll(ctx, rt)
	held := disk
	held.Metrics, held.Text = nil, disk.Text+" · Stand von vor 4 Min."
	heldVol := vol
	heldVol.Text = vol.Text + " · Stand von vor 4 Min."
	fake.set([]model.Service{up, held, heldVol}, part)
	for i := 0; i < 3; i++ {
		ageTrackers(rt, 2*time.Minute)
		m.poll(ctx, rt)
	}
	if qhState(rt, "disk:HDD1") != eval.OK || qhState(rt, "store:DataVol1") != eval.OK {
		t.Fatalf("mit Halten: %s %s (erwartet OK)", qhState(rt, "disk:HDD1"), qhState(rt, "store:DataVol1"))
	}
}
