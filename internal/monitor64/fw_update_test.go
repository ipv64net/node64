package monitor64

import (
	"context"
	"testing"

	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Forum 5134 (Beitrag 9): Die FRITZ!Box meldet "FRITZ!OS-Update verfuegbar", der Dienst Updates bleibt aber gruen.
// Ursache: das Update kam als "Sicherheitsupdates ausstehend", und diese Regel warnt erst nach 24 Stunden (gedacht
// fuer apt, das Sicherheitsupdates oft selbst einspielt). Firmware-Updates von Geraeten haben eine eigene Regel, die
// sofort warnt; die laufende Wartezeit einer Zustandsregel steht am Dienst.
func TestFirmwareUpdateWarns(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	upd := func(code string) model.Service {
		return model.Service{Key: "updates", Name: "Updates", Kind: "updates", Default: true, Text: "FRITZ!OS-Update verfügbar: 8.51",
			Metrics: []model.Metric{{Name: "pending", Value: 1}}, Facts: []model.Fact{{Code: code, Text: "FRITZ!OS-Update verfügbar: 8.51"}}}
	}
	fake := &fakeCol{svcs: []model.Service{upd("firmware_update")}}
	rt := hostWithFake(t, m, fake)
	m.poll(ctx, rt)
	adoptAll(t, m, rt.host.UID)
	m.poll(ctx, rt)
	if st := qhState(rt, "updates"); st != eval.Warn {
		t.Fatalf("Firmware-Update: %v (erwartet Warnung)", st)
	}

	// apt-Sicherheitsupdates: weiter erst nach 24 Stunden, die Wartezeit steht am Dienst
	fake.set([]model.Service{upd("updates_security")}, nil)
	m.poll(ctx, rt)
	m.poll(ctx, rt)
	var sv *SvcView
	for i, s := range rt.getView().Services {
		if s.Key == "updates" {
			sv = &rt.getView().Services[i]
		}
	}
	if sv == nil || sv.State != eval.OK || len(sv.Pending) != 1 || sv.Pending[0].Kind != eval.KindUpdatesSecurity || sv.Pending[0].State != eval.Warn ||
		sv.Pending[0].At.Sub(sv.Pending[0].Since).Hours() != 24 {
		t.Fatalf("Sicherheitsupdates: %+v", sv)
	}
}
