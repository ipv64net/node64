package monitor64

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// #142: Probleme eines Hosts im Wartungsfenster (z. B. PBS tagsueber aus, 97 Eintraege) stehen in der Uebersicht und
// auf der Problemseite hinter den echten Problemen und sind gekennzeichnet; die Oberflaeche klappt sie ein.
func TestMaintProblemsLast(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newTestModule(t)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	full := model.Metric{Name: "used", Value: 99, Unit: "%", Rule: model.RuleFS, Max: 1e12}
	mk := func(name string) *hostRT {
		fake := &fakeCol{svcs: []model.Service{svc("fs:/", "fs", full), svc("fs:/data", "fs", full)}}
		rt := hostWithFake(t, m, fake)
		rt.mu.Lock()
		rt.host.Name = name
		rt.mu.Unlock()
		if err := m.store.SaveHost(ctx, rt.host, SystemActor); err != nil {
			t.Fatal(err)
		}
		m.poll(ctx, rt)
		adoptAll(t, m, rt.host.UID)
		return rt
	}
	pbs := mk("pbs")
	nas := mk("nas")
	// pbs in Wartung (laufendes Fenster), nas nicht
	w := maintRow{Title: "tagsueber aus", Hosts: []string{pbs.host.UID}, Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)}
	if err := m.store.SaveMaint(ctx, &w, SystemActor); err != nil {
		t.Fatal(err)
	}
	m.reloadConfig(ctx)
	for i := 0; i < 2; i++ {
		m.poll(ctx, pbs)
		m.poll(ctx, nas)
	}
	ov := m.overview(ctx)
	if len(ov.Problems) != 4 {
		t.Fatalf("Uebersicht: %d Probleme", len(ov.Problems))
	}
	for i, p := range ov.Problems {
		if want := i >= 2; p.Maint != want || (want && p.Host != "pbs") || (!want && p.Host != "nas") {
			t.Fatalf("Uebersicht, Reihenfolge %d: %+v", i, p)
		}
	}
	req := httptest.NewRequest("GET", "/api/monitor64/problems?status=open", nil)
	out, err := m.problems(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out.Problems)
	if len(out.Problems) != 4 || out.Problems[0].Maint || !out.Problems[3].Maint || out.Problems[3].Host != "pbs" {
		t.Fatalf("Problemseite: %s", b)
	}
}
