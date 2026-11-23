package monitor64

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/metrics"
	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Ist ein Host nicht erreichbar (z. B. SNMP ohne Antwort), verschwanden alle Messwerte: CPU war nicht mehr
// anklickbar, die Diagramme der Host-Seite fehlten, obwohl der Verlauf gespeichert ist. Jetzt bleiben die zuletzt
// gelieferten Werte als "letzter Wert" (stale_at) sichtbar - nur Anzeige: weder im Prometheus-Export noch bewertet.
func TestStaleValuesWhenUnreachable(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	cpu := svc("cpu", "cpu", model.Metric{Name: "util", Value: 42, Unit: "%", Rule: model.RuleCPU})
	mem := svc("mem", "mem", model.Metric{Name: "used", Value: 61, Unit: "%", Rule: model.RuleMem})
	fake := &fakeCol{svcs: []model.Service{cpu, mem}}
	rt := hostWithFake(t, e.m, fake)
	uid := rt.host.UID
	e.m.poll(ctx, rt)
	adoptAll(t, e.m, uid)
	e.m.poll(ctx, rt)

	type detail struct {
		Charts   []chartDef `json:"charts"`
		Services []struct {
			Key     string `json:"key"`
			Metrics []struct {
				Name    string  `json:"name"`
				Value   float64 `json:"value"`
				Unit    string  `json:"unit"`
				StaleAt string  `json:"stale_at"`
			} `json:"metrics"`
		} `json:"services"`
	}
	get := func() detail {
		t.Helper()
		w := e.do("GET", "/api/monitor64/hosts/"+uid, nil)
		var d detail
		if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	prom := func() string {
		w := metrics.New()
		e.m.Metrics(ctx, w)
		var b bytes.Buffer
		_, _ = w.WriteTo(&b)
		return b.String()
	}
	if d := get(); len(d.Charts) != 2 {
		t.Fatalf("Ausgang: Diagramme %+v", d.Charts)
	}
	if !strings.Contains(prom(), "node64_monitor_value{") {
		t.Fatal("Ausgang: keine Werte im Export")
	}
	if ov := e.do("GET", "/api/monitor64/overview", nil).Body.String(); !strings.Contains(ov, `"has_cpu":true`) {
		t.Fatalf("Ausgang: Uebersicht ohne CPU: %s", ov)
	}

	// Host nicht erreichbar
	fake.set(nil, errors.New("request timeout"))
	for i := 0; i < 3; i++ {
		ageTrackers(rt, 2*time.Minute)
		e.m.poll(ctx, rt)
	}
	d := get()
	if len(d.Charts) != 2 {
		t.Fatalf("Diagramme weg: %+v", d.Charts)
	}
	got := map[string]float64{}
	for _, s := range d.Services {
		for _, mt := range s.Metrics {
			if mt.StaleAt == "" {
				t.Errorf("%s/%s ohne stale_at", s.Key, mt.Name)
			}
			got[s.Key+"|"+mt.Name] = mt.Value
		}
	}
	if got["cpu|util"] != 42 || got["mem|used"] != 61 {
		t.Fatalf("letzte Werte: %v", got)
	}
	for _, s := range rt.getView().Services {
		if s.Key == "cpu" && (len(s.Metrics) != 1 || s.Metrics[0].Status.State != eval.Unknown) {
			t.Fatalf("Zustand des letzten Werts: %+v", s.Metrics)
		}
	}
	if strings.Contains(prom(), "node64_monitor_value{") {
		t.Fatalf("alte Werte im Prometheus-Export:\n%s", prom())
	}
	// Uebersicht: keine Balken aus alten Werten
	if ov := e.do("GET", "/api/monitor64/overview", nil).Body.String(); strings.Contains(ov, `"has_cpu":true`) || strings.Contains(ov, `"label":"cpu"`) {
		t.Fatalf("Uebersicht mit altem CPU-Wert: %s", ov)
	}

	// ueberlebt den Neustart (gespeicherter Laufzeitstand)
	rt.mu.Lock()
	b, err := json.Marshal(rt)
	rt.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var back hostRT
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if l := back.LastMetrics["cpu"]; len(l.Metrics) != 1 || l.Metrics[0].Value != 42 || l.At.IsZero() {
		t.Fatalf("nach Neustart: %+v", back.LastMetrics)
	}

	// wieder erreichbar: frische Werte ohne stale_at
	cpu.Metrics[0].Value = 17
	fake.set([]model.Service{cpu, mem}, nil)
	e.m.poll(ctx, rt)
	for _, s := range get().Services {
		for _, mt := range s.Metrics {
			if mt.StaleAt != "" || (s.Key == "cpu" && mt.Value != 17) {
				t.Fatalf("nach Erholung: %s %+v", s.Key, mt)
			}
		}
	}

	// entfernte Dienste vergessen ihre letzten Werte
	if _, err := e.m.st.Writer().ExecContext(ctx, `DELETE FROM m64_services WHERE host_uid = ? AND key = 'mem'`, uid); err != nil {
		t.Fatal(err)
	}
	e.m.poll(ctx, rt)
	rt.mu.Lock()
	_, still := rt.LastMetrics["mem"]
	rt.mu.Unlock()
	if still {
		t.Fatal("letzte Werte eines entfernten Dienstes behalten")
	}
}
