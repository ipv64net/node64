package monitor64

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// Dashboard: Probleme fuer "Letzte Stoerungen" (neueste zuerst, Zustand, Pfad) und die Karte mit Kennzahlen.
func TestDashIncidentsAndCard(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	rec := e.do("POST", "/api/monitor64/hosts", map[string]any{"name": "nas01", "address": "192.0.2.20", "paused": true,
		"services": []map[string]any{{"key": "fs:/", "name": "Dateisystem /", "kind": "fs", "default": true}}, "adopt": []string{"fs:/"}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created struct{ UID string }
	decodeBody(t, rec.Body.Bytes(), &created)
	now := time.Now()
	for _, p := range []struct {
		uid, key, state, worst string
		opened                 time.Duration
		closed                 string
	}{
		{"p-old", "fs:/", "ok", "crit", -5 * time.Hour, ts(now.Add(-4 * time.Hour))},
		{"p-open", "fs:/", "warn", "warn", -time.Hour, ""},
		{"p-host", "", "unreachable", "unreachable", -3 * time.Hour, ts(now.Add(-2 * time.Hour))},
		{"p-gone", "cpu", "crit", "crit", -time.Minute, ""},
	} {
		host := created.UID
		if p.uid == "p-gone" {
			host = "geloeschter-host"
		}
		if _, err := e.m.st.Writer().Exec(`INSERT INTO m64_problems (uid, host_uid, service_key, state, worst, opened_at, closed_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			p.uid, host, p.key, p.state, p.worst, ts(now.Add(p.opened)), p.closed, tsNow()); err != nil {
			t.Fatal(err)
		}
	}
	inc := e.m.DashIncidents(ctx, 10)
	if len(inc) != 3 {
		t.Fatalf("incidents: %+v", inc)
	}
	if a := inc[0]; a.Name != "nas01 · Dateisystem /" || !a.Open || !a.Warn || a.StateKey != "monitor64.state.warn" || a.Path != "/monitor64/host/"+created.UID || a.Source != "nav.monitor64" {
		t.Fatalf("open warn: %+v", a)
	}
	if b := inc[1]; b.Name != "nas01" || b.Open || b.StateKey != "monitor64.state.unreachable" {
		t.Fatalf("host unreachable: %+v", b)
	}
	if c := inc[2]; c.Open || c.Warn || c.StateKey != "monitor64.state.crit" || c.EndedAt.IsZero() {
		t.Fatalf("closed crit keeps worst state: %+v", c)
	}
	if got := e.m.DashIncidents(ctx, 1); len(got) != 1 || got[0].Name != inc[0].Name {
		t.Fatalf("limit: %+v", got)
	}
	c, err := e.m.Card(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stats := map[string]int64{}
	var last string
	for _, s := range c.Stats {
		stats[s.LabelKey] = s.Value
		if s.LabelKey == "monitor64.card.last" {
			last = s.Text
		}
	}
	if c.Path != "/monitor64" || c.Image != "monitor64.svg" || stats["monitor64.card.hosts"] != 1 || stats["monitor64.card.paused"] != 1 || last != "nas01 · Dateisystem /" {
		t.Fatalf("card: %+v", c.Stats)
	}
}
