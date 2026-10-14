package healthchecks

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// Nachgeladener Verlauf: Einzelpunkte ohne Doppelte, eigene Messstelle ausgelassen, Stundenwerte nur fuer
// Stunden ohne Einzelpunkte; Diagramm zaehlt Stunden aus beiden Ablagen zusammen.
func TestHistoryBackfill(t *testing.T) {
	m, srv := newTestModule(t)
	ctx := context.Background()
	me, other := "selfnode0000000000000000000000aa", "othernode000000000000000000000bb"
	if err := m.core.SetSetting(ctx, "node.id", me); err != nil {
		t.Fatal(err)
	}
	self.Lock()
	self.id = ""
	self.Unlock()
	t.Cleanup(func() { self.Lock(); self.id = ""; self.Unlock() })
	m.SetLinked(func() bool { return true })
	code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": "fremd", "type": "icmp", "target": "10.0.0.2", "execution": "local", "nodes": []string{other}})
	if code != 201 && code != 200 {
		t.Fatalf("create: %d %s", code, b)
	}
	var c struct{ Token string }
	_ = json.Unmarshal(b, &c)

	if gaps := m.HistoryGaps(ctx, 48*time.Hour); gaps[c.Token].IsZero() {
		t.Fatal("check without remote points must have a gap")
	}
	t0 := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Hour)
	pts := []HistoryPoint{
		{Source: "loc:fsn", Time: t0, Status: 1, MS: 10},
		{Source: "loc:fsn", Time: t0.Add(time.Minute), Status: 0},
		{Source: "node:" + me, Time: t0, Status: 1, MS: 5}, // eigene Messstelle: nicht uebernehmen
	}
	if n := m.StoreHistory(ctx, c.Token, pts); n != 2 {
		t.Fatalf("stored %d, want 2", n)
	}
	if n := m.StoreHistory(ctx, c.Token, pts); n != 0 {
		t.Fatalf("second load stored %d, want 0 (no duplicates)", n)
	}
	hours := []HistoryPoint{
		{Source: "loc:fsn", Time: t0, Count: 120, Up: 120, MS: 9},                 // Stunde hat Einzelpunkte: auslassen
		{Source: "loc:fsn", Time: t0.Add(-time.Hour), Count: 120, Up: 60, MS: 11}, // davor: uebernehmen
	}
	if n := m.StoreHistoryHourly(ctx, c.Token, hours); n != 1 {
		t.Fatalf("hourly stored %d, want 1", n)
	}
	if gaps := m.HistoryGaps(ctx, 48*time.Hour); !gaps[c.Token].Equal(t0.Add(time.Minute)) {
		t.Fatalf("gap after load = %v, want from last point %v", gaps[c.Token], t0.Add(time.Minute))
	}
}
