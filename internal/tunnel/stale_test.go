package tunnel

import (
	"context"
	"testing"
)

// TestUpdateIgnoresStaleSlot: eine beendete Slot-Goroutine (SetEdges mit neuer Adresse, SetSessions runter und wieder
// hoch) schreibt nicht in den neu angelegten Zustand desselben Namens und Slots; die eigene schon.
func TestUpdateIgnoresStaleSlot(t *testing.T) {
	c := NewClient(ClientConfig{Edges: []Edge{{Name: "A", Host: "a.test"}}, Sessions: 1})
	old := c.st["A"][0]
	stale := context.WithValue(context.Background(), ownState{}, old)
	c.st["A"][0] = newState(Edge{Name: "A", Host: "a.test"}) // Slot neu angelegt
	c.update(stale, "A", 0, func(s *edgeState) { s.Connected = true })
	if c.st["A"][0].Connected || old.Connected {
		t.Fatal("stale goroutine wrote into the new slot state")
	}
	own := context.WithValue(context.Background(), ownState{}, c.st["A"][0])
	c.update(own, "A", 0, func(s *edgeState) { s.Connected = true })
	if !c.st["A"][0].Connected {
		t.Fatal("update of the own slot state ignored")
	}
	c.update(context.Background(), "A", 0, func(s *edgeState) { s.Connected = false }) // ohne Zuordnung (Tests): wie bisher
	if c.st["A"][0].Connected {
		t.Fatal("update without owner ignored")
	}
}
