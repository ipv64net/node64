package m64cluster

import (
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/peer"
)

// C2-2: ausgesetzte Mitglieder und solche mit Monitor64 aus zaehlen als nicht erreichbar (statt zu fehlen), Mitglieder
// ohne Monitor64, die kein Host nennt, zaehlen nicht.
func TestAreaPeersCountsInactiveMembers(t *testing.T) {
	now := time.Now()
	on := []string{"monitor64/config", "monitor64/status"}
	list := []peer.Member{
		{NodeID: "a", Name: "A", Sync: on, LastSeen: now},                              // gleicht ab, erreichbar
		{NodeID: "b", Name: "B", Sync: on, LastSeen: now, State: "suspended"},          // ausgesetzt
		{NodeID: "c", Name: "C", Sync: []string{"healthchecks/checks"}, LastSeen: now}, // Monitor64 aus, Host nennt C
		{NodeID: "d", Name: "D", Sync: nil, LastSeen: now},                             // Monitor64 aus, kein Host nennt D
	}
	used := func(id string) bool { return id == "c" }
	got := areaPeers(true, list, "config", used)
	want := map[string]bool{"a": true, "b": false, "c": false}
	if len(got) != len(want) {
		t.Fatalf("peers: %+v", got)
	}
	for _, p := range got {
		on, ok := want[p.ID]
		if !ok || p.Online != on {
			t.Fatalf("peer %s online=%v (want %v, listed %v): %+v", p.ID, p.Online, on, ok, got)
		}
	}
	if got := areaPeers(false, list, "config", used); got != nil {
		t.Fatalf("area off here: no members, got %+v", got)
	}
}

// Mitglied online, aber laenger als ein Ping-Abstand ohne Antwort: Silent.
func TestAreaPeersSilent(t *testing.T) {
	area := []string{"monitor64/config"}
	list := []peer.Member{
		{NodeID: "fresh", LastSeen: time.Now(), Sync: area},
		{NodeID: "quiet", LastSeen: time.Now().Add(-70 * time.Second), Sync: area},
	}
	out := areaPeers(true, list, "config", func(string) bool { return false })
	if len(out) != 2 || out[0].Silent || !out[1].Silent || !out[1].Online {
		t.Fatalf("peers %+v", out)
	}
}
