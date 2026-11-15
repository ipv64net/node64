package trap

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Review 3: Der Replay-Schutz fuer v3-Traps galt je Engine-ID, Benutzer und Absender-Adresse und verfiel nach einer
// Stunde - ein mitgeschnittener Trap wurde nach einer Stunde bzw. ueber die Adresse eines anderen Hosts (gleicher
// Benutzer) wieder angenommen. Der Stand gilt je Engine-ID und Benutzer ohne Verfall (wie v1.5.0).
func TestReviewV3ReplayNoExpiryNoOtherSource(t *testing.T) {
	r, _ := newRecv(t, Config{})
	other := netip.MustParseAddr("192.0.2.11")
	if err := r.SetHosts([]Host{{ID: "h1", Addrs: []netip.Addr{hostIP}, Users: []User{v3User}}, {ID: "h2", Addrs: []netip.Addr{other}, Users: []User{v3User}}}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	g := v3Client(v3User, senderEID)
	sp := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime = 5, 1000
	old := capture(t, g, linkDown(2, "eth2"))
	if _, ev := r.process(old, hostIP); ev == nil || ev.Rejected != "" {
		t.Fatalf("erster Trap: %+v", ev)
	}
	now = now.Add(200 * time.Second)
	if _, ev := r.process(old, other); ev == nil || ev.Rejected != "time" {
		t.Fatalf("Wiederholung ueber die Adresse eines anderen Hosts angenommen: %+v", ev)
	}
	now = now.Add(2 * time.Hour)
	if _, ev := r.process(old, hostIP); ev == nil || ev.Rejected != "time" {
		t.Fatalf("Wiederholung nach zwei Stunden angenommen: %+v", ev)
	}
}
