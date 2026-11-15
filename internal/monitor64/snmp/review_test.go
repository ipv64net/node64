package snmp

import (
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Review 9: "Probe ohne Wert" ueberbrueckte nur ein schon gewaehltes Profil. Fehlte der Wert bei der ersten Wahl
// (z. B. nach einem Neustart der Node), fehlte das Profil samt Platten und Volumes 60 Minuten. Jetzt fragt die
// naechste Runde neu.
func TestReviewProbeMissingFirstSelection(t *testing.T) {
	m := qnapMIB()
	m.del(qnapBase + ".4.0")
	c, _, now := newTestCollector(t, m, Config{})
	_, _ = c.Collect(t.Context())
	if len(c.profiles) != 0 {
		t.Fatalf("Profil ohne Probe gewaehlt: %v", c.profiles)
	}
	m.set(qnapBase+".4.0", gosnmp.OctetString, []byte("3.8 GB"))
	*now = now.Add(time.Minute)
	svcs, _ := c.Collect(t.Context())
	if len(c.profiles) != 1 || c.profiles[0].ID != "qnap" {
		t.Fatalf("Profil in der naechsten Runde nicht gewaehlt: %v", c.profiles)
	}
	svcByKey(t, svcs, "disk:HDD1")
}

// Review 10: Scheiterte die Abfrage der Skalare eines Profils, ergaenzte useHeld die Dienste zwar, sie wurden aber
// nicht ausgegeben (return vor der Ausgabe) - Platten und Volumes fehlten trotz Ueberbrueckung.
func TestReviewScalarFailUsesHeld(t *testing.T) {
	c, fc, now := newTestCollector(t, qnapMIB(), Config{})
	if _, err := c.Collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	fc.failOn = qnapBase + ".5" // Skalare (Temperaturen) scheitern
	*now = now.Add(time.Minute)
	svcs, err := c.Collect(t.Context())
	if err == nil {
		t.Fatal("kein Teilfehler")
	}
	h1 := svcByKey(t, svcs, "disk:HDD1")
	if !strings.Contains(de(h1.Text), "Stand von vor") {
		t.Fatalf("Platte nicht aus dem letzten Stand: %+v", h1)
	}
	svcByKey(t, svcs, "store:DataVol1")
}
