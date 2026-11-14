package snmp

import (
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

const qnapBase = ".1.3.6.1.4.1.24681.1.2"

// qnapMIB: QNAP mit zwei Platten und einem Volume (NAS-MIB).
func qnapMIB() *mib {
	m := sysMIB("Linux TS-453D 5.10.60-qnap #1 SMP", ".1.3.6.1.4.1.8072.3.2.10")
	q := qnapBase
	m.set(q+".4.0", gosnmp.OctetString, []byte("3.8 GB"))
	m.set(q+".5.0", gosnmp.OctetString, []byte("47 C/116 F"))
	m.set(q+".6.0", gosnmp.OctetString, []byte("39 C/102 F"))
	m.set(q+".11.1.2.1", gosnmp.OctetString, []byte("HDD1"))
	m.set(q+".11.1.2.2", gosnmp.OctetString, []byte("HDD2"))
	m.set(q+".11.1.3.1", gosnmp.OctetString, []byte("35 C/95 F"))
	m.set(q+".11.1.3.2", gosnmp.OctetString, []byte("36 C/96 F"))
	m.set(q+".11.1.4.1", gosnmp.Integer, 0)
	m.set(q+".11.1.4.2", gosnmp.Integer, 0)
	m.set(q+".11.1.7.1", gosnmp.OctetString, []byte("GOOD"))
	m.set(q+".11.1.7.2", gosnmp.OctetString, []byte("GOOD"))
	m.set(q+".17.1.2.1", gosnmp.OctetString, []byte("DataVol1"))
	m.set(q+".17.1.6.1", gosnmp.OctetString, []byte("Ready"))
	return m
}

func keysOfKind(svcs []string, prefix string) int {
	n := 0
	for _, k := range svcs {
		if strings.HasPrefix(k, prefix) {
			n++
		}
	}
	return n
}

// #136: Die Tabellen der NAS-MIB antworten bei QNAP zeitweise nicht rechtzeitig. Ein einzelner Aussetzer wird in der
// Runde noch einmal versucht; haelt er an, liefert der Sammler die letzten Werte der Platten und Volumes noch eine
// Weile (mit Hinweis, ohne Messwerte) weiter, statt sie fehlen zu lassen – sonst stehen alle Platten nach drei
// Intervallen auf "Unbekannt". Erst wenn die Tabelle laenger ausbleibt, fehlen sie.
func TestQNAPTableGap(t *testing.T) {
	c, fc, now := newTestCollector(t, qnapMIB(), Config{})
	keys := func() []string {
		t.Helper()
		svcs, _ := c.Collect(t.Context())
		var out []string
		for _, s := range svcs {
			out = append(out, s.Key)
		}
		return out
	}
	if k := keys(); keysOfKind(k, "disk:") != 2 || keysOfKind(k, "store:") != 1 {
		t.Fatalf("Runde 1: %v", k)
	}

	// ein einzelner Aussetzer: die Wiederholung in derselben Runde holt die frischen Werte
	fc.failOn, fc.failTimes = qnapBase+".11", 1
	*now = now.Add(time.Minute)
	svcs, err := c.Collect(t.Context())
	if err != nil {
		t.Fatalf("einzelner Aussetzer: %v", err)
	}
	if h1 := svcByKey(t, svcs, "disk:HDD1"); !hasMetric(h1, "temp") || strings.Contains(h1.Text, "Stand") {
		t.Fatalf("nach Wiederholung nicht frisch: %+v", h1)
	}

	// anhaltender Aussetzer: Platten und Volume kommen mit dem letzten Stand (ohne Messwerte, mit Hinweis) und als
	// Teilfehler
	fc.failOn, fc.failTimes = qnapBase+".1", 0 // beide Tabellen
	for i := 1; i <= 5; i++ {
		*now = now.Add(time.Minute)
		svcs, err = c.Collect(t.Context())
		if err == nil || !strings.Contains(deErr(err), "Profil") {
			t.Fatalf("Runde %d ohne Teilfehler: %v", i, err)
		}
		h1 := svcByKey(t, svcs, "disk:HDD1")
		if hasMetric(h1, "temp") || !strings.Contains(de(h1.Text), "Stand von vor") {
			t.Fatalf("Runde %d: gehaltene Platte %+v", i, h1)
		}
		svcByKey(t, svcs, "store:DataVol1")
	}
	// nach mehr als 10 Minuten ohne Tabelle fehlen sie (dann gilt wieder: drei Intervalle, dann Unbekannt)
	*now = now.Add(6 * time.Minute)
	if k := keys(); keysOfKind(k, "disk:") != 0 || keysOfKind(k, "store:") != 0 {
		t.Fatalf("nach Ablauf noch gehalten: %v", k)
	}
	// wieder da: frische Werte
	fc.failOn = ""
	*now = now.Add(time.Minute)
	svcs, err = c.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if h1 := svcByKey(t, svcs, "disk:HDD1"); !hasMetric(h1, "temp") || strings.Contains(de(h1.Text), "Stand von vor") {
		t.Fatalf("nach Erholung: %+v", h1)
	}
}

// #136: Antwortet die Probe des Profils bei der stuendlichen Neuwahl einmal nicht mit Wert, bleibt das Profil gewaehlt
// (vorher fehlten Platten und Volumes dann eine Stunde lang und galten als verschwunden).
func TestQNAPProbeGap(t *testing.T) {
	m := qnapMIB()
	c, _, now := newTestCollector(t, m, Config{})
	if _, err := c.Collect(t.Context()); err != nil || len(c.profiles) != 1 {
		t.Fatalf("Runde 1: %v %v", err, c.profiles)
	}
	m.del(qnapBase + ".4.0")
	*now = now.Add(profileEvery + time.Minute)
	svcs, _ := c.Collect(t.Context())
	if len(c.profiles) != 1 || c.profiles[0].ID != "qnap" {
		t.Fatalf("Profil nach fehlender Probe weg: %v", c.profiles)
	}
	svcByKey(t, svcs, "disk:HDD1")
	// fehlt die Probe mehrmals hintereinander, gilt die neue Wahl
	for i := 0; i < 3; i++ {
		*now = now.Add(time.Minute)
		_, _ = c.Collect(t.Context())
	}
	if len(c.profiles) != 0 {
		t.Fatalf("Profil trotz dauerhaft fehlender Probe: %v", c.profiles)
	}
}
