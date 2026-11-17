package snmp

import (
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// #204: QNAP beantwortet die Plattentabelle zeitweise ohne Fehler, aber unvollstaendig (einzelne Zeilen fehlen) oder
// leer. Bisher galt das als vollstaendige Antwort: die fehlenden Platten fielen aus der Runde und standen nach drei
// Intervallen auf "Unbekannt" (mit Alarm und Entwarnung). Jetzt kommen sie bis zu 10 Minuten mit dem letzten Stand.
func TestQNAPTableRowsMissing(t *testing.T) {
	m := qnapMIB()
	c, _, now := newTestCollector(t, m, Config{})
	collect := func() map[string]string {
		t.Helper()
		*now = now.Add(time.Minute)
		svcs, err := c.Collect(t.Context())
		if err != nil {
			t.Fatalf("Teilfehler: %v", err)
		}
		out := map[string]string{}
		for _, s := range svcs {
			if strings.HasPrefix(s.Key, "disk:") || strings.HasPrefix(s.Key, "store:") {
				txt := "frisch"
				if strings.Contains(de(s.Text), "Stand von vor") {
					txt = "gehalten"
				}
				if !hasMetric(s, "temp") && strings.HasPrefix(s.Key, "disk:") && txt == "frisch" {
					txt = "ohne Wert"
				}
				out[s.Key] = txt
			}
		}
		return out
	}
	if got := collect(); got["disk:HDD1"] != "frisch" || got["disk:HDD2"] != "frisch" || got["store:DataVol1"] != "frisch" {
		t.Fatalf("Ausgang: %v", got)
	}

	// Zeile HDD2 fehlt ganz: HDD2 gehalten, HDD1 frisch
	row2 := map[string]pdu{}
	for _, col := range []string{"2", "3", "4", "7"} {
		o := qnapBase + ".11.1." + col + ".2"
		row2[o] = m.vals[o]
		m.del(o)
	}
	if got := collect(); got["disk:HDD1"] != "frisch" || got["disk:HDD2"] != "gehalten" || len(got) != 3 {
		t.Fatalf("Zeile fehlt: %v", got)
	}

	// nur die Namensspalte fehlt: kein Dienst unter der Indexnummer ("disk:2"), HDD2 weiter gehalten
	for o, v := range row2 {
		if !strings.HasSuffix(o, ".11.1.2.2") {
			m.set(o, v.Type, v.Value)
		}
	}
	if got := collect(); got["disk:HDD2"] != "gehalten" || got["disk:2"] != "" || len(got) != 3 {
		t.Fatalf("Name fehlt: %v", got)
	}
	m.set(qnapBase+".11.1.2.2", gosnmp.OctetString, []byte("HDD2"))

	// leere Tabellen (ohne Fehler): alle gehalten
	saved := map[string]pdu{}
	for o, v := range m.vals {
		if strings.HasPrefix(o, qnapBase+".11.") || strings.HasPrefix(o, qnapBase+".17.") {
			saved[o] = v
			m.del(o)
		}
	}
	for i := 0; i < 5; i++ {
		if got := collect(); got["disk:HDD1"] != "gehalten" || got["disk:HDD2"] != "gehalten" || got["store:DataVol1"] != "gehalten" {
			t.Fatalf("leere Tabelle, Runde %d: %v", i, got)
		}
	}
	// wieder da: frisch
	for o, v := range saved {
		m.set(o, v.Type, v.Value)
	}
	if got := collect(); got["disk:HDD1"] != "frisch" || got["disk:HDD2"] != "frisch" || got["store:DataVol1"] != "frisch" {
		t.Fatalf("nach Erholung: %v", got)
	}

	// ausgebaute Platte: nach mehr als 10 Minuten fehlt sie
	for _, col := range []string{"2", "3", "4", "7"} {
		m.del(qnapBase + ".11.1." + col + ".2")
	}
	for i := 0; i < 10; i++ {
		if got := collect(); got["disk:HDD2"] != "gehalten" {
			t.Fatalf("Minute %d: %v", i+1, got)
		}
	}
	if got := collect(); got["disk:HDD2"] != "" || got["disk:HDD1"] != "frisch" {
		t.Fatalf("nach Ablauf: %v", got)
	}
}
