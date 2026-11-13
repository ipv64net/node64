package snmp

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/ipv64net/node64/internal/monitor64/apis"
)

// TestWalkLargeIFTable: eine IF-Tabelle mit vielen Spalten und mehr als 3000 Ports wird vollstaendig gelesen
// (frueher: feste Grenze von 1000 Anfragen bei 3 Zeilen je GETBULK).
func TestWalkLargeIFTable(t *testing.T) {
	m := newMIB()
	cols := []string{ifAdmin, ifOper, ifSpeed, ifInDisc, ifInErr, ifOutDisc, ifOutErr, ifHigh, ifHCInOct, ifHCInUc, ifHCInMc, ifHCInBc,
		ifHCOutOc, ifHCOutUc, ifHCOutMc, ifHCOutBc, dot3Dup}
	const rows = 4000
	for i := 1; i <= rows; i++ {
		for _, c := range cols {
			m.set(c+"."+strconv.Itoa(i), gosnmp.Integer, 1)
		}
	}
	tab, err := walkColumns(context.Background(), &fakeConn{m: m}, cols, DefaultMaxRep)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cols {
		if n := len(tab.col(normOID(c))); n != rows {
			t.Fatalf("%s: %d Zeilen", c, n)
		}
	}
	// v1 (GETNEXT, eine Zeile je Anfrage)
	tab, err = walkColumns(context.Background(), &fakeConn{m: m, isV1: true}, cols[:3], DefaultMaxRep)
	if err != nil || len(tab.col(normOID(ifSpeed))) != rows {
		t.Fatalf("v1: %v", err)
	}
}

// TestLAGWithoutPortStatus: scheitert die IF-Abfrage, rechnet LAG nicht mit fehlendem bzw. altem Portstatus (frueher:
// alle Mitglieder "down"); der Teilfehler deckt "bond:" ab.
func TestLAGWithoutPortStatus(t *testing.T) {
	m := loadWalk(t, "testdata/switch.walk")
	c, fc, now := newTestCollector(t, m, Config{})
	fc.failOn = normOID(ifAdmin) // Portstatus scheitert, Namen kommen
	s, err := c.Collect(context.Background())
	var pe *apis.PartialError
	if !errors.As(err, &pe) || !pe.Affects("bond:Po1") {
		t.Fatalf("Teilfehler: %v", err)
	}
	if hasKey(s, "bond:Po1") {
		t.Fatalf("Bond ohne Portstatus: %+v", svcByKey(t, s, "bond:Po1"))
	}
	// naechste Runde mit Portstatus: Bond wie gewohnt (ein Mitglied down)
	fc.failOn = ""
	*now = now.Add(time.Minute)
	s = collect(t, c)
	if v := metric(t, svcByKey(t, s, "bond:Po1"), "members_up"); v.Value != 1 {
		t.Fatalf("members_up: %+v", v)
	}
	// IF scheitert wieder: kein Bond aus dem Stand der vorigen Runde
	fc.failOn = normOID(ifAdmin)
	*now = now.Add(time.Minute)
	m.set(".1.3.6.1.2.1.2.2.1.8.4", gosnmp.Integer, 1)
	if s, _ = c.Collect(context.Background()); hasKey(s, "bond:Po1") {
		t.Fatal("Bond aus altem Portstatus")
	}
}

// TestRateMeasureTime: Raten beziehen sich auf den Messzeitpunkt der Zaehler, nicht auf den Rundenbeginn (die erste
// Runde liest zusaetzlich Namen und Profile und dauert laenger).
func TestRateMeasureTime(t *testing.T) {
	m := loadWalk(t, "testdata/switch.walk")
	c, fc, now := newTestCollector(t, m, Config{})
	const inOct = ".1.3.6.1.2.1.31.1.1.1.6.1"
	tick := func(d time.Duration) { // Zeit vergeht, der Port empfaengt 1 MB/s
		*now = now.Add(d)
		m.add(inOct, uint64(d/time.Second)*1_000_000)
	}
	fc.onReq = func() { tick(time.Second) } // jede Anfrage dauert 1 s
	collect(t, c)
	tick(60 * time.Second)
	s := collect(t, c)
	if v := metric(t, svcByKey(t, s, "if:Gi1/0/1"), "in"); !near(v.Value, 8) {
		t.Fatalf("Rate: %v Mbit/s statt 8", v.Value)
	}
}

// TestProfileProbeRetry: scheitert die Probe bei der ersten Profilwahl, fragt die naechste Runde neu (frueher erst nach
// 60 min); bis dahin deckt der Teilfehler die Profil-Dienste ab.
func TestProfileProbeRetry(t *testing.T) {
	m := sysMIB("Linux TS-453D 5.10.60-qnap #1 SMP", ".1.3.6.1.4.1.8072.3.2.10")
	m.set(".1.3.6.1.4.1.24681.1.2.4.0", gosnmp.OctetString, []byte("3.8 GB"))
	m.set(".1.3.6.1.4.1.24681.1.2.5.0", gosnmp.OctetString, []byte("47 C/116 F"))
	c, fc, now := newTestCollector(t, m, Config{})
	fc.failOn = ".1.3.6.1.4.1.24681.1.2.4.0"
	s, err := c.Collect(context.Background())
	var pe *apis.PartialError
	if !errors.As(err, &pe) || !pe.Affects("temp:cpu") || hasKey(s, "temp:cpu") {
		t.Fatalf("Probe gescheitert: %v", err)
	}
	fc.failOn = ""
	*now = now.Add(time.Minute)
	s = collect(t, c)
	if len(c.profiles) != 1 || c.profiles[0].ID != "qnap" || !hasKey(s, "temp:cpu") {
		t.Fatalf("Profil nicht neu gewaehlt: %v", c.profiles)
	}
}

// TestMikrotikPoEStates: mtxrPOEStatus laut MIKROTIK-MIB (7 currentTooLow, 8 powerReset ... 15 lowVoltageTooLow).
func TestMikrotikPoEStates(t *testing.T) {
	m := loadWalk(t, "testdata/mikrotik.walk")
	const st = ".1.3.6.1.4.1.14988.1.1.15.1.1.3.2"
	for _, tc := range []struct {
		v     int
		fault bool
		text  string
	}{{3, false, "versorgt"}, {7, false, "Strom zu niedrig"}, {8, false, "Versorgung neu gestartet"}, {9, true, "Spannung zu hoch"},
		{10, true, "Controller-Fehler"}, {11, false, "Controller-Update"}, {12, false, "PoE-Eingang erkannt"},
		{13, true, "kein gültiges Netzteil"}, {14, false, "Controller startet"}, {15, true, "Eingangsspannung zu niedrig"}, {5, true, "Kurzschluss"}} {
		m.set(st, gosnmp.Integer, tc.v)
		c, _, _ := newTestCollector(t, m, Config{})
		p := svcByKey(t, collect(t, c), "poe:ether2")
		if _, ok := fact(p, FactPoEFault); ok != tc.fault || p.Text == "" || !strings.Contains(p.Text, tc.text) {
			t.Fatalf("Zustand %d: fault=%v %+v", tc.v, ok, p)
		}
	}
}

// TestAddSeenUp: gemerkte Ports aus dem Laufzeitstand machen einen Port ohne Link wieder zum Vorschlag.
func TestAddSeenUp(t *testing.T) {
	m := loadWalk(t, "testdata/switch.walk")
	c, _, _ := newTestCollector(t, m, Config{})
	c.AddSeenUp([]string{"if:Gi1/0/4", "kaputt", ""})
	s := collect(t, c)
	if !svcByKey(t, s, "if:Gi1/0/4").Default {
		t.Fatal("gemerkter Port nicht vorgeschlagen")
	}
	for _, k := range c.SeenUp() {
		if k == "kaputt" || k == "" {
			t.Fatalf("ungueltiger Schluessel uebernommen: %q", k)
		}
	}
}

// Issue #98: Ein Geraet ohne ENTITY-SENSOR- bzw. LAG-MIB, das die Abfrage der Tabelle mit einer Antwort ohne Werte
// quittiert, hat die Tabelle nicht – kein Teilfehler, und die Abfrage ruht wie bei endOfMibView. Bei einer
// Pflicht-Tabelle (IF-MIB) bleibt die leere Antwort ein Teilfehler, damit die Ports nicht als verschwunden gelten.
func TestEmptyOptionalTableIsAbsent(t *testing.T) {
	m := loadWalk(t, "testdata/switch.walk")
	c, fc, clk := newTestCollector(t, m, Config{})
	fc.emptyOn = ".1.3.6.1.2.1.99" // ENTITY-SENSOR
	s, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("leere Sensor-Tabelle ist kein Fehler: %v", err)
	}
	if !hasKey(s, "if:Gi1/0/1") || hasKey(s, "temp:CPU") {
		t.Fatal("Ports muessen kommen, Temperaturen nicht")
	}
	if !c.isAbsent("entsensor", *clk) {
		t.Fatal("ENTITY-SENSOR muss als nicht vorhanden gemerkt sein")
	}
	before := fc.reqs
	fc.emptyOn = ""
	fc.failOn = ".1.3.6.1.2.1.99" // wuerde scheitern, wird aber nicht mehr gefragt
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("zweite Runde: %v", err)
	}
	if fc.reqs == before {
		t.Fatal("zweite Runde ohne Anfragen")
	}

	c2, fc2, _ := newTestCollector(t, m, Config{})
	fc2.emptyOn = normOID(ifAdmin)
	if _, err := c2.Collect(context.Background()); !apis.IsPartial(err) {
		t.Fatalf("leere Antwort der IF-MIB muss ein Teilfehler bleiben: %v", err)
	}
}
