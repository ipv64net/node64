package snmp

import (
	"context"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/ipv64net/node64/internal/monitor64/apis"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// checkPrinter prueft die Dienste aus testdata/printer.walk (Status, Seiten, beide Verbrauchsmaterialien, drei Faecher).
func checkPrinter(t *testing.T, what string, s []model.Service) {
	t.Helper()
	if v := metric(t, svcByKey(t, s, "printer"), "pages"); v.Value != 48211 {
		t.Fatalf("%s: Seiten %+v", what, v)
	}
	if v := metric(t, svcByKey(t, s, "supply:1.1"), "level"); v.Value != 10 {
		t.Fatalf("%s: Toner %+v", what, v)
	}
	for _, k := range []string{"supply:1.2", "tray:1.1", "tray:1.2", "tray:1.3"} {
		if !hasKey(s, k) {
			t.Fatalf("%s: %s fehlt", what, k)
		}
	}
}

// #269: Drucker, die GETBULK still verwerfen, aber GETNEXT beantworten (snmpwalk geht). Die erste Runde stellt auf
// GETNEXT um und liefert alles samt eigener OID; die naechste Runde fragt gar nicht mehr per GETBULK.
func TestUDPAgentNoBulk(t *testing.T) {
	m := loadWalk(t, "testdata/printer.walk")
	a := startAgent(t, m, "testcommunity")
	a.noBulk.Store(true)
	c, err := New(Config{Address: "127.0.0.1", Port: a.port(), Version: "2c", Secret: Secret{Community: "testcommunity"},
		Timeout: 200 * time.Millisecond, Retries: -1,
		Custom: []CustomOID{{OID: "1.3.6.1.2.1.43.10.2.1.4.1.1", Name: "Gedruckte Seiten"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", deErr(err))
	}
	checkPrinter(t, "Runde 1", s)
	if v := metric(t, svcByKey(t, s, "oid:.1.3.6.1.2.1.43.10.2.1.4.1.1"), "value"); v.Value != 48211 {
		t.Fatalf("eigene OID: %+v", v)
	}
	if c.noBulk.Load() == 0 {
		t.Fatal("GETBULK ohne Antwort nicht gelernt")
	}
	n := a.bulkReqs.Load()
	start := time.Now()
	if s, err = c.Collect(context.Background()); err != nil {
		t.Fatalf("Runde 2: %v", deErr(err))
	}
	checkPrinter(t, "Runde 2", s)
	if a.bulkReqs.Load() != n || time.Since(start) > 2*time.Second {
		t.Fatalf("Runde 2: %d GETBULK-Anfragen, %v", a.bulkReqs.Load()-n, time.Since(start))
	}
	// Discover ("Verbindung testen") mit neuem Sammler: ohne Teilfehler
	c2, _ := New(Config{Address: "127.0.0.1", Port: a.port(), Version: "2c", Secret: Secret{Community: "testcommunity"},
		Timeout: 200 * time.Millisecond, Retries: -1})
	defer c2.Close()
	d, err := c2.Discover(context.Background())
	if err != nil || d.Device != "printer" || d.Warning != model.T("monitor64.txt.snmp_warn_community") {
		t.Fatalf("Discover: %v %q %q", err, d.Device, d.Warning)
	}
}

// #269: Agenten mit Fehlerstatus bei GETBULK (genErr) bzw. tooBig bei GETNEXT ueber mehrere Spalten: die Tabellen
// kommen trotzdem (GETNEXT, dann Spalte fuer Spalte), ohne Teilfehler.
func TestPrinterBulkErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bulkErr gosnmp.SNMPError
		nextMax int
	}{
		{"genErr", gosnmp.GenErr, 0},
		{"genErr+tooBig", gosnmp.GenErr, 1},
		{"tooBig", gosnmp.TooBig, 1},
	} {
		m := loadWalk(t, "testdata/printer.walk")
		c, fc, _ := newTestCollector(t, m, Config{})
		fc.bulkErr, fc.nextMax = tc.bulkErr, tc.nextMax
		s, err := c.Collect(context.Background())
		if err != nil {
			t.Fatalf("%s: %v (teilweise %v)", tc.name, deErr(err), apis.IsPartial(err))
		}
		checkPrinter(t, tc.name, s)
	}
}

// #241: GETBULK-Antwort Spalte fuer Spalte statt Zeile fuer Zeile (falsch zugeordnet): nicht nur die erste Zeile
// (z. B. nur Cyan), sondern alle Verbrauchsmaterialien und Faecher.
func TestPrinterBulkColumnMajor(t *testing.T) {
	m := loadWalk(t, "testdata/printer.walk")
	c, fc, _ := newTestCollector(t, m, Config{})
	fc.colMajor = true
	s, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", deErr(err))
	}
	checkPrinter(t, "Spalte fuer Spalte", s)
}
