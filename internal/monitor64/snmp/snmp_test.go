package snmp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/ipv64net/node64/internal/monitor64/apis"
	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/monitor64/model/modeltest"
)

// de ist der deutsche Text, den ein Betrachter sieht (Namen, Texte und Fehler des Sammlers sind uebersetzbar).
func de(s string) string { return modeltest.DE(s) }

// deErr: deutscher Text eines Fehlers ("" bei nil).
func deErr(err error) string {
	if err == nil {
		return ""
	}
	return de(err.Error())
}

// svcByKey liefert den Dienst mit deutschen Texten.
func svcByKey(t testing.TB, l []model.Service, key string) model.Service {
	t.Helper()
	for _, s := range l {
		if s.Key == key {
			return modeltest.Service("de", s)
		}
	}
	var keys []string
	for _, s := range l {
		keys = append(keys, s.Key)
	}
	t.Fatalf("Dienst %q fehlt (vorhanden: %s)", key, strings.Join(keys, ", "))
	return model.Service{}
}

func hasKey(l []model.Service, key string) bool {
	for _, s := range l {
		if s.Key == key {
			return true
		}
	}
	return false
}

func metric(t testing.TB, s model.Service, name string) model.Metric {
	t.Helper()
	for _, m := range s.Metrics {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("%s: Messgroesse %q fehlt (%+v)", s.Key, name, s.Metrics)
	return model.Metric{}
}

func hasMetric(s model.Service, name string) bool {
	for _, m := range s.Metrics {
		if m.Name == name {
			return true
		}
	}
	return false
}

func fact(s model.Service, code string) (model.Fact, bool) {
	for _, f := range s.Facts {
		if f.Code == code {
			return f, true
		}
	}
	return model.Fact{}, false
}

func near(a, b float64) bool { return a-b < 0.01 && b-a < 0.01 }

func collect(t testing.TB, c *Collector) []model.Service {
	t.Helper()
	svcs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return svcs
}

// net-snmp unter Linux (aufgezeichnet im Testcontainer): UCD-Speicher, Load, CPU aus ssCpuRaw, Ports mit HC-Zaehlern.
func TestNetSNMPLinux(t *testing.T) {
	m := loadWalk(t, "testdata/netsnmp-linux.walk")
	c, fc, now := newTestCollector(t, m, Config{})
	first := collect(t, c)
	if hasKey(first, "if:lo") {
		t.Fatal("Loopback darf kein Port sein")
	}
	eth := svcByKey(t, first, "if:eth0")
	if hasMetric(eth, "in") || !eth.Default {
		t.Fatalf("erste Runde ohne Rate, eth0 vorgeschlagen: %+v", eth)
	}
	mem := svcByKey(t, first, "mem")
	if u := metric(t, mem, "used"); u.Rule != model.RuleMem || !near(u.Value, 13.96) {
		t.Fatalf("RAM belegt (memSysAvail): %+v", u)
	}
	sw := svcByKey(t, first, "swap")
	if u := metric(t, sw, "used"); !near(u.Value, 10.82) {
		t.Fatalf("Swap: %+v", u)
	}
	ld := svcByKey(t, first, "load")
	if v := metric(t, ld, "l1"); !near(v.Value, 1.25) {
		t.Fatalf("Load: %+v", ld)
	}
	if hasMetric(ld, "per_core") {
		t.Fatal("ohne hrProcessorLoad keine Kernzahl")
	}
	up := svcByKey(t, first, "uptime")
	if v := metric(t, up, "uptime"); v.Value != 68286 { // hrSystemUptime vor sysUpTime
		t.Fatalf("Laufzeit: %+v", v)
	}
	for _, s := range first {
		if s.Kind == "fs" && s.Default {
			t.Fatalf("Pseudo-Dateisystem vorgeschlagen: %s", s.Key)
		}
	}
	// zweite Runde 60 s spaeter: 75 MB rein, 7,5 MB raus -> 10 / 1 Mbit/s; 2 Fehler auf 1000 Pakete
	*now = now.Add(60 * time.Second)
	m.add(".1.3.6.1.2.1.31.1.1.1.6.2", 75_000_000)
	m.add(".1.3.6.1.2.1.31.1.1.1.10.2", 7_500_000)
	m.add(".1.3.6.1.2.1.31.1.1.1.7.2", 600)
	m.add(".1.3.6.1.2.1.31.1.1.1.11.2", 400)
	m.add(".1.3.6.1.2.1.2.2.1.14.2", 2)
	m.add(".1.3.6.1.2.1.2.2.1.13.2", 5)
	m.set(".1.3.6.1.2.1.25.1.1.0", gosnmp.TimeTicks, uint32(6828656+6000))
	m.add(".1.3.6.1.4.1.2021.11.50.0", 300) // user
	m.add(".1.3.6.1.4.1.2021.11.53.0", 700) // idle
	reqs := fc.reqs
	second := collect(t, c)
	eth = svcByKey(t, second, "if:eth0")
	if v := metric(t, eth, "in"); !near(v.Value, 10) {
		t.Fatalf("in: %+v", v)
	}
	if v := metric(t, eth, "out"); !near(v.Value, 1) {
		t.Fatalf("out: %+v", v)
	}
	if v := metric(t, eth, "util"); v.Rule != model.RuleIfUtil || !near(v.Value, 0.1) { // 10 Gbit/s
		t.Fatalf("util: %+v", v)
	}
	if v := metric(t, eth, "errrate"); v.Rule != model.RuleIfErrRate || !near(v.Value, 0.2) {
		t.Fatalf("errrate: %+v", v)
	}
	if v := metric(t, eth, "drops"); v.Value != 5 {
		t.Fatalf("drops: %+v", v)
	}
	cpu := svcByKey(t, second, "cpu")
	if v := metric(t, cpu, "util"); v.Rule != model.RuleCPU || !near(v.Value, 30) {
		t.Fatalf("CPU aus ssCpuRaw: %+v", v)
	}
	if _, ok := fact(svcByKey(t, second, "uptime"), FactRestarted); ok {
		t.Fatal("kein Neustart")
	}
	if n := fc.reqs - reqs; n > 30 {
		t.Fatalf("zu viele Anfragen je Runde: %d", n)
	}
}

func TestRestartAndCounters(t *testing.T) {
	m := loadWalk(t, "testdata/switch.walk")
	c, _, now := newTestCollector(t, m, Config{})
	collect(t, c)
	*now = now.Add(time.Minute)
	m.set(".1.3.6.1.2.1.1.3.0", gosnmp.TimeTicks, uint32(1000000+6000))
	m.add(".1.3.6.1.2.1.31.1.1.1.6.1", 750_000_000) // 100 Mbit/s
	m.add(".1.3.6.1.2.1.31.1.1.1.10.1", 75_000_000)
	s := collect(t, c)
	if v := metric(t, svcByKey(t, s, "if:Gi1/0/1"), "in"); !near(v.Value, 100) {
		t.Fatalf("in: %+v", v)
	}
	if v := metric(t, svcByKey(t, s, "if:Gi1/0/1"), "util"); !near(v.Value, 10) {
		t.Fatalf("util: %+v", v)
	}
	// Neustart: Laufzeit klein, Zaehler von vorn -> keine Rate, Fact restarted
	*now = now.Add(time.Minute)
	m.set(".1.3.6.1.2.1.1.3.0", gosnmp.TimeTicks, uint32(3000))
	m.set(".1.3.6.1.2.1.31.1.1.1.6.1", gosnmp.Counter64, uint64(1000))
	m.set(".1.3.6.1.2.1.31.1.1.1.10.1", gosnmp.Counter64, uint64(1000))
	s = collect(t, c)
	up := svcByKey(t, s, "uptime")
	if _, ok := fact(up, FactRestarted); !ok {
		t.Fatalf("Neustart nicht erkannt: %+v", up)
	}
	if hasMetric(svcByKey(t, s, "if:Gi1/0/1"), "in") {
		t.Fatal("nach Neustart keine Rate")
	}
	// nach der Haltezeit verschwindet der Fact
	*now = now.Add(DefaultRestartHold + time.Minute)
	m.set(".1.3.6.1.2.1.1.3.0", gosnmp.TimeTicks, uint32(3000+uint32((DefaultRestartHold+time.Minute)/(10*time.Millisecond))))
	s = collect(t, c)
	if _, ok := fact(svcByKey(t, s, "uptime"), FactRestarted); ok {
		t.Fatal("Fact restarted muss nach der Haltezeit weg sein")
	}
}

func TestDelta(t *testing.T) {
	c := &Collector{counters: map[string]ctr{}}
	t0 := time.Unix(1000, 0)
	p32 := func(v uint) pdu { return pdu{Type: gosnmp.Counter32, Value: v} }
	p64 := func(v uint64) pdu { return pdu{Type: gosnmp.Counter64, Value: v} }
	cases := []struct {
		name   string
		a, b   pdu
		want   float64
		wantOK bool
	}{
		{"steigt", p32(100), p32(160), 60, true},
		{"32-Bit-Ueberlauf", p32(4294967200), p32(100), 196, true},
		{"Ruecksetzen", p32(1000), p32(10), 0, false},
		{"64 Bit zurueck", p64(1 << 40), p64(5), 0, false},
		{"Wechsel 32/64", p32(5), p64(10), 0, false},
		{"kein Zaehler", p32(5), pdu{Type: gosnmp.OctetString, Value: []byte("x")}, 0, false},
	}
	for _, tc := range cases {
		c.counters = map[string]ctr{}
		c.delta("k", tc.a, t0)
		d, dt, ok := c.delta("k", tc.b, t0.Add(10*time.Second))
		if ok != tc.wantOK || (ok && (d != tc.want || dt != 10)) {
			t.Errorf("%s: d=%v dt=%v ok=%v", tc.name, d, dt, ok)
		}
	}
}

func TestUptimeWrap(t *testing.T) {
	c := &Collector{counters: map[string]ctr{"x": {}}}
	t0 := time.Unix(1000, 0)
	c.detectRestart(sysInfo{ticks: 1<<32 - 3000, source: "sys", hasTicks: true}, t0)
	c.detectRestart(sysInfo{ticks: 3000, source: "sys", hasTicks: true}, t0.Add(60*time.Second))
	if !c.sys.restartAt.IsZero() {
		t.Fatal("Ueberlauf der TimeTicks ist kein Neustart")
	}
	c.detectRestart(sysInfo{ticks: 1000, source: "sys", hasTicks: true}, t0.Add(120*time.Second))
	if c.sys.restartAt.IsZero() {
		t.Fatal("Neustart nicht erkannt")
	}
}

func TestSwitch(t *testing.T) {
	m := loadWalk(t, "testdata/switch.walk")
	c, _, now := newTestCollector(t, m, Config{})
	s := collect(t, c)
	for _, k := range []string{"if:Lo0", "if:Po1#10"} {
		if hasKey(s, k) {
			t.Fatalf("%s darf nicht da sein", k)
		}
	}
	p1 := svcByKey(t, s, "if:Gi1/0/1")
	if !p1.Default || p1.Name != "Gi1/0/1 · Uplink NAS (1 Gbit/s)" {
		t.Fatalf("Port 1: %+v", p1)
	}
	p4 := svcByKey(t, s, "if:Gi1/0/4")
	if p4.Default {
		t.Fatal("Port ohne Link, nie verbunden: nicht vorschlagen")
	}
	if _, ok := fact(p4, FactIfDown); !ok {
		t.Fatalf("if_down fehlt: %+v", p4)
	}
	p5 := svcByKey(t, s, "if:Gi1/0/5")
	if _, ok := fact(p5, FactIfDown); ok || !strings.Contains(p5.Text, "abgeschaltet") {
		t.Fatalf("abgeschalteter Port: %+v", p5)
	}
	if vl := svcByKey(t, s, "if:Vl1"); vl.Default {
		t.Fatal("VLAN-Schnittstelle nicht vorschlagen")
	}
	if po := svcByKey(t, s, "if:Po1"); !po.Default {
		t.Fatal("LAG-Schnittstelle ist ein echter Port")
	}
	p3 := svcByKey(t, s, "if:Gi1/0/3")
	if _, ok := fact(p3, FactIfHalfDuplex); !ok {
		t.Fatalf("Halbduplex fehlt: %+v", p3)
	}
	// Bond
	b := svcByKey(t, s, "bond:Po1")
	if f, ok := fact(b, factBondDown); !ok || !strings.Contains(f.Text, "Gi1/0/4") {
		t.Fatalf("Bond-Mitglied down: %+v", b)
	}
	if v := metric(t, b, "members_up"); v.Value != 1 {
		t.Fatalf("members_up: %+v", b)
	}
	// Sensoren
	cpuT := svcByKey(t, s, "temp:CPU")
	if v := metric(t, cpuT, "temp"); v.Value != 41 || v.Rule != model.RuleTemp {
		t.Fatalf("CPU-Temperatur: %+v", v)
	}
	if v := metric(t, svcByKey(t, s, "temp:Inlet"), "temp"); v.Value != 38.5 {
		t.Fatalf("milli-Skala: %+v", v)
	}
	if hasKey(s, "temp:Fan 1") {
		t.Fatal("Drehzahl ist keine Temperatur")
	}
	cpu := svcByKey(t, s, "cpu")
	if v := metric(t, cpu, "util"); v.Value != 20 {
		t.Fatalf("hrProcessorLoad: %+v", v)
	}
	if c.PortKey(4) != "if:Gi1/0/4" {
		t.Fatalf("PortKey: %q", c.PortKey(4))
	}
	// Port 4 bekommt Link -> danach immer vorgeschlagen; Port 3 faellt auf 100 Mbit/s
	*now = now.Add(time.Minute)
	m.set(".1.3.6.1.2.1.2.2.1.8.4", gosnmp.Integer, 1)
	s = collect(t, c)
	if !svcByKey(t, s, "if:Gi1/0/4").Default {
		t.Fatal("einmal verbunden -> vorschlagen")
	}
	*now = now.Add(time.Minute)
	m.set(".1.3.6.1.2.1.2.2.1.8.4", gosnmp.Integer, 2)
	m.set(".1.3.6.1.2.1.31.1.1.1.15.3", gosnmp.Gauge32, uint(100))
	s = collect(t, c)
	if !svcByKey(t, s, "if:Gi1/0/4").Default {
		t.Fatal("wieder ohne Link: bleibt vorgeschlagen")
	}
	if f, ok := fact(svcByKey(t, s, "if:Gi1/0/3"), FactIfSpeedLow); !ok || f.Text != "100 Mbit/s statt 1 Gbit/s" {
		t.Fatalf("if_speed_low: %+v", f)
	}
	seen := c.SeenUp()
	if len(seen) == 0 || seen[0] != "if:Gi1/0/1" {
		t.Fatalf("SeenUp: %v", seen)
	}
	// Merkliste aus der Konfiguration
	c2, _, _ := newTestCollector(t, m, Config{SeenUp: []string{"if:Gi1/0/4"}})
	if s := collect(t, c2); !svcByKey(t, s, "if:Gi1/0/4").Default {
		t.Fatal("SeenUp aus der Konfiguration")
	}
}

func TestLACPMismatch(t *testing.T) {
	m := loadWalk(t, "testdata/switch.walk")
	m.set(".1.2.840.10006.300.43.1.2.1.1.13.4", gosnmp.Integer, 10)
	m.set(".1.3.6.1.2.1.2.2.1.8.4", gosnmp.Integer, 1)
	m.set(".1.2.840.10006.300.43.1.2.1.1.9.4", gosnmp.OctetString, []byte{0xde, 0xad, 0, 0, 0, 2})
	c, _, _ := newTestCollector(t, m, Config{})
	s := collect(t, c)
	b := svcByKey(t, s, "bond:Po1")
	if _, ok := fact(b, factBondDown); ok {
		t.Fatalf("alle Mitglieder aktiv: %+v", b)
	}
	if _, ok := fact(b, factLACPMismatch); !ok {
		t.Fatalf("LACP passt nicht: %+v", b)
	}
}

func TestDuplicatePortNames(t *testing.T) {
	m := loadWalk(t, "testdata/switch.walk")
	m.set(".1.3.6.1.2.1.31.1.1.1.1.2", gosnmp.OctetString, []byte("Gi1/0/1"))
	c, _, _ := newTestCollector(t, m, Config{})
	s := collect(t, c)
	if !hasKey(s, "if:Gi1/0/1#1") || !hasKey(s, "if:Gi1/0/1#2") {
		t.Fatal("doppelte ifName mit ifIndex unterscheiden")
	}
}

func TestPrinter(t *testing.T) {
	m := loadWalk(t, "testdata/printer.walk")
	c, _, _ := newTestCollector(t, m, Config{})
	d, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d.Device != "printer" || len(d.Profiles) != 1 || d.Profiles[0].ID != "printer" {
		t.Fatalf("Geraeteart/Profil: %q %+v", d.Device, d.Profiles)
	}
	s := d.Services
	p := svcByKey(t, s, "printer")
	f, ok := fact(p, FactPrinterError)
	if !ok || f.Text != "kein Papier, Klappe offen" {
		t.Fatalf("Druckerfehler: %+v", p)
	}
	if v := metric(t, p, "pages"); v.Value != 48211 {
		t.Fatalf("Seiten: %+v", v)
	}
	if !strings.Contains(p.Text, "Seriennummer CNB1234567") {
		t.Fatalf("Profil-Label: %q", p.Text)
	}
	toner := svcByKey(t, s, "supply:1.1")
	if v := metric(t, toner, "level"); v.Value != 10 || v.Rule != RulePrinterSupply {
		t.Fatalf("Toner: %+v", v)
	}
	if w := svcByKey(t, s, "supply:1.2"); hasMetric(w, "level") || w.Name != "Resttoner" {
		t.Fatalf("Resttoner unbekannt: %+v", w)
	}
	t1 := svcByKey(t, s, "tray:1.1")
	if t1.Default || len(t1.Facts) > 0 {
		t.Fatalf("manuelle Zufuhr: %+v", t1)
	}
	if _, ok := fact(svcByKey(t, s, "tray:1.2"), FactPaperEmpty); !ok {
		t.Fatal("Fach 2 leer")
	}
	if tr := svcByKey(t, s, "tray:1.3"); len(tr.Facts) > 0 || tr.Text != "Papier vorhanden" {
		t.Fatalf("Fach 3: %+v", tr)
	}
}

func TestUPSMIB(t *testing.T) {
	m := loadWalk(t, "testdata/ups-mib.walk")
	c, _, _ := newTestCollector(t, m, Config{})
	d, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d.Device != "ups" {
		t.Fatalf("Geraeteart: %q", d.Device)
	}
	u := svcByKey(t, d.Services, "ups")
	if u.Name != "USV EATON 5PX 1500" {
		t.Fatalf("Name: %q", u.Name)
	}
	if _, ok := fact(u, factUPSOnBattery); !ok {
		t.Fatalf("auf Batterie: %+v", u)
	}
	if _, ok := fact(u, FactUPSBatteryLow); !ok {
		t.Fatalf("Batterie schwach: %+v", u)
	}
	if f, ok := fact(u, FactUPSAlarm); !ok || f.Text != "Überlast" {
		t.Fatalf("Alarm (ohne OnBattery): %+v", u)
	}
	if v := metric(t, u, "runtime"); v.Value != 480 || v.Rule != RuleUPSRuntime {
		t.Fatalf("Restlaufzeit: %+v", v)
	}
	for name, want := range map[string]float64{"charge": 62, "load": 34, "on_battery": 1, "battery_temp": 27, "input_v": 0} {
		if v := metric(t, u, name); v.Value != want {
			t.Fatalf("%s: %+v", name, v)
		}
	}
}

func TestAPCProfile(t *testing.T) {
	m := loadWalk(t, "testdata/apc.walk")
	c, _, _ := newTestCollector(t, m, Config{})
	d, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d.Device != "ups" || len(d.Profiles) != 1 || d.Profiles[0].ID != "apc" {
		t.Fatalf("Profil: %+v %q", d.Profiles, d.Device)
	}
	u := svcByKey(t, d.Services, "ups")
	if v := metric(t, u, "runtime"); v.Value != 2880 || v.Rule != RuleUPSRuntime {
		t.Fatalf("Restlaufzeit aus TimeTicks: %+v", v)
	}
	if _, ok := fact(u, factUPSOnBattery); ok {
		t.Fatal("Netzbetrieb")
	}
	if _, ok := fact(u, FactUPSReplace); !ok {
		t.Fatalf("Batterie tauschen: %+v", u)
	}
	if !strings.Contains(u.Text, "Netzbetrieb") || !strings.Contains(u.Text, "Modell Smart-UPS 1500") {
		t.Fatalf("Text: %q", u.Text)
	}
	if !strings.Contains(d.Summary, "APC") {
		t.Fatalf("Summary: %q", d.Summary)
	}
}

func TestSynologyProfile(t *testing.T) {
	m := loadWalk(t, "testdata/synology.walk")
	c, _, _ := newTestCollector(t, m, Config{})
	s := collect(t, c)
	sys := svcByKey(t, s, "syno:system")
	if f, ok := fact(sys, FactHWFailed); !ok || f.Text != "Systemlüfter fehlerhaft" {
		t.Fatalf("Luefter: %+v", sys)
	}
	if !strings.Contains(sys.Text, "Modell DS920+") || !strings.Contains(sys.Text, "DSM DSM 7.2-72806") {
		t.Fatalf("Text: %q", sys.Text)
	}
	if v := metric(t, svcByKey(t, s, "temp:system"), "temp"); v.Value != 44 || v.Rule != model.RuleTemp {
		t.Fatalf("Systemtemperatur: %+v", v)
	}
	d1 := svcByKey(t, s, "disk:Disk 1")
	if v := metric(t, d1, "temp"); v.Value != 36 || v.Rule != model.RuleDiskTemp {
		t.Fatalf("Platte 1: %+v", d1)
	}
	if hasMetric(d1, "wear") || len(d1.Facts) > 0 {
		t.Fatalf("Platte 1 ohne Verschleiss (-1) und gesund: %+v", d1)
	}
	d2 := svcByKey(t, s, "disk:Disk 2")
	if v := metric(t, d2, "wear"); v.Value != 93 || v.Rule != model.RuleWear {
		t.Fatalf("Verschleiss = 100 - Restlebensdauer: %+v", v)
	}
	if _, ok := fact(d2, factSmartSectors); !ok {
		t.Fatalf("defekte Sektoren: %+v", d2)
	}
	if !strings.Contains(d2.Text, "Warnung") {
		t.Fatalf("Gesundheitsstatus im Text: %q", d2.Text)
	}
	pool := svcByKey(t, s, "raid:Storage Pool 1")
	if _, ok := fact(pool, factRAIDDegraded); !ok {
		t.Fatalf("Pool beeintraechtigt: %+v", pool)
	}
	if v := metric(t, pool, "used"); v.Value != 75 || v.Rule != model.RuleStore || v.Max != 4e12 {
		t.Fatalf("Belegung: %+v", v)
	}
	if v := metric(t, pool, "free"); v.Value != 1e12 {
		t.Fatalf("frei: %+v", v)
	}
}

func TestMikrotikProfile(t *testing.T) {
	m := loadWalk(t, "testdata/mikrotik.walk")
	c, _, _ := newTestCollector(t, m, Config{})
	s := collect(t, c)
	if v := metric(t, svcByKey(t, s, "temp:cpu-temperature"), "temp"); v.Value != 52 {
		t.Fatalf("CPU: %+v", v)
	}
	if hasKey(s, "temp:fan1-speed") || hasKey(s, "temp:psu1-state") {
		t.Fatal("Filter nach Einheit")
	}
	if v := metric(t, svcByKey(t, s, "fan:fan1-speed"), "rpm"); v.Value != 3200 {
		t.Fatalf("Luefter: %+v", v)
	}
	if _, ok := fact(svcByKey(t, s, "poe:ether2"), FactPoEFault); !ok {
		t.Fatal("PoE ueberlastet")
	}
	if v := metric(t, svcByKey(t, s, "poe:ether1"), "power"); v.Value != 5.2 {
		t.Fatalf("PoE-Leistung: %+v", v)
	}
	if hasKey(s, "temp:board") {
		t.Fatal("fehlender Skalar ergibt keinen Dienst")
	}
}

func TestPartialError(t *testing.T) {
	m := loadWalk(t, "testdata/switch.walk")
	c, fc, _ := newTestCollector(t, m, Config{})
	fc.failOn = ".1.3.6.1.2.1.99" // ENTITY-SENSOR antwortet nicht
	s, err := c.Collect(context.Background())
	var pe *apis.PartialError
	if !errors.As(err, &pe) || !apis.IsPartial(err) {
		t.Fatalf("Teilfehler erwartet: %v", err)
	}
	if !pe.Affects("temp:CPU") || pe.Affects("if:Gi1/0/1") {
		t.Fatalf("Praefixe: %v", pe.Prefixes)
	}
	if !hasKey(s, "if:Gi1/0/1") || hasKey(s, "temp:CPU") {
		t.Fatal("uebrige Dienste muessen kommen")
	}
}

func TestTotalFailureScrubbed(t *testing.T) {
	m := loadWalk(t, "testdata/switch.walk")
	c, fc, _ := newTestCollector(t, m, Config{Secret: Secret{Community: "geheim-community"}})
	fc.fail = true
	c.dial = func() (conn, error) { return fc, nil }
	_, err := c.Collect(context.Background())
	if err == nil || apis.IsPartial(err) {
		t.Fatalf("Fehler erwartet: %v", err)
	}
	// Geheimnis im Fehlertext wird entfernt
	c.dial = func() (conn, error) { return nil, errors.New("dial: community geheim-community abgelehnt") }
	c.resetConn()
	_, err = c.Collect(context.Background())
	if err == nil || strings.Contains(deErr(err), "geheim-community") {
		t.Fatalf("Geheimnis im Fehler: %v", err)
	}
	res := c.Test(context.Background())
	if res.OK || strings.Contains(res.Error, "geheim") || !strings.Contains(de(res.Warning), "v3 empfohlen") {
		t.Fatalf("Test: %+v", res)
	}
}

func TestV1(t *testing.T) {
	m := loadWalk(t, "testdata/switch.walk")
	c, fc, _ := newTestCollector(t, m, Config{Version: "1"})
	s := collect(t, c)
	if !fc.isV1 {
		t.Fatal("v1 erwartet")
	}
	if !hasKey(s, "if:GigabitEthernet1/0/1") { // v1: ohne ifXTable -> ifDescr
		t.Fatalf("Ports unter v1 fehlen")
	}
	if !hasKey(s, "temp:CPU") || !hasKey(s, "bond:Port-channel1") {
		t.Fatal("Tabellen unter v1 per GETNEXT")
	}
}

func TestWalkLimits(t *testing.T) {
	m := loadWalk(t, "testdata/switch.walk")
	// abgeschnittene GETBULK-Antworten: trotzdem vollstaendig
	fc := &fakeConn{m: m, maxResp: 7}
	tab, err := walkColumns(context.Background(), fc, []string{ifDescr, ifType, ifOper}, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(tab.col(ifDescr)) != 8 || len(tab.col(ifOper)) != 8 {
		t.Fatalf("Zeilen: %d %d", len(tab.col(ifDescr)), len(tab.col(ifOper)))
	}
	// riesige Werte werden gekuerzt
	m.set(ifDescr+".1", gosnmp.OctetString, []byte(strings.Repeat("x", 60000)))
	tab, err = walkColumns(context.Background(), &fakeConn{m: m}, []string{ifDescr}, 20)
	if err != nil || len(rawBytes(tab.col(ifDescr)["1"])) != maxValueBytes {
		t.Fatalf("kuerzen: %v", err)
	}
	// feindlicher Agent: liefert immer dieselbe OID -> Abbruch statt Endlosschleife
	loop := &loopConn{}
	_, err = walkColumns(context.Background(), loop, []string{ifDescr}, 20)
	if err != nil || loop.reqs > 2 {
		t.Fatalf("Schleife: err=%v reqs=%d", err, loop.reqs)
	}
	// feindlicher Agent: endlose steigende Tabelle -> Zeilengrenze
	inf := &infConn{}
	tab, err = walkColumns(context.Background(), inf, []string{ifDescr}, 50)
	if err != nil || len(tab.col(ifDescr)) != maxTableRows {
		t.Fatalf("Grenze: err=%v n=%d", err, len(tab.col(ifDescr)))
	}
}

type loopConn struct{ reqs int }

func (l *loopConn) v1() bool { return false }
func (l *loopConn) close()   {}
func (l *loopConn) get(context.Context, []string) ([]pdu, error) {
	return nil, errors.New("nicht benutzt")
}
func (l *loopConn) getNext(context.Context, []string) ([]pdu, error) {
	return nil, errors.New("nicht benutzt")
}
func (l *loopConn) getBulk(_ context.Context, oids []string, _ uint32) ([]pdu, error) {
	l.reqs++
	return []pdu{{Name: oids[0], Type: gosnmp.Integer, Value: 1}}, nil
}

type infConn struct{ n int }

func (f *infConn) v1() bool { return false }
func (f *infConn) close()   {}
func (f *infConn) get(context.Context, []string) ([]pdu, error) {
	return nil, errors.New("nicht benutzt")
}
func (f *infConn) getNext(context.Context, []string) ([]pdu, error) {
	return nil, errors.New("nicht benutzt")
}
func (f *infConn) getBulk(_ context.Context, _ []string, rep uint32) ([]pdu, error) {
	out := make([]pdu, rep)
	for i := range out {
		f.n++
		out[i] = pdu{Name: ifDescr + "." + itoa(f.n), Type: gosnmp.OctetString, Value: []byte("x")}
	}
	return out, nil
}

func itoa(n int) string { return strings.TrimPrefix(oid{0, uint32(n)}.String(), ".0.") }

func TestCustomOID(t *testing.T) {
	m := loadWalk(t, "testdata/switch.walk")
	m.set(".1.3.6.1.4.1.99999.5.1.0", gosnmp.Gauge32, uint(235))
	m.set(".1.3.6.1.4.1.99999.5.2.0", gosnmp.Counter64, uint64(1000))
	m.set(".1.3.6.1.4.1.99999.5.3.0", gosnmp.OctetString, []byte("Betrieb\x00ok"))
	c, _, now := newTestCollector(t, m, Config{Custom: []CustomOID{
		{OID: "1.3.6.1.4.1.99999.5.1.0", Name: "Wassertemperatur", Unit: "°C", Factor: 0.1, Rule: "temp.system"},
		{OID: ".1.3.6.1.4.1.99999.5.2.0", Name: "Zaehler", Counter: true},
		{OID: ".1.3.6.1.4.1.99999.5.3.0", Name: "Status"},
		{OID: ".1.3.6.1.4.1.99999.5.4.0", Name: "fehlt"},
	}})
	s := collect(t, c)
	w := svcByKey(t, s, "oid:.1.3.6.1.4.1.99999.5.1.0")
	if v := metric(t, w, "value"); v.Value != 23.5 || v.Unit != "°C" || v.Rule != model.RuleTemp || w.Name != "Wassertemperatur" {
		t.Fatalf("eigene OID: %+v", w)
	}
	if st := svcByKey(t, s, "oid:.1.3.6.1.4.1.99999.5.3.0"); st.Text != "Betrieb ok" {
		t.Fatalf("Text bereinigt: %q", st.Text)
	}
	if f := svcByKey(t, s, "oid:.1.3.6.1.4.1.99999.5.4.0"); f.Text != "kein Wert" {
		t.Fatalf("fehlende OID: %+v", f)
	}
	*now = now.Add(10 * time.Second)
	m.add(".1.3.6.1.4.1.99999.5.2.0", 50)
	s = collect(t, c)
	if v := metric(t, svcByKey(t, s, "oid:.1.3.6.1.4.1.99999.5.2.0"), "value"); v.Value != 5 {
		t.Fatalf("Zaehler als Rate: %+v", v)
	}
}

func TestConfig(t *testing.T) {
	ok := func(c Config) {
		t.Helper()
		if _, err := New(c); err != nil {
			t.Fatalf("%+v: %v", c, err)
		}
	}
	bad := func(c Config) {
		t.Helper()
		if _, err := New(c); err == nil {
			t.Fatalf("%+v: Fehler erwartet", c)
		}
	}
	ok(Config{Address: "192.0.2.1", Secret: Secret{Community: "public"}})
	ok(Config{Address: "[2001:db8::1]:1161", Secret: Secret{Community: "public"}})
	ok(Config{Address: "nas.local", Version: "3", User: "mon", AuthProto: "SHA-512", PrivProto: "AES-256", Secret: Secret{AuthPass: "12345678", PrivPass: "abcdefgh"}})
	ok(Config{Address: "nas.local", Version: "3", User: "mon", Level: "noAuthNoPriv"})
	ok(Config{Address: "nas.local", Version: "3", User: "mon", Level: "authNoPriv", AuthProto: "MD5", Secret: Secret{AuthPass: "12345678"}})
	bad(Config{Address: "", Secret: Secret{Community: "public"}})
	bad(Config{Address: "h", Version: "4", Secret: Secret{Community: "public"}})
	bad(Config{Address: "h"})
	bad(Config{Address: "h", Version: "3"})
	bad(Config{Address: "h", Version: "3", User: "u", Secret: Secret{AuthPass: "kurz"}})
	bad(Config{Address: "h", Version: "3", User: "u", AuthProto: "SHA9", Secret: Secret{AuthPass: "12345678", PrivPass: "12345678"}})
	bad(Config{Address: "h", Secret: Secret{Community: "p"}, Custom: []CustomOID{{OID: "abc", Name: "x"}}})
	bad(Config{Address: "h", Secret: Secret{Community: "p"}, Custom: []CustomOID{{OID: ".1.3.6", Name: "x", Unit: "parsec"}}})
	bad(Config{Address: "h", Secret: Secret{Community: "p"}, Profiles: []string{"gibtsnicht"}})
	c, _ := New(Config{Address: "[2001:db8::1]:1161", Secret: Secret{Community: "public"}})
	if c.cfg.Address != "2001:db8::1" || c.cfg.Port != 1161 {
		t.Fatalf("Adresse: %+v", c.cfg)
	}
	// Secret als JSON bzw. reiner Text
	sec := Secret{Community: "c", AuthPass: "a12345678", PrivPass: "p12345678"}
	if got := ParseSecret(sec.String()); got != sec {
		t.Fatalf("Secret: %+v", got)
	}
	if got := ParseSecret("public"); got.Community != "public" {
		t.Fatalf("Secret Text: %+v", got)
	}
	v3, _ := New(Config{Address: "h", Version: "3", User: "u", AuthProto: "MD5", PrivProto: "DES", Secret: Secret{AuthPass: "12345678", PrivPass: "12345678"}})
	if w := de(v3.warning()); !strings.Contains(w, "MD5") || !strings.Contains(w, "DES") {
		t.Fatalf("Warnung: %q", w)
	}
}

func TestProfilesLoad(t *testing.T) {
	if err := ProfilesError(); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, p := range Profiles() {
		ids[p.ID] = true
	}
	for _, id := range []string{"synology", "qnap", "truenas", "apc", "mikrotik", "unifi", "printer", "ups"} {
		if !ids[id] {
			t.Errorf("Profil %s fehlt", id)
		}
	}
	// Regel-Arten muessen Standard-Schwellen haben
	def := eval.Defaults()
	for r := range knownRules {
		if _, ok := def[r]; !ok {
			t.Errorf("Regel-Art %s ohne Standard-Schwelle", r)
		}
	}
}

func TestParseProfileErrors(t *testing.T) {
	cases := map[string]string{
		"unbekanntes Feld": `{"id":"x","name":"X","device":"nas","match":{"probe":".1.3"},"foo":1}`,
		"match leer":       `{"id":"x","name":"X","device":"nas","match":{}}`,
		"falsche OID":      `{"id":"x","name":"X","match":{"probe":".1.3"},"scalars":[{"key":"a","kind":"hw","oid":"1.x","label":"L"}]}`,
		"falsche Regel":    `{"id":"x","name":"X","match":{"probe":".1.3"},"scalars":[{"key":"a","kind":"hw","oid":".1.3.1","metric":"m","rule":"cpu.foo"}]}`,
		"falscher Fact":    `{"id":"x","name":"X","match":{"probe":".1.3"},"scalars":[{"key":"a","kind":"hw","oid":".1.3.1","fact":{"code":"boom","when":[1]}}]}`,
		"zwei Bedingungen": `{"id":"x","name":"X","match":{"probe":".1.3"},"scalars":[{"key":"a","kind":"hw","oid":".1.3.1","fact":{"code":"hw_failed","when":[1],"ok":[2]}}]}`,
		"Tabelle ohne Ph":  `{"id":"x","name":"X","match":{"probe":".1.3"},"tables":[{"key":"a","kind":"hw","oid":".1.3.1","columns":[{"col":1,"label":"L"}]}]}`,
		"name ohne Spalte": `{"id":"x","name":"X","match":{"probe":".1.3"},"tables":[{"key":"a:{name}","kind":"hw","oid":".1.3.1","columns":[{"col":1,"label":"L"}]}]}`,
		"Platzhalter Skal": `{"id":"x","name":"X","match":{"probe":".1.3"},"scalars":[{"key":"a:{index}","kind":"hw","oid":".1.3.1","label":"L"}]}`,
		"Einheit":          `{"id":"x","name":"X","match":{"probe":".1.3"},"scalars":[{"key":"a","kind":"hw","oid":".1.3.1","metric":"m","unit":"furlong"}]}`,
		"pct ohne used":    `{"id":"x","name":"X","match":{"probe":".1.3"},"tables":[{"key":"a:{index}","kind":"hw","oid":".1.3.1","columns":[{"col":1,"metric":"used","pct":{"total":"2"}}]}]}`,
		"leer":             `{"id":"x","name":"X","match":{"probe":".1.3"},"scalars":[{"key":"a","kind":"hw","oid":".1.3.1"}]}`,
		"id":               `{"id":"X Y","name":"X","device":"nas","match":{"probe":".1.3"}}`,
	}
	for name, js := range cases {
		if _, err := ParseProfile([]byte(js)); err == nil {
			t.Errorf("%s: Fehler erwartet", name)
		}
	}
	if _, err := ParseProfile([]byte(`{"id":"ok","name":"OK","device":"nas","match":{"descr":["x"]}}`)); err != nil {
		t.Fatalf("gueltiges Profil: %v", err)
	}
}

func TestForcedProfile(t *testing.T) {
	m := loadWalk(t, "testdata/apc.walk")
	m.set(".1.3.6.1.2.1.1.2.0", gosnmp.ObjectIdentifier, ".1.3.6.1.4.1.99999.1") // fremde sysObjectID
	m.set(".1.3.6.1.2.1.1.1.0", gosnmp.OctetString, []byte("irgendwas"))
	c, _, _ := newTestCollector(t, m, Config{})
	if hasKey(collect(t, c), "ups") {
		t.Fatal("ohne Profil keine USV")
	}
	c2, _, _ := newTestCollector(t, m, Config{Profiles: []string{"apc"}})
	if !hasKey(collect(t, c2), "ups") {
		t.Fatal("festes Profil")
	}
}

func TestQueriesAndText(t *testing.T) {
	m := loadWalk(t, "testdata/apc.walk")
	c, _, _ := newTestCollector(t, m, Config{Custom: []CustomOID{{OID: ".1.3.6.1.4.1.1.0", Name: "X"}}})
	collect(t, c)
	q := strings.Join(c.Queries(), "\n")
	for _, want := range []string{"IF-MIB", "UPS-MIB", "Profil APC", ".1.3.6.1.4.1.318.1.1.1.2.2.1.0", ".1.3.6.1.4.1.1.0 (X)"} {
		if !strings.Contains(q, want) {
			t.Errorf("Queries ohne %q", want)
		}
	}
	if got := cleanText("a\x00b\x1b[31m\u0085  c\xff"); got != "a b [31m c" {
		t.Fatalf("cleanText: %q", got)
	}
	if got := cleanText(strings.Repeat("ä", 1000)); len([]rune(got)) != maxTextLen {
		t.Fatalf("Laenge: %d", len([]rune(got)))
	}
	if v, ok := parseNumText("37 C/98 F", true); !ok || v != 37 {
		t.Fatalf("leading: %v", v)
	}
	if _, ok := parseNumText("NaN", false); ok {
		t.Fatal("NaN verwerfen")
	}
	if _, ok := num(pdu{Type: gosnmp.OpaqueFloat, Value: float32(0) / float32(zero())}); ok {
		t.Fatal("NaN aus Opaque verwerfen")
	}
}

func zero() float64 { return 0 }

// Echter gosnmp-Weg gegen den UDP-Agenten (v2c und v1, falsche Community).
func TestUDPAgent(t *testing.T) {
	m := loadWalk(t, "testdata/switch.walk")
	a := startAgent(t, m, "testcommunity")
	for _, v := range []string{"2c", "1"} {
		c, err := New(Config{Address: "127.0.0.1", Port: a.port(), Version: v, Secret: Secret{Community: "testcommunity"}, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		s, err := c.Collect(context.Background())
		if err != nil {
			t.Fatalf("v%s: %v", v, err)
		}
		if !hasKey(s, "temp:CPU") || !(hasKey(s, "bond:Po1") || hasKey(s, "bond:Port-channel1")) || !hasKey(s, "uptime") {
			t.Fatalf("v%s: Dienste fehlen", v)
		}
		c.Close()
	}
	c, _ := New(Config{Address: "127.0.0.1", Port: a.port(), Secret: Secret{Community: "falsch-geheim"}, Timeout: 200 * time.Millisecond, Retries: -1})
	defer c.Close()
	start := time.Now()
	_, err := c.Collect(context.Background())
	if err == nil || strings.Contains(deErr(err), "falsch-geheim") || time.Since(start) > 5*time.Second {
		t.Fatalf("falsche Community: %v (%v)", err, time.Since(start))
	}
}

// RouterOS (CRS305): verwirft zu grosse GETBULK-Antworten still und meldet noSuchName ohne Index. Die Ports kommen
// trotzdem, die Grenze wird gelernt, und fehlende Werte (UPS-MIB) machen die Runde nicht "teilweise".
func TestUDPAgentRouterOS(t *testing.T) {
	m := loadWalk(t, "testdata/switch.walk")
	a := startAgent(t, m, "testcommunity")
	a.routerOS.Store(20)
	c, err := New(Config{Address: "127.0.0.1", Port: a.port(), Version: "2c", Secret: Secret{Community: "testcommunity"},
		Timeout: 300 * time.Millisecond, Retries: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	ports := 0
	for _, x := range s {
		if strings.HasPrefix(x.Key, "if:") {
			ports++
		}
	}
	if ports == 0 {
		t.Fatal("no ports")
	}
	if lim := c.bulkMax.Load(); lim <= 0 || lim > 20 {
		t.Fatalf("learned limit: %d", lim)
	}
}
