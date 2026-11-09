package m64bsd

// Alle Dateien unter testdata/ mit "_nachgebaut" im Namen sind aus Manpages, Quelltext und Doku von FreeBSD 14 /
// OPNsense 25.1 nachgebaut (keine Aufzeichnung eines echten Hosts). Abweichungen echter Ausgaben bitte als neue
// Datei mit Herkunft ergaenzen.

import (
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/m64linux"
	"github.com/ipv64net/node64/internal/m64proto"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func enc32(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }
func enc64(v uint64) []byte { return binary.NativeEndian.AppendUint64(nil, v) }

// encLongs kodiert longs der Breite ls.
func encLongs(ls int, v ...uint64) []byte {
	var b []byte
	for _, x := range v {
		if ls == 8 {
			b = binary.NativeEndian.AppendUint64(b, x)
		} else {
			b = binary.NativeEndian.AppendUint32(b, uint32(x))
		}
	}
	return b
}

func TestParseCPTime(t *testing.T) {
	for _, ls := range []int{8, 4} {
		c, err := ParseCPTime(encLongs(ls, 100, 2, 50, 7, 1000), ls)
		if err != nil || c.User != 100 || c.Nice != 2 || c.System != 50 || c.IRQ != 7 || c.Idle != 1000 || c.IOWait != 0 {
			t.Fatalf("ls=%d: %+v %v", ls, c, err)
		}
	}
	for _, b := range [][]byte{nil, encLongs(8, 1, 2, 3, 4), append(encLongs(8, 1, 2, 3, 4, 5), 1)} {
		if _, err := ParseCPTime(b, 8); err == nil {
			t.Fatalf("Fehler erwartet fuer %d Bytes", len(b))
		}
	}
	if n := cpTimesCores(encLongs(8, make([]uint64, 20)...), 8); n != 4 {
		t.Fatalf("Kerne: %d", n)
	}
}

func TestParseLoadavg(t *testing.T) {
	// 64 Bit: drei fixpt_t, 4 Bytes Fuellung, long fscale
	b := append(append(append(append(enc32(1024), enc32(2560)...), enc32(4096)...), enc32(0)...), enc64(2048)...)
	l, err := ParseLoadavg(b, 8)
	if err != nil || l.L1 != 0.5 || l.L5 != 1.25 || l.L15 != 2 {
		t.Fatalf("64 Bit: %+v %v", l, err)
	}
	b32 := append(append(append(enc32(1024), enc32(2560)...), enc32(4096)...), enc32(2048)...)
	if l, err := ParseLoadavg(b32, 4); err != nil || l.L5 != 1.25 {
		t.Fatalf("32 Bit: %+v %v", l, err)
	}
	if _, err := ParseLoadavg(append(b32[:12], enc32(0)...), 4); err == nil {
		t.Fatal("fscale 0: Fehler erwartet")
	}
	if _, err := ParseLoadavg(b[:10], 8); err == nil {
		t.Fatal("zu kurz: Fehler erwartet")
	}
}

func TestParseBoottime(t *testing.T) {
	if s, err := ParseBoottime(append(enc64(1794000000), enc64(123456)...)); err != nil || s != 1794000000 {
		t.Fatalf("64 Bit: %d %v", s, err)
	}
	if s, err := ParseBoottime(append(enc32(1700000000), enc32(5)...)); err != nil || s != 1700000000 {
		t.Fatalf("i386: %d %v", s, err)
	}
	for _, b := range [][]byte{nil, enc32(1), append(enc64(0), enc64(0)...)} {
		if _, err := ParseBoottime(b); err == nil {
			t.Fatalf("Fehler erwartet: %v", b)
		}
	}
}

// xswdev baut struct xswdev (Version 2, 64-Bit-Ausrichtung).
func xswdev(nblks, used uint32) []byte {
	b := make([]byte, 32)
	binary.NativeEndian.PutUint32(b[0:], 2)
	binary.NativeEndian.PutUint64(b[8:], 0x5a)
	binary.NativeEndian.PutUint32(b[20:], nblks)
	binary.NativeEndian.PutUint32(b[24:], used)
	return b
}

func TestParseXswdev(t *testing.T) {
	if n, u, err := ParseXswdev(xswdev(524288, 1000)); err != nil || n != 524288 || u != 1000 {
		t.Fatalf("v2/64: %d %d %v", n, u, err)
	}
	i386 := make([]byte, 24)
	binary.NativeEndian.PutUint32(i386[0:], 2)
	binary.NativeEndian.PutUint32(i386[16:], 100)
	binary.NativeEndian.PutUint32(i386[20:], 10)
	if n, u, err := ParseXswdev(i386); err != nil || n != 100 || u != 10 {
		t.Fatalf("v2/i386: %d %d %v", n, u, err)
	}
	v1 := make([]byte, 20)
	binary.NativeEndian.PutUint32(v1[0:], 1)
	binary.NativeEndian.PutUint32(v1[12:], 200)
	binary.NativeEndian.PutUint32(v1[16:], 20)
	if n, u, err := ParseXswdev(v1); err != nil || n != 200 || u != 20 {
		t.Fatalf("v1: %d %d %v", n, u, err)
	}
	bad := xswdev(10, 20) // belegt > gesamt
	if _, _, err := ParseXswdev(bad); err == nil {
		t.Fatal("used > nblks: Fehler erwartet")
	}
	bad = xswdev(10, 1)
	binary.NativeEndian.PutUint32(bad, 7)
	if _, _, err := ParseXswdev(bad); err == nil {
		t.Fatal("Version 7: Fehler erwartet")
	}
	if _, _, err := ParseXswdev(make([]byte, 8)); err == nil {
		t.Fatal("zu kurz: Fehler erwartet")
	}
}

func TestParseIK(t *testing.T) {
	c, ok := ParseIK(enc32(3232)) // 323,2 K
	if !ok || math.Abs(c-50.05) > 0.06 {
		t.Fatalf("%v %v", c, ok)
	}
	for _, v := range []uint32{0, 0xffffffff, 5000} { // 0 K, -1, 226,85 °C
		if _, ok := ParseIK(enc32(v)); ok {
			t.Fatalf("%d: unplausibel erwartet", v)
		}
	}
	if _, ok := ParseIK(enc64(3232)); ok {
		t.Fatal("8 Bytes: Fehler erwartet")
	}
}

func TestMemFromValues(t *testing.T) {
	m, err := MemFromValues(MemValues{Physmem: 8 << 30, PageSize: 4096, Free: 262144, Inactive: 131072, ARC: 3 << 30, ARCMin: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	// (262144+131072)*4096 = 1,5 GiB + ARC ueber c_min 2 GiB
	if m.Total != 8<<30 || m.Available != 3<<30+512<<20 {
		t.Fatalf("%+v", m)
	}
	m, _ = MemFromValues(MemValues{Physmem: 1 << 30, PageSize: 4096, Free: 1 << 20}) // mehr frei als vorhanden
	if m.Available != 1<<30 {
		t.Fatalf("gekappt: %+v", m)
	}
	if _, err := MemFromValues(MemValues{Physmem: 1 << 30}); err == nil {
		t.Fatal("ohne Seitengroesse: Fehler erwartet")
	}
	if _, err := MemFromValues(MemValues{Physmem: 1 << 30, PageSize: 4096, Free: 1 << 50}); err == nil {
		t.Fatal("Ueberlauf: Fehler erwartet")
	}
}

func TestReadTemps(t *testing.T) {
	sc := fakeSysctl{
		"dev.cpu.0.temperature":           enc32(3231), // 49,95 °C
		"dev.cpu.0.coretemp.tjmax":        enc32(3731), // 99,95 °C
		"dev.cpu.1.temperature":           enc32(3251),
		"dev.cpu.3.temperature":           enc32(9999), // unplausibel
		"hw.acpi.thermal.tz0.temperature": enc32(3001),
		"hw.acpi.thermal.tz0._CRT":        enc32(3681),
		"hw.acpi.thermal.tz0._HOT":        enc32(0xffffffff), // -1: nicht gesetzt
	}.fn()
	ts := readTemps(sc, 4)
	if len(ts) != 3 {
		t.Fatalf("%+v", ts)
	}
	if ts[0].Name != "cpu/0" || ts[0].Label != "CPU 0" || ts[0].Crit == nil || math.Abs(*ts[0].Crit-100) > 0.1 {
		t.Fatalf("cpu0: %+v", ts[0])
	}
	if ts[1].Name != "cpu/1" || ts[1].Crit != nil {
		t.Fatalf("cpu1: %+v", ts[1])
	}
	if ts[2].Name != "acpi/tz0" || ts[2].Crit == nil || ts[2].High != nil || math.Abs(ts[2].C-27) > 0.1 {
		t.Fatalf("acpi: %+v", ts[2])
	}
	if ts := readTemps(fakeSysctl{}.fn(), 8); len(ts) != 0 {
		t.Fatalf("ohne Sensoren: %+v", ts)
	}
}

func TestParseIostat(t *testing.T) {
	ds, err := ParseIostat(readTestdata(t, "iostat_xI_freebsd14_nachgebaut.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 3 || ds[0].Name != "ada0" || ds[2].Name != "nda0" {
		t.Fatalf("%+v", ds)
	}
	d := ds[0]
	if d.ReadOps != 123456 || d.WriteOps != 789012 || d.ReadBytes != uint64(4567890.5*1024) || d.WriteBytes != 12345678*1024 || d.IOTimeMs != 567800 {
		t.Fatalf("ada0: %+v", d)
	}
	// ohne -I (Raten) ist das Format unbrauchbar
	rates := "                        extended device statistics  \ndevice       r/s     w/s     kr/s     kw/s  ms/r  ms/w  ms/o  ms/t qlen  %b  \nada0           1       3     22.7     45.4     0     1     0     1    0   0 \n"
	if _, err := ParseIostat([]byte(rates)); err == nil {
		t.Fatal("Raten: Fehler erwartet")
	}
	if _, err := ParseIostat([]byte("Muell\n")); err == nil {
		t.Fatal("ohne Kopf: Fehler erwartet")
	}
	// feindliche Werte: NaN, negativ, riesig, falsche Spaltenzahl
	bad := "device r/i w/i kr/i kw/i qlen tsvc_t/i sb/i\nada0 NaN 1 1 1 0 1 1\nada1 -1 1 1 1 0 1 1\nada2 1 1 1e30 1 0 1 1\nada3 1 1 1\nada4 1 2 3 4 0 5 6\n"
	ds, err = ParseIostat([]byte(bad))
	if err != nil || len(ds) != 1 || ds[0].Name != "ada4" || ds[0].IOTimeMs != 6000 {
		t.Fatalf("feindlich: %+v %v", ds, err)
	}
}

func TestParseGeomDisks(t *testing.T) {
	g := ParseGeomDisks(readTestdata(t, "geom_disk_list_nachgebaut.txt"))
	if len(g) != 3 { // cd0 ist keine Platte
		t.Fatalf("%+v", g)
	}
	if d := g["ada0"]; d.Serial != "WD-WCC7K1ABCDEF" || d.Model != "WDC WD40EFRX-68N32N0" || d.Rotational == nil || !*d.Rotational {
		t.Fatalf("ada0: %+v", d)
	}
	if d := g["nda0"]; d.Serial != "S4EVNX0N123456A" || d.Rotational == nil || *d.Rotational {
		t.Fatalf("nda0: %+v", d)
	}
	ds := []m64proto.DiskIO{{Name: "nda0"}, {Name: "da9"}}
	mergeGeom(ds, g)
	if ds[0].Serial != "S4EVNX0N123456A" || ds[1].Serial != "" {
		t.Fatalf("merge: %+v", ds)
	}
}

func TestBuildNetOPNsense(t *testing.T) {
	counters, down, err := ParseNetstatJSON(readTestdata(t, "netstat_ibn_opnsense25_nachgebaut.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfgs := ParseIfconfig(readTestdata(t, "ifconfig_opnsense25_nachgebaut.txt"))
	if len(cfgs) != 14 {
		t.Fatalf("ifconfig: %d Schnittstellen", len(cfgs))
	}
	ifs, bonds := BuildNet(counters, down, cfgs)
	by := map[string]m64proto.NetIf{}
	for _, n := range ifs {
		by[n.Name] = n
	}
	if _, ok := by["lo0"]; ok {
		t.Fatal("lo0 gehoert nicht in den Bericht")
	}
	want := map[string]struct {
		kind, master string
		up           bool
		speed        int
	}{
		"igb0": {"physical", "", true, 1000}, "igb1": {"physical", "", true, 2500}, "igb2": {"physical", "lagg0", true, 1000},
		"igb3": {"physical", "lagg0", true, 1000}, "igb4": {"physical", "bridge0", false, 0}, "enc0": {"virtual", "", false, 0},
		"pflog0": {"virtual", "", false, 0}, "pfsync0": {"virtual", "", false, 0}, "lagg0": {"bond", "", true, 0},
		"vlan01": {"vlan", "", true, 2500}, "wg1": {"virtual", "", true, 0}, "ovpns1": {"virtual", "", true, 0},
		"bridge0": {"bridge", "", true, 0},
	}
	if len(by) != len(want) {
		t.Fatalf("Schnittstellen: %v", by)
	}
	for name, w := range want {
		n := by[name]
		if n.Kind != w.kind || n.Master != w.master || n.Up != w.up || n.SpeedMbit != w.speed {
			t.Errorf("%s: %+v, erwartet %+v", name, n, w)
		}
	}
	igb0 := by["igb0"]
	if igb0.RxBytes != 21345678901 || igb0.TxBytes != 1234567890 || igb0.RxPackets != 18234567 || igb0.RxErrors != 3 ||
		igb0.RxDropped != 12 || igb0.Duplex != "full" || igb0.MAC != "00:0d:b9:5a:1b:2c" || igb0.MTU != 1500 {
		t.Fatalf("igb0: %+v", igb0)
	}
	if !down["igb4"] || by["wg1"].TxErrors != 1 {
		t.Fatalf("igb4 abgeschaltet / wg1: %v %+v", down, by["wg1"])
	}
	if len(bonds) != 1 {
		t.Fatalf("bonds: %+v", bonds)
	}
	b := bonds[0]
	if b.Name != "lagg0" || !strings.Contains(b.Mode, "802.3ad") || b.MII != "up" || len(b.Members) != 2 ||
		b.Members[0].MII != "up" || b.Members[0].SpeedMbit != 1000 || b.Members[1].MII != "down" {
		t.Fatalf("lagg0: %+v", b)
	}
	// ohne ifconfig: Art aus dem Namen, Zustand unbekannt (down)
	ifs, _ = BuildNet(counters, down, nil)
	for _, n := range ifs {
		if n.Name == "lagg0" && n.Kind != "bond" || n.Name == "wg1" && n.Kind != "virtual" || n.Up {
			t.Fatalf("ohne ifconfig: %+v", n)
		}
	}
}

func TestBuildNetFailover(t *testing.T) {
	cfg := "lagg0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500\n" +
		"\tlaggproto failover lagghash l2,l3,l4\n\tlaggport: em0 flags=5<MASTER,ACTIVE>\n\tlaggport: em1 flags=0<>\n" +
		"\tmedia: Ethernet autoselect\n\tstatus: active\n" +
		"em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500\n\tmedia: Ethernet autoselect (1000baseT <full-duplex>)\n\tstatus: active\n" +
		"em1: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500\n\tmedia: Ethernet autoselect (1000baseT <full-duplex>)\n\tstatus: active\n"
	_, bonds := BuildNet(nil, nil, ParseIfconfig([]byte(cfg)))
	if len(bonds) != 1 || bonds[0].Mode != "failover" || bonds[0].Members[0].MII != "up" || bonds[0].Members[1].MII != "up" {
		t.Fatalf("failover: Reserve mit Link gilt als up: %+v", bonds)
	}
}

func TestIfUp(t *testing.T) {
	for _, c := range []struct {
		cfg string
		up  bool
	}{
		{"em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500\n\tstatus: active\n", true},
		{"em0: flags=8802<BROADCAST,SIMPLEX,MULTICAST> metric 0 mtu 1500\n\tstatus: active\n", false}, // abgeschaltet
		{"em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500\n\tstatus: no carrier\n", false},
		{"wlan0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500\n\tstatus: associated\n", true},
		{"wg0: flags=80c1<UP,RUNNING,NOARP,MULTICAST> metric 0 mtu 1420\n", true},
		{"tun0: flags=8010<POINTOPOINT,MULTICAST> metric 0 mtu 1500\n", false},
	} {
		cfgs := ParseIfconfig([]byte(c.cfg))
		if len(cfgs) != 1 || ifUp(&cfgs[0]) != c.up {
			t.Errorf("%q: %+v", c.cfg, cfgs)
		}
	}
}

func TestParseNetstatJSONErrors(t *testing.T) {
	if _, _, err := ParseNetstatJSON([]byte("kein json")); err == nil {
		t.Fatal("Fehler erwartet")
	}
	// andere Schluessel als erwartet: lieber Fehler als Nullen
	other := `{"statistics":{"interface":[{"name":"em0","network":"<Link#1>","ipackets":5,"ibytes":7}]}}`
	if _, _, err := ParseNetstatJSON([]byte(other)); err == nil {
		t.Fatal("unbekannte Schluessel: Fehler erwartet")
	}
	// Zahlen als Text, ungueltige Namen
	str := `{"statistics":{"interface":[{"name":"em0","network":"<Link#1>","received-packets":"5","received-bytes":"7","sent-bytes":"x"},{"name":"bad name","network":"<Link#2>","received-packets":1}]}}`
	ifs, _, err := ParseNetstatJSON([]byte(str))
	if err != nil || len(ifs) != 1 || ifs[0].RxPackets != 5 || ifs[0].RxBytes != 7 || ifs[0].TxBytes != 0 {
		t.Fatalf("%+v %v", ifs, err)
	}
	if ifs, _, err := ParseNetstatJSON([]byte(`{"statistics":{"interface":[]}}`)); err != nil || len(ifs) != 0 {
		t.Fatalf("leer: %+v %v", ifs, err)
	}
}

func TestParseMedia(t *testing.T) {
	for _, c := range []struct {
		in     string
		speed  int
		duplex string
	}{
		{"Ethernet autoselect (1000baseT <full-duplex>)", 1000, "full"},
		{"Ethernet autoselect (10Gbase-T <full-duplex,rxpause,txpause>)", 10000, "full"},
		{"Ethernet autoselect (2500Base-T <full-duplex>)", 2500, "full"},
		{"Ethernet autoselect (25GBase-SR <full-duplex>)", 25000, "full"},
		{"Ethernet autoselect (100baseTX <half-duplex>)", 100, "half"},
		{"Ethernet 10baseT/UTP <half-duplex>", 10, "half"},
		{"Ethernet autoselect", 0, ""},
		{"Ethernet autoselect (none)", 0, ""},
		{"IEEE 802.11 Wireless Ethernet autoselect mode 11ng", 0, ""},
		{"Ethernet autoselect (99999999999Gbase-T)", 0, ""},
	} {
		s, d := parseMedia(c.in)
		if s != c.speed || d != c.duplex {
			t.Errorf("%q: %d %q", c.in, s, d)
		}
	}
}

func TestIfKindByName(t *testing.T) {
	for name, kind := range map[string]string{
		"lo0": "virtual", "pflog0": "virtual", "wg0": "virtual", "ovpnc2": "virtual", "tun0": "virtual", "pppoe0": "virtual",
		"epair0a": "virtual", "vm-public": "virtual", "lagg1": "bond", "bridge3": "bridge", "vlan0.10": "vlan",
		"igb0_vlan10": "vlan", "igb0.20": "vlan", "mlxen0": "virtual", "me0": "virtual",
	} {
		if k := ifKind(name, nil); k != kind {
			t.Errorf("%s: %s, erwartet %s", name, k, kind)
		}
	}
	// mit Medium: physisch (auch vtnet, re, ue)
	for _, name := range []string{"vtnet0", "re0", "ue0", "ix1", "igc0", "mce0"} {
		if k := ifKind(name, &IfConfig{Name: name, HasMedia: true}); k != "physical" {
			t.Errorf("%s: %s", name, k)
		}
	}
}

func TestParseGeomStatus(t *testing.T) {
	rs := ParseGeomStatus(geomMirror, readTestdata(t, "gmirror_status_degraded_nachgebaut.txt"))
	if len(rs) != 3 {
		t.Fatalf("%+v", rs)
	}
	gm0 := rs[0]
	if gm0.Name != "mirror/gm0" || gm0.Level != "gmirror" || gm0.State != "recovering" || gm0.Devices != 2 || gm0.Active != 1 ||
		gm0.SyncPercent == nil || *gm0.SyncPercent != 45 || strings.Join(gm0.Members, ",") != "ada0,ada1" {
		t.Fatalf("gm0: %+v", gm0)
	}
	if gm1 := rs[1]; gm1.State != "active" || gm1.Devices != 2 || gm1.Active != 2 || gm1.SyncPercent != nil {
		t.Fatalf("gm1: %+v", gm1)
	}
	if sw := rs[2]; sw.Name != "mirror/swap" || sw.State != "degraded" || sw.Devices != 1 || sw.Active != 1 {
		t.Fatalf("swap: %+v", sw)
	}
	// Skript-Form (-s): Name in jeder Zeile
	rs = ParseGeomStatus(geomMirror, []byte("mirror/gm0  COMPLETE  ada0 (ACTIVE)\nmirror/gm0  COMPLETE  ada1 (ACTIVE)\n"))
	if len(rs) != 1 || rs[0].Devices != 2 || rs[0].Active != 2 || rs[0].State != "active" {
		t.Fatalf("-s: %+v", rs)
	}
	rs = ParseGeomStatus(geomRAID, readTestdata(t, "graid_status_nachgebaut.txt"))
	if len(rs) != 3 || rs[0].State != "active" || rs[0].Active != 2 {
		t.Fatalf("graid: %+v", rs)
	}
	if r1 := rs[1]; r1.State != "recovering" || r1.Active != 1 || r1.SyncPercent == nil || *r1.SyncPercent != 23 {
		t.Fatalf("r1: %+v", r1)
	}
	if r2 := rs[2]; r2.State != "failed" || r2.Failed != 1 || r2.Active != 0 {
		t.Fatalf("r2: %+v", r2)
	}
	// PB7: Reserve-Platte zaehlt nicht zum Soll (gesundes Array mit Hot-Spare)
	rs = ParseGeomStatus(geomRAID, []byte("raid/r0  OPTIMAL  ada0 (ACTIVE (ACTIVE))\n                 ada1 (ACTIVE (ACTIVE))\n                 ada2 (SPARE)\n"))
	if len(rs) != 1 || rs[0].Devices != 2 || rs[0].Active != 2 || rs[0].Spare != 1 || rs[0].State != "active" || len(rs[0].Members) != 3 {
		t.Fatalf("Hot-Spare: %+v", rs)
	}
	if rs := ParseGeomStatus(geomMirror, nil); len(rs) != 0 {
		t.Fatalf("leer: %+v", rs)
	}
}

func TestParsePkg(t *testing.T) {
	list := "curl-8.10.1                        <\nlibxml2-2.11.8                     <\nopnsense-25.1.4_1                  <\nphp83-8.3.15   <   needs updating (remote has 8.3.16)\nfoo-1.0 =\npkg: warning\n"
	if n := ParsePkgVersion([]byte(list)); n != 4 {
		t.Fatalf("pkg version: %d", n)
	}
	if n, noDB, ok := ParsePkgAudit(readTestdata(t, "pkg_audit_vuln_nachgebaut.txt"), nil, 1); !ok || noDB || n != 2 {
		t.Fatalf("audit: %d %v %v", n, noDB, ok)
	}
	if n, _, ok := ParsePkgAudit([]byte("0 problem(s) in 0 installed package(s) found.\n"), nil, 0); !ok || n != 0 {
		t.Fatalf("audit sauber: %d %v", n, ok)
	}
	nodb := []byte("pkg: vulnxml file /var/db/pkg/vuln.xml does not exist. Try running 'pkg audit -F' first\n")
	if _, noDB, ok := ParsePkgAudit(nil, nodb, 1); ok || !noDB {
		t.Fatalf("ohne Datenbank: %v %v", noDB, ok)
	}
	if n, _, ok := ParsePkgAudit([]byte("a-1 is vulnerable:\n  x\nb-2 is vulnerable:\n"), nil, 1); !ok || n != 2 {
		t.Fatalf("ohne Summenzeile: %d %v", n, ok)
	}
	if _, _, ok := ParsePkgAudit([]byte("Muell"), nil, 70); ok {
		t.Fatal("Muell: nicht auswertbar erwartet")
	}
}

func TestParseFreeBSDVersion(t *testing.T) {
	r, ok := ParseFreeBSDVersion([]byte("14.1-RELEASE-p5\n14.1-RELEASE-p5\n"))
	if !ok || r.Required {
		t.Fatalf("gleich: %+v %v", r, ok)
	}
	r, ok = ParseFreeBSDVersion([]byte("14.1-RELEASE-p6\n14.1-RELEASE-p5\n"))
	if !ok || !r.Required || len(r.Packages) != 1 || !strings.Contains(r.Packages[0], "14.1-RELEASE-p6") {
		t.Fatalf("neuer Kernel: %+v %v", r, ok)
	}
	for _, s := range []string{"", "14.1-RELEASE\n", "x y\n14.1\n", "14.1; rm -rf /\n14.1\n"} {
		if _, ok := ParseFreeBSDVersion([]byte(s)); ok {
			t.Fatalf("%q: ungueltig erwartet", s)
		}
	}
}

func TestParseSwapinfo(t *testing.T) {
	in := "Device          1K-blocks     Used    Avail Capacity\n/dev/ada0p3       2097152    10240  2086912     0%\n/dev/ada1p3       2097152        0  2097152     0%\nTotal             4194304    10240  4184064     0%\n"
	tot, free, err := ParseSwapinfo([]byte(in))
	if err != nil || tot != 4194304*1024 || free != (4194304-10240)*1024 {
		t.Fatalf("%d %d %v", tot, free, err)
	}
	if tot, _, err := ParseSwapinfo([]byte("Device          1K-blocks     Used    Avail Capacity\n")); err != nil || tot != 0 {
		t.Fatalf("ohne Swap: %d %v", tot, err)
	}
	if _, _, err := ParseSwapinfo([]byte("a\nb c\n")); err == nil {
		t.Fatal("Muell: Fehler erwartet")
	}
}

func TestFSFromStatfs(t *testing.T) {
	mounts := []Mount{
		{Device: "zroot/ROOT/default", Mount: "/", Type: "zfs", Local: true},
		{Device: "devfs", Mount: "/dev", Type: "devfs", Local: true},
		{Device: "/dev/gpt/efiboot0", Mount: "/boot/efi", Type: "msdosfs", Local: true},
		{Device: "tmpfs", Mount: "/var/log", Type: "tmpfs", Local: true},
		{Device: "zroot/tmp", Mount: "/tmp", Type: "zfs", Local: true},
		{Device: "nas:/export", Mount: "/mnt/nfs", Type: "nfs"},
		{Device: "/usr/home", Mount: "/jail/www/home", Type: "nullfs", Local: true},
		{Device: "tank/data@daily", Mount: "/mnt/tank/data/.zfs/snapshot/daily", Type: "zfs", Local: true},
		{Device: "tank/.system", Mount: "/var/db/system", Type: "zfs", Local: true},
		{Device: "tank/data", Mount: "/mnt/tank/data", Type: "zfs", ReadOnly: true, Local: true},
		{Device: "tank/empty", Mount: "/mnt/tank/empty", Type: "zfs", Local: true},
		{Device: "tank/hang", Mount: "/mnt/tank/hang", Type: "zfs", Local: true},
	}
	var asked []string
	fsl, errs := FSFromStatfs(mounts, func(p string) (StatFS, error) {
		asked = append(asked, p)
		switch p {
		case "/mnt/tank/empty":
			return StatFS{}, nil
		case "/mnt/tank/hang":
			return StatFS{}, os.ErrDeadlineExceeded
		}
		return StatFS{Total: 1000, Free: 400, Avail: 300, InodesTotal: 10, InodesFree: 5}, nil
	})
	if len(errs) != 1 {
		t.Fatalf("errs: %v", errs)
	}
	var got []string
	for _, f := range fsl {
		got = append(got, f.Mount)
	}
	if strings.Join(got, ",") != "/,/boot/efi,/tmp,/mnt/tank/data" {
		t.Fatalf("Dateisysteme: %v (gefragt: %v)", got, asked)
	}
	if f := fsl[0]; f.Used != 600 || f.Avail != 300 || f.Type != "zfs" || f.Device != "zroot/ROOT/default" {
		t.Fatalf("/: %+v", f)
	}
	if !fsl[3].ReadOnly {
		t.Fatal("ro fehlt")
	}
	for _, p := range asked {
		if p == "/mnt/nfs" || p == "/dev" {
			t.Fatalf("statfs auf %s darf nicht laufen", p)
		}
	}
}

func TestStatfsValues(t *testing.T) {
	st := statfsValues(4096, 1000, 100, -50, 500, -3) // root-Reserve angegriffen
	if st.Total != 4096000 || st.Free != 409600 || st.Avail != 0 || st.InodesFree != 0 || st.InodesTotal != 500 {
		t.Fatalf("%+v", st)
	}
	if st := statfsValues(1<<40, 1<<40, 1, 1, 0, 0); st.Total != 0 || st.Avail != 0 { // Ueberlauf
		t.Fatalf("Ueberlauf: %+v", st)
	}
}

func TestDetectPlatform(t *testing.T) {
	files := func(m map[string]string) func(string) ([]byte, error) {
		return func(p string) ([]byte, error) {
			if s, ok := m[p]; ok {
				return []byte(s), nil
			}
			return nil, os.ErrNotExist
		}
	}
	core := string(readTestdata(t, "opnsense_version_core_nachgebaut.json"))
	for _, c := range []struct {
		files map[string]string
		want  string
	}{
		{map[string]string{fileOPNsenseCore: core}, "OPNsense 25.1.4_1"},
		{map[string]string{fileOPNsenseOld: "21.7.8\n"}, "OPNsense 21.7.8"},
		{map[string]string{filePlatform: "pfSense\n", fileVersion: "2.7.2-RELEASE\n"}, "pfSense 2.7.2-RELEASE"},
		{map[string]string{fileVersion: "TrueNAS-13.0-U6.1\n"}, "TrueNAS-13.0-U6.1"},
		{map[string]string{fileFreeBSDVer: "#!/bin/sh\nUSERLAND_VERSION=\"14.1-RELEASE-p6\"\n"}, "FreeBSD 14.1-RELEASE-p6"},
		{map[string]string{fileFreeBSDVer: "USERLAND_VERSION=\"$(rm -rf /)\"\n"}, "FreeBSD 14.1-RELEASE-p5"},
		{nil, "FreeBSD 14.1-RELEASE-p5"},
	} {
		if got := DetectPlatform(files(c.files), "14.1-RELEASE-p5"); got != c.want {
			t.Errorf("%v: %q, erwartet %q", c.files, got, c.want)
		}
	}
	sc := fakeSysctl{"kern.osrelease": []byte("14.1-RELEASE-p5\x00"), "kern.boottime": append(enc64(1794000000), enc64(0)...)}.fn()
	p, k, boot := hostInfo(sc, files(nil))
	if p != "FreeBSD 14.1-RELEASE-p5" || k != "14.1-RELEASE-p5" || boot != 1794000000 {
		t.Fatalf("hostInfo: %q %q %d", p, k, boot)
	}
	if p, _, _ := hostInfo(fakeSysctl{}.fn(), files(nil)); p != "" {
		t.Fatalf("ohne sysctl: %q", p)
	}
}

func TestZpoolFreeBSD(t *testing.T) {
	pools := m64linux.ParseZpoolList([]byte("zroot\t483183820800\t21474836480\t461708984320\t3\tONLINE\ntank\t3985729650688\t1992864825344\t1992864825344\t12\tDEGRADED\n"))
	m64linux.MergeZpoolStatus(pools, m64linux.ParseZpoolStatus(readTestdata(t, "zpool_status_freebsd14_nachgebaut.txt")))
	if len(pools) != 2 || pools[0].Errors != "No known data errors" || !strings.Contains(pools[0].ScanText, "scrub repaired") {
		t.Fatalf("zroot: %+v", pools)
	}
	if !strings.Contains(pools[1].Errors, "could not be opened") || pools[1].FragPct != 12 {
		t.Fatalf("tank: %+v", pools[1])
	}
}

// TestParsersHostile: Muell, riesige Zahlen und Steuerzeichen duerfen keinen Parser zum Absturz bringen.
func TestParsersHostile(t *testing.T) {
	inputs := [][]byte{nil, []byte("\x00\xff\xfe"), []byte(strings.Repeat("a", 1<<16)),
		[]byte(strings.Repeat("device x\n", 1000)), []byte("{\"statistics\":{\"interface\":[{\"name\":\"" + strings.Repeat("x", 5000) + "\"}]}}"),
		[]byte("igb0: flags=8843<UP> metric 0 mtu 99999999999999999999\n\tmedia: Ethernet autoselect (\n\tlaggport: \n\tstatus: \x1b[31m\n"),
		[]byte("mirror/x  DEGRADED\n   \n(\n  ada0 (((\n"), []byte("Geom name:\n   rotationrate: -5\n   ident: \x07\n")}
	for _, b := range inputs {
		_, _ = ParseIostat(b)
		_ = ParseGeomDisks(b)
		_, _, _ = ParseNetstatJSON(b)
		cfgs := ParseIfconfig(b)
		_, _ = BuildNet(nil, nil, cfgs)
		_ = ParseGeomStatus(geomRAID, b)
		_ = ParsePkgVersion(b)
		_, _, _ = ParsePkgAudit(b, b, 1)
		_, _ = ParseFreeBSDVersion(b)
		_, _, _ = ParseSwapinfo(b)
		_, _ = ParseCPTime(b, 8)
		_, _ = ParseLoadavg(b, 8)
		_, _ = ParseBoottime(b)
		_, _, _ = ParseXswdev(b)
		_, _ = ParseIK(b)
	}
	cfgs := ParseIfconfig([]byte("igb0: flags=8843<UP> metric 0 mtu 99999999999999999999\n\tstatus: \x1b[31mactive\n"))
	if len(cfgs) != 1 || cfgs[0].MTU != 0 || strings.ContainsRune(cfgs[0].Status, 0x1b) {
		t.Fatalf("%+v", cfgs)
	}
}
