package m64win

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
)

func TestCPUFromTimes(t *testing.T) {
	c := cpuFromTimes(900_000_000, 1_000_000_000, 300_000_000, 8)
	if c.Cores != 8 || c.Idle != 9000 || c.System != 1000 || c.User != 3000 || c.Util != nil {
		t.Fatalf("cpu = %+v", c)
	}
	// kernel < idle (kaputte Werte): kein Unterlauf
	if c := cpuFromTimes(10, 5, 0, 1); c.System != 0 {
		t.Fatalf("system = %d", c.System)
	}
}

func pagefileEntry(next, size, inUse uint32) []byte {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b[0:], next)
	binary.LittleEndian.PutUint32(b[4:], size)
	binary.LittleEndian.PutUint32(b[8:], inUse)
	return b
}

func TestParsePagefiles(t *testing.T) {
	two := append(pagefileEntry(32, 1000, 100), pagefileEntry(0, 500, 600)...) // belegt > gesamt wird gekappt
	for _, tc := range []struct {
		name        string
		buf         []byte
		total, used uint64
		ok          bool
	}{
		{"leer", nil, 0, 0, false},
		{"eine", pagefileEntry(0, 1000, 250), 1000 * 4096, 250 * 4096, true},
		{"zwei", two, 1500 * 4096, 600 * 4096, true},
		{"kaputter Offset", pagefileEntry(0xffffffff, 10, 1), 10 * 4096, 4096, true},
		{"Schleife", pagefileEntry(1, 1, 0)[:16], 4096, 0, true},
		{"zu kurz", make([]byte, 10), 0, 0, false},
	} {
		total, used, ok := parsePagefiles(tc.buf, 4096)
		if total != tc.total || used != tc.used || ok != tc.ok {
			t.Errorf("%s: %d %d %v", tc.name, total, used, ok)
		}
	}
	// Selbstverweis (NextEntryOffset zeigt immer weiter): hoechstens 64 Eintraege
	loop := make([]byte, 16*100)
	for i := 0; i < 100; i++ {
		copy(loop[i*16:], pagefileEntry(16, 1, 1)[:16])
	}
	if total, _, _ := parsePagefiles(loop, 1); total != 64 {
		t.Fatalf("Schleife: %d Eintraege", total)
	}
}

func TestParseDiskPerf(t *testing.T) {
	b := make([]byte, 88)
	le := binary.LittleEndian
	le.PutUint64(b[0:], 1000)
	le.PutUint64(b[8:], 2000)
	le.PutUint64(b[32:], 5_000_000)  // idle 0,5 s
	le.PutUint32(b[40:], 7)          // reads
	le.PutUint32(b[44:], 9)          // writes
	le.PutUint64(b[56:], 25_000_000) // query 2,5 s
	p, ok := parseDiskPerf(b)
	if !ok || p.bytesRead != 1000 || p.bytesWritten != 2000 || p.reads != 7 || p.writes != 9 || p.ioTimeMs() != 2000 {
		t.Fatalf("perf = %+v %v (io %d)", p, ok, p.ioTimeMs())
	}
	if _, ok := parseDiskPerf(b[:40]); ok {
		t.Fatal("zu kurz angenommen")
	}
	if (diskPerf{idle: 10, query: 5}).ioTimeMs() != 0 || (diskPerf{idle: -1, query: 5}).ioTimeMs() != 0 {
		t.Fatal("Unsinn nicht verworfen")
	}
}

func storageDescBuf(vendor, product, serial string, bus uint32, removable bool) []byte {
	b := make([]byte, 40)
	le := binary.LittleEndian
	add := func(s string) uint32 {
		if s == "" {
			return 0
		}
		off := uint32(len(b))
		b = append(b, append([]byte(s), 0)...)
		return off
	}
	v, p, s := add(vendor), add(product), add(serial)
	le.PutUint32(b[4:], uint32(len(b)))
	if removable {
		b[10] = 1
	}
	le.PutUint32(b[12:], v)
	le.PutUint32(b[16:], p)
	le.PutUint32(b[24:], s)
	le.PutUint32(b[28:], bus)
	return b
}

func TestParseStorageDesc(t *testing.T) {
	d, ok := parseStorageDesc(storageDescBuf("", "Corsair MP700 PRO", "0000_0000_6479_A7A3_E300_001E.", 17, false))
	if !ok || d.model() != "Corsair MP700 PRO" || d.serial != "0000_0000_6479_A7A3_E300_001E" || d.bus != 17 || d.removable {
		t.Fatalf("desc = %+v", d)
	}
	d, _ = parseStorageDesc(storageDescBuf("ATA", "WDC WD40EFRX", "  WD-123 ", 11, false))
	if d.model() != "ATA WDC WD40EFRX" || d.serial != "WD-123" {
		t.Fatalf("desc = %+v (%s)", d, d.model())
	}
	d, _ = parseStorageDesc(storageDescBuf("Generic", "Generic MassStorageClass", "1210", 7, true))
	if !d.removable || d.model() != "Generic MassStorageClass" {
		t.Fatalf("desc = %+v", d)
	}
	// Offsets ausserhalb, Text ohne Nullbyte, zu kurz
	b := storageDescBuf("x", "y", "z", 1, false)
	binary.LittleEndian.PutUint32(b[24:], 9999)
	if d, ok := parseStorageDesc(b); !ok || d.serial != "" {
		t.Fatalf("Offset ausserhalb: %+v", d)
	}
	if _, ok := parseStorageDesc(make([]byte, 20)); ok {
		t.Fatal("zu kurz angenommen")
	}
	long := storageDescBuf("", strings.Repeat("A", 500), "", 0, false)
	long = long[:len(long)-1] // ohne Nullbyte
	if d, _ := parseStorageDesc(long); len(d.product) > maxText {
		t.Fatalf("Text nicht gekuerzt: %d", len(d.product))
	}
}

func TestNetHelpers(t *testing.T) {
	for _, tc := range []struct {
		flags uint8
		typ   uint32
		kind  string
		skip  bool
	}{
		{ifFlagHardware | ifFlagConnector, 6, "physical", false},
		{ifFlagHardware | ifFlagConnector | ifFlagFilter, 6, "", true},
		{ifFlagHardware, 6, "virtual", false}, // z. B. Wi-Fi Direct
		{0, 6, "virtual", false},              // Hyper-V vEthernet, VPN
		{ifFlagHardware | ifFlagConnector, ifTypeLoopback, "", true},
		{0, ifTypeTunnel, "", true},
	} {
		k, s := netKind(tc.flags, tc.typ)
		if k != tc.kind || s != tc.skip {
			t.Errorf("netKind(%x, %d) = %q %v", tc.flags, tc.typ, k, s)
		}
	}
	if linkSpeedMbit(10_000_000_000) != 10000 || linkSpeedMbit(0) != 0 || linkSpeedMbit(^uint64(0)) != 0 {
		t.Error("linkSpeedMbit")
	}
	if macString([]byte{0x98, 0xb7, 0x85, 0x1e, 0xca, 0x60}) != "98:b7:85:1e:ca:60" || macString(make([]byte, 6)) != "" || macString(nil) != "" {
		t.Error("macString")
	}
}

func TestSvcWanted(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    svcInfo
		want bool
	}{
		{"auto laeuft", svcInfo{startType: svcAutoStart, state: svcRunning}, true},
		{"auto gestoppt", svcInfo{startType: svcAutoStart, state: svcStopped, exitCode: 1067}, true},
		{"auto nie gestartet", svcInfo{startType: svcAutoStart, state: svcStopped, exitCode: 1077}, true},
		{"auto sauber beendet", svcInfo{startType: svcAutoStart, state: svcStopped}, true},
		{"verzoegert sauber beendet", svcInfo{startType: svcAutoStart, delayed: true, state: svcStopped}, false},
		{"verzoegert mit Fehler", svcInfo{startType: svcAutoStart, delayed: true, state: svcStopped, exitCode: 1066, specific: 3}, true},
		{"verzoegert laeuft", svcInfo{startType: svcAutoStart, delayed: true, state: svcRunning}, true},
		{"Trigger", svcInfo{startType: svcAutoStart, triggers: 2, state: svcStopped, exitCode: 1067}, false},
		{"manuell", svcInfo{startType: 3, state: svcStopped}, false},
		{"deaktiviert", svcInfo{startType: 4}, false},
	} {
		if got := svcWanted(tc.s); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
	if svcState(4) != "running" || svcState(1) != "stopped" || svcState(99) != "unknown" {
		t.Error("svcState")
	}
}

func TestRebootFrom(t *testing.T) {
	if r := rebootFrom(false, false, false, false); r.Required || r.Packages != nil {
		t.Fatalf("%+v", r)
	}
	r := rebootFrom(true, true, true, true)
	if !r.Required || strings.Join(r.Packages, ",") != "Windows Update,Component Based Servicing,PendingFileRenameOperations" {
		t.Fatalf("%+v", r)
	}
	if r := rebootFrom(false, false, false, true); !r.Required || r.Packages[0] != "Windows Update" {
		t.Fatalf("%+v", r)
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseStorageAdmin(t *testing.T) {
	res, err := ParseStorage(readFixture(t, "storage_admin.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.smart) != 3 || len(res.errs) != 0 {
		t.Fatalf("smart %d errs %v", len(res.smart), res.errs)
	}
	nv, hdd, ssd := res.smart[0], res.smart[1], res.smart[2]
	if nv.Device != "PhysicalDrive0" || nv.Type != "nvme" || nv.Serial != "0025_38B1_4140_A1B2" || nv.Passed == nil || !*nv.Passed ||
		nv.TempC == nil || *nv.TempC != 41 || nv.WearPercentUsed == nil || *nv.WearPercentUsed != 3 ||
		nv.PowerOnHours == nil || *nv.PowerOnHours != 1234 || nv.Uncorrectable == nil || *nv.Uncorrectable != 0 || nv.CapacityBytes != 2000398934016 {
		t.Errorf("nvme = %+v", nv)
	}
	// Warning mit "Predictive Failure" = SMART-Vorhersage; HDD ohne Verschleiss
	if hdd.Type != "ata" || hdd.Passed == nil || *hdd.Passed || hdd.WearPercentUsed != nil || hdd.Uncorrectable == nil || *hdd.Uncorrectable != 12 {
		t.Errorf("hdd = %+v", hdd)
	}
	// Zahlen statt Namen, einzelner Wert statt Liste, 0 = unbekannt, Verschleiss > 100 verworfen
	if ssd.Type != "ata" || ssd.Passed == nil || *ssd.Passed || ssd.TempC != nil || ssd.WearPercentUsed != nil || ssd.PowerOnHours != nil ||
		ssd.Uncorrectable != nil || ssd.CapacityBytes != 500107862016 {
		t.Errorf("ssd = %+v", ssd)
	}
	if res.vdisks != 1 || len(res.raid) != 1 {
		t.Fatalf("raid = %+v", res.raid)
	}
	r := res.raid[0]
	if r.Name != "Spiegel" || r.Level != "mirror" || r.State != "degraded" || r.Devices != 2 || r.Active != 1 || r.Failed != 1 {
		t.Errorf("raid = %+v", r)
	}
	if len(res.notes) != 0 {
		t.Errorf("notes = %+v", res.notes)
	}
}

func TestParseStorageUser(t *testing.T) {
	res, err := ParseStorage(readFixture(t, "storage_user.json"))
	if err != nil {
		t.Fatal(err)
	}
	// ohne Adminrechte: Zustand ja, Zaehler nein - Hinweis statt Fehler (sonst "SMART nicht lesbar" je Platte)
	if len(res.smart) != 2 || res.smart[0].Error != "" || res.smart[0].Passed == nil || res.smart[0].TempC != nil || len(res.errs) != 0 {
		t.Fatalf("res = %+v", res)
	}
	if len(res.notes) != 1 || res.notes[0].Section != m64proto.SecSmart || !strings.Contains(res.notes[0].Note, "Administratorrechte") {
		t.Fatalf("notes = %+v", res.notes)
	}
}

func TestParseStorageErrors(t *testing.T) {
	if _, err := ParseStorage(readFixture(t, "storage_fatal.json")); err == nil || !strings.Contains(err.Error(), "Get-PhysicalDisk") {
		t.Fatalf("fatal: %v", err)
	}
	if _, err := ParseStorage([]byte("#< CLIXML\n<Objs>")); err == nil {
		t.Fatal("kein JSON angenommen")
	}
	res, err := ParseStorage([]byte(`{"disks":[],"vdisks":[],"errors":["Get-PhysicalDisk: Zugriff verweigert","Get-VirtualDisk: kaputt"]}`))
	if err != nil || len(res.errs) != 2 || res.errs[0].Section != m64proto.SecSmart || res.errs[1].Section != m64proto.SecRAID {
		t.Fatalf("errs = %+v %v", res.errs, err)
	}
	res, _ = ParseStorage([]byte(`{"disks":[],"vdisks":[],"errors":[]}`))
	if len(res.notes) != 1 || res.notes[0].Note != "keine Platten gefunden" || res.smart == nil {
		t.Fatalf("leer = %+v", res)
	}
	// PowerShell 5.1: Liste mit einem Element als Einzelwert
	res, err = ParseStorage([]byte(`{"disks":[],"vdisks":[],"errors":"Get-VirtualDisk: x"}`))
	if err != nil || len(res.errs) != 1 {
		t.Fatalf("Einzelwert: %+v %v", res.errs, err)
	}
}

func TestVDiskStates(t *testing.T) {
	for _, tc := range []struct {
		health string
		op     flexList
		want   string
	}{
		{"Healthy", flexList{"OK"}, "clean"},
		{"Warning", flexList{"In Service"}, "recovering"},
		{"Warning", flexList{"Degraded"}, "degraded"},
		{"Warning", flexList{"No Redundancy"}, "degraded"},
		{"Unhealthy", flexList{"Detached"}, "failed"},
		{"Healthy", flexList{"Lost Communication"}, "failed"},
		{"", nil, "unknown"},
	} {
		if r := vdiskRAID("v", "Parity", flexStr(tc.health), tc.op, nil); r.State != tc.want {
			t.Errorf("%s %v: %s", tc.health, tc.op, r.State)
		}
	}
}

func TestParseUpdates(t *testing.T) {
	now := time.Unix(1700000000, 0)
	u, reboot, err := ParseUpdates([]byte(`{"pending":5,"security":2,"reboot":true}`), now)
	if err != nil || !reboot || u.Manager != "windows" || u.Pending != 5 || u.Security != 2 || u.Checked != now.Unix() {
		t.Fatalf("%+v %v %v", u, reboot, err)
	}
	if u, _, _ := ParseUpdates([]byte(`{"pending":1,"security":9}`), now); u.Security != 1 {
		t.Fatalf("security > pending: %+v", u)
	}
	for _, bad := range []string{`{"fatal":"0x8024402C"}`, `{}`, `{"pending":-1}`, `{"pending":"NaN"}`, `kaputt`} {
		if _, _, err := ParseUpdates([]byte(bad), now); err == nil {
			t.Errorf("%s angenommen", bad)
		}
	}
}

func TestFillSmartSerials(t *testing.T) {
	sm := []m64proto.SMART{{Device: "PhysicalDrive0", Serial: "ps"}, {Device: "PhysicalDrive1", Serial: "x"}}
	fillSmartSerials(sm, []m64proto.DiskIO{{Name: "PhysicalDrive0", Serial: "io"}, {Name: "PhysicalDrive1"}})
	if sm[0].Serial != "io" || sm[1].Serial != "x" {
		t.Fatalf("%+v", sm)
	}
}

func TestFlexJSON(t *testing.T) {
	var v struct {
		A flexStr  `json:"a"`
		B flexList `json:"b"`
		C num      `json:"c"`
		D num      `json:"d"`
	}
	if err := json.Unmarshal([]byte(`{"a":17,"b":"OK","c":"42","d":1e300}`), &v); err != nil {
		t.Fatal(err)
	}
	if v.A != "17" || len(v.B) != 1 || v.B[0] != "OK" || !v.C.ok || v.C.v != 42 || v.D.ok {
		t.Fatalf("%+v", v)
	}
	if !(flexList{"Predictive Failure"}).has("PredictiveFailure") || (flexList{"OK"}).has("Degraded") {
		t.Fatal("has")
	}
}

func TestCacheSlow(t *testing.T) {
	c := NewCache()
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	var runs atomic.Int32
	release := make(chan struct{})
	fn := func(ctx context.Context) slowResult {
		runs.Add(1)
		<-release
		return slowResult{updates: &m64proto.Updates{Pending: int(runs.Load())}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	res := c.slow(ctx, clock, "k", m64proto.SecUpdates, time.Hour, fn)
	cancel()
	if len(res.notes) != 1 || res.notes[0].Note != NoteReading || res.notes[0].Section != m64proto.SecUpdates {
		t.Fatalf("erster Lauf: %+v", res)
	}
	// laufender Lauf wird nicht doppelt gestartet
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Millisecond)
	c.slow(ctx2, clock, "k", m64proto.SecUpdates, time.Hour, fn)
	cancel2()
	close(release)
	c.Wait()
	if runs.Load() != 1 {
		t.Fatalf("%d Laeufe", runs.Load())
	}
	res = c.slow(context.Background(), clock, "k", m64proto.SecUpdates, time.Hour, fn)
	if res.updates == nil || res.updates.Pending != 1 {
		t.Fatalf("Stand: %+v", res)
	}
	// veraltet: alter Stand sofort, Erneuerung im Hintergrund
	now = now.Add(2 * time.Hour)
	res = c.slow(context.Background(), clock, "k", m64proto.SecUpdates, time.Hour, fn)
	c.Wait()
	if res.updates.Pending != 1 || runs.Load() != 2 {
		t.Fatalf("veraltet: %+v %d", res, runs.Load())
	}
	if r, ok := c.peek("k"); !ok || r.updates.Pending != 2 {
		t.Fatalf("peek: %+v %v", r, ok)
	}
	// Fehler: neuer Versuch schon nach slowRetry
	errFn := func(ctx context.Context) slowResult {
		runs.Add(1)
		return slowResult{errs: []m64proto.SectionErr{{Section: "x", Error: errors.New("kaputt").Error()}}}
	}
	c2 := NewCache()
	c2.slow(context.Background(), clock, "e", "x", time.Hour, errFn)
	c2.Wait()
	before := runs.Load()
	now = now.Add(slowRetry + time.Second)
	c2.slow(context.Background(), clock, "e", "x", time.Hour, errFn)
	c2.Wait()
	if runs.Load() != before+1 {
		t.Fatal("kein neuer Versuch nach Fehler")
	}
}

func TestClip(t *testing.T) {
	if s := clip("a\x00b\r\nc\xff"); s != "a b  c?" {
		t.Fatalf("%q", s)
	}
	if s := clip(strings.Repeat("ä", 400)); len(s) > maxText || !strings.HasPrefix(s, "ää") {
		t.Fatalf("%d", len(s))
	}
}
