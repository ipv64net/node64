package m64bsd

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64"
)

// fakeSysctl ist eine sysctl-Tabelle; Argumente haengen als ".N" am Namen ("vm.swap_info.0").
type fakeSysctl map[string][]byte

func (f fakeSysctl) fn() SysctlFunc {
	return func(name string, args ...int) ([]byte, error) {
		for _, a := range args {
			name += "." + strconv.Itoa(a)
		}
		if b, ok := f[name]; ok {
			return b, nil
		}
		return nil, syscall.ENOENT
	}
}

// fakeExec liefert vorbereitete Ausgaben je Befehlszeile und merkt sich die Aufrufe.
type fakeExec struct {
	mu    sync.Mutex
	out   map[string]ExecResult
	calls []string
}

func (f *fakeExec) exec(_ context.Context, name string, args ...string) (ExecResult, error) {
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.mu.Lock()
	f.calls = append(f.calls, cmd)
	f.mu.Unlock()
	if r, ok := f.out[cmd]; ok {
		return r, nil
	}
	return ExecResult{}, errors.New(name + ": " + ErrNotFound.Error())
}

func (f *fakeExec) called(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// opnsenseHost baut einen OPNsense-Host mit ZFS, lagg, gmirror und SMART. cp ist kern.cp_time.
func opnsenseHost(t *testing.T, cp []uint64) (fakeSysctl, *fakeExec, func(string) bool) {
	t.Helper()
	longSize = 8
	t.Cleanup(func() { longSize = strconv.IntSize / 8 })
	load := append(append(append(append(enc32(410), enc32(307)...), enc32(205)...), enc32(0)...), enc64(2048)...)
	sc := fakeSysctl{
		"kern.cp_time":                     encLongs(8, cp...),
		"hw.ncpu":                          enc32(4),
		"hw.physmem":                       enc64(8 << 30),
		"hw.pagesize":                      enc32(4096),
		"vm.stats.vm.v_free_count":         enc32(262144),
		"vm.stats.vm.v_inactive_count":     enc32(131072),
		"vm.stats.vm.v_cache_count":        enc32(0),
		"kstat.zfs.misc.arcstats.size":     enc64(3 << 30),
		"kstat.zfs.misc.arcstats.c_min":    enc64(1 << 30),
		"vm.swap_info.0":                   xswdev(524288, 2560),
		"vm.loadavg":                       load,
		"kern.boottime":                    append(enc64(1794000000), enc64(0)...),
		"dev.cpu.0.temperature":            enc32(3231),
		"hw.acpi.thermal.tz0.temperature":  enc32(3001),
		"kern.geom.mirror.debug":           enc32(0),
		"net.link.lagg.default_use_flowid": enc32(1),
	}
	ex := &fakeExec{out: map[string]ExecResult{
		"iostat " + strings.Join(iostatArgs, " "): {Stdout: readTestdata(t, "iostat_xI_freebsd14_nachgebaut.txt")},
		"geom disk list": {Stdout: readTestdata(t, "geom_disk_list_nachgebaut.txt")},
		"ifconfig -a":    {Stdout: readTestdata(t, "ifconfig_opnsense25_nachgebaut.txt")},
		"netstat " + strings.Join(netstatArgs, " "): {Stdout: readTestdata(t, "netstat_ibn_opnsense25_nachgebaut.json")},
		"gmirror status": {Stdout: readTestdata(t, "gmirror_status_degraded_nachgebaut.txt")},
		"zpool list -Hp -o name,size,alloc,free,frag,health": {Stdout: []byte("zroot\t483183820800\t21474836480\t461708984320\t3\tONLINE\n")},
		"zpool status":                                  {Stdout: readTestdata(t, "zpool_status_freebsd14_nachgebaut.txt")},
		"freebsd-version -k -r":                         {Stdout: []byte("14.2-RELEASE-p2\n14.2-RELEASE-p1\n")},
		"smartctl --scan-open -j":                       {Stdout: readTestdata(t, "smartctl_scan_freebsd14_nachgebaut.json")},
		"smartctl -j -a -n standby -d atacam /dev/ada0": {Stdout: readTestdata(t, "smartctl_ada0_freebsd14_nachgebaut.json")},
		"smartctl -j -a -n standby -d atacam /dev/ada1": {Stdout: []byte(`{"smartctl":{"exit_status":2,"messages":[{"string":"Device is in STANDBY mode, exit(2)","severity":"information"}]},"device":{"name":"/dev/ada1","type":"atacam","protocol":"ATA"}}`), Code: 2},
		"smartctl -j -a -n standby -d nvme /dev/nvme0":  {Stdout: []byte(`{"device":{"name":"/dev/nvme0","type":"nvme","protocol":"NVMe"},"model_name":"Samsung SSD 970 EVO Plus 500GB","serial_number":"S4EVNX0N123456A","smart_status":{"passed":true},"nvme_smart_health_information_log":{"critical_warning":0,"temperature":41,"percentage_used":3,"power_on_hours":9000,"media_errors":0}}`)},
		"/usr/local/sbin/pkg version -U -R -l <":        {Stdout: []byte("curl-8.10.1   <\nlibxml2-2.11.8   <\nopnsense-25.1.4_1   <\n")},
		"/usr/local/sbin/pkg audit":                     {Stdout: readTestdata(t, "pkg_audit_vuln_nachgebaut.txt"), Code: 1},
	}}
	has := map[string]bool{"iostat": true, "geom": true, "ifconfig": true, "netstat": true, "gmirror": true, "graid": true,
		"zpool": true, "freebsd-version": true, "smartctl": true, "/usr/local/sbin/pkg": true, "swapinfo": true}
	return sc, ex, func(n string) bool { return has[n] }
}

func opnsenseMounts() ([]Mount, error) {
	return []Mount{
		{Device: "zroot/ROOT/default", Mount: "/", Type: "zfs", Local: true},
		{Device: "devfs", Mount: "/dev", Type: "devfs", Local: true},
		{Device: "tmpfs", Mount: "/var/log", Type: "tmpfs", Local: true},
		{Device: "zroot/tmp", Mount: "/tmp", Type: "zfs", Local: true},
	}, nil
}

func fixedStatfs(string) (StatFS, error) {
	return StatFS{Total: 100 << 30, Free: 80 << 30, Avail: 80 << 30, InodesTotal: 1000, InodesFree: 900}, nil
}

func TestCollectOPNsense(t *testing.T) {
	sc, ex, has := opnsenseHost(t, []uint64{1000, 10, 500, 50, 8000})
	cache := NewCache()
	now := time.Unix(1794003600, 0)
	opt := Options{Exec: ex.exec, Has: has, Sysctl: sc.fn(), Mounts: opnsenseMounts, Statfs: fixedStatfs, Cache: cache,
		Now: func() time.Time { return now }}
	r := Collect(context.Background(), opt)
	cache.Wait()
	if len(r.Errors) > 0 {
		t.Fatalf("Fehler: %+v", r.Errors)
	}
	if r.V != m64proto.Version || r.Time != now.UnixMilli() || r.Uptime != 3600 {
		t.Fatalf("Kopf: %+v", r)
	}
	if r.CPU == nil || r.CPU.Cores != 4 || r.CPU.User != 1000 || r.CPU.IRQ != 50 || r.CPU.Idle != 8000 {
		t.Fatalf("cpu: %+v", r.CPU)
	}
	if r.Mem == nil || r.Mem.Total != 8<<30 || r.Mem.Available != 3<<30+512<<20 || r.Mem.SwapTotal != 2<<30 || r.Mem.SwapFree != (524288-2560)*4096 {
		t.Fatalf("mem: %+v", r.Mem)
	}
	if r.Load == nil || r.Load.L1 != 0.2 || r.Load.L5 != 0.15 || r.Load.L15 != 0.1 {
		t.Fatalf("load: %+v", r.Load)
	}
	if len(r.FS) != 2 || r.FS[0].Mount != "/" || r.FS[1].Mount != "/tmp" {
		t.Fatalf("fs: %+v", r.FS)
	}
	if len(r.Disks) != 3 || r.Disks[0].Serial != "WD-WCC7K1ABCDEF" || r.Disks[2].Serial != "S4EVNX0N123456A" {
		t.Fatalf("disk: %+v", r.Disks)
	}
	if len(r.Net) != 13 || len(r.Bonds) != 1 {
		t.Fatalf("net/bond: %d %d", len(r.Net), len(r.Bonds))
	}
	if len(r.RAID) != 3 || r.RAID[0].State != "recovering" {
		t.Fatalf("raid: %+v", r.RAID)
	}
	if ex.called("graid") {
		t.Fatal("graid ohne geladenes Modul aufgerufen")
	}
	if len(r.Temps) != 2 {
		t.Fatalf("temp: %+v", r.Temps)
	}
	if len(r.ZFS) != 1 || r.ZFS[0].Errors != "No known data errors" {
		t.Fatalf("zfs: %+v", r.ZFS)
	}
	// langsame Abschnitte: erster Lauf ist mit dem schnellen Fake innerhalb von slowFirstWait fertig
	if r.Reboot == nil || !r.Reboot.Required {
		t.Fatalf("reboot: %+v (notes %+v)", r.Reboot, r.Notes)
	}
	if len(r.SMART) != 3 || r.SMART[0].Serial != "WD-WCC7K1ABCDEF" || r.SMART[0].Passed == nil || !*r.SMART[0].Passed ||
		r.SMART[1].Error != "standby" || r.SMART[2].WearPercentUsed == nil {
		t.Fatalf("smart: %+v", r.SMART)
	}
	if r.Updates == nil || r.Updates.Manager != "pkg" || r.Updates.Pending != 3 || r.Updates.Security != 2 || r.Updates.Checked != now.Unix() {
		t.Fatalf("updates: %+v (notes %+v)", r.Updates, r.Notes)
	}
	if r.Systemd != nil {
		t.Fatal("kein systemd-Abschnitt unter FreeBSD")
	}

	// zweiter Bericht 60 s spaeter: Mapper rechnet Raten und erkennt die Probleme
	sc["kern.cp_time"] = encLongs(8, 1300, 10, 650, 100, 8500) // 1000 Ticks, davon 500 idle
	now = now.Add(time.Minute)
	r2 := Collect(context.Background(), opt)
	cache.Wait()
	svcs := monitor64.MapReport(r, r2)
	by := map[string]monitor64.Service{}
	for _, s := range svcs {
		by[s.Key] = s
	}
	metric := func(key, name string) (float64, bool) {
		for _, m := range by[key].Metrics {
			if m.Name == name {
				return m.Value, true
			}
		}
		return 0, false
	}
	if v, ok := metric("cpu", "util"); !ok || v != 50 {
		t.Fatalf("cpu util: %v %v", v, ok)
	}
	hasFact := func(key, code string) bool {
		for _, f := range by[key].Facts {
			if f.Code == code {
				return true
			}
		}
		return false
	}
	for _, c := range []struct{ key, fact string }{
		{"bond:lagg0", "bond_member_down"}, {"reboot", "reboot_required"}, {"updates", "updates_security"},
		{"raid:mirror/swap", "raid_degraded"},
	} {
		if !hasFact(c.key, c.fact) {
			t.Errorf("%s: Fact %s fehlt (%+v)", c.key, c.fact, by[c.key])
		}
	}
	if hasFact("raid:mirror/gm0", "raid_degraded") { // Wiederaufbau laeuft: wie mdraid "recovering"
		t.Error("gm0 im Wiederaufbau meldet raid_degraded")
	}
	// Platte ada0: I/O (iostat) und SMART unter derselben Seriennummer; nda0 und nvme0 ebenso
	for _, key := range []string{"disk:WD-WCC7K1ABCDEF", "disk:S4EVNX0N123456A", "disk:WD-WCC7K1GHIJKL"} {
		if _, ok := by[key]; !ok {
			t.Errorf("%s fehlt: %v", key, keys(by))
		}
	}
	for _, key := range []string{"if:pflog0", "if:wg1", "if:lo0", "disk:nvme0", "disk:nda0"} {
		if _, ok := by[key]; ok {
			t.Errorf("%s gehoert nicht in die Dienste", key)
		}
	}
	if s, ok := by["if:igb0"]; !ok || !strings.Contains(s.Name, "1 Gbit/s") {
		t.Errorf("igb0: %+v", s)
	}
	if _, ok := by["temp:cpu/0"]; !ok {
		t.Error("temp:cpu/0 fehlt")
	}
}

func keys(m map[string]monitor64.Service) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCollectSections(t *testing.T) {
	sc, ex, has := opnsenseHost(t, []uint64{1, 2, 3, 4, 5})
	r := Collect(context.Background(), Options{Sections: []string{m64proto.SecCPU, m64proto.SecLoad}, Exec: ex.exec, Has: has,
		Sysctl: sc.fn(), Mounts: opnsenseMounts, Statfs: fixedStatfs, Cache: NewCache()})
	if r.CPU == nil || r.Load == nil || r.Mem != nil || r.FS != nil || r.Net != nil || len(r.Temps) != 0 {
		t.Fatalf("%+v", r)
	}
	if len(ex.calls) != 0 {
		t.Fatalf("Programme aufgerufen: %v", ex.calls)
	}
}

func TestCollectNoZFSModule(t *testing.T) {
	sc, ex, has := opnsenseHost(t, []uint64{1, 2, 3, 4, 5})
	delete(sc, "kstat.zfs.misc.arcstats.size") // UFS-Installation: zpool wuerde zfs.ko laden
	r := Collect(context.Background(), Options{Sections: []string{m64proto.SecZFS, m64proto.SecMem}, Exec: ex.exec, Has: has,
		Sysctl: sc.fn(), Cache: NewCache()})
	if ex.called("zpool") || r.ZFS != nil {
		t.Fatalf("zpool ohne ZFS-Modul: %v", ex.calls)
	}
	if r.Mem == nil || r.Mem.Available != 1536<<20 { // ohne ARC
		t.Fatalf("mem: %+v", r.Mem)
	}
	for _, c := range Caps(Options{Has: has, Sysctl: sc.fn()}) {
		if c == m64proto.SecZFS {
			t.Fatal("zfs in Caps ohne Modul")
		}
	}
}

func TestCollectEmptyHost(t *testing.T) {
	ex := &fakeExec{}
	r := Collect(context.Background(), Options{Exec: ex.exec, Has: func(string) bool { return false }, Sysctl: fakeSysctl{}.fn(),
		Mounts: func() ([]Mount, error) { return nil, errors.New("kaputt") }, Cache: NewCache()})
	secs := map[string]bool{}
	for _, e := range r.Errors {
		secs[e.Section] = true
	}
	for _, s := range []string{m64proto.SecCPU, m64proto.SecMem, m64proto.SecLoad, m64proto.SecFS, m64proto.SecNet} {
		if !secs[s] {
			t.Errorf("Fehler fuer %s fehlt: %+v", s, r.Errors)
		}
	}
	notes := map[string]string{}
	for _, n := range r.Notes {
		notes[n.Section] = n.Note
	}
	if notes[m64proto.SecSmart] != "smartctl fehlt" || notes[m64proto.SecUpdates] != "pkg nicht installiert" || notes[m64proto.SecDisk] != "iostat fehlt" {
		t.Fatalf("notes: %+v", r.Notes)
	}
	if r.Reboot != nil || r.CPU != nil || r.Uptime != 0 {
		t.Fatalf("%+v", r)
	}
	caps := Caps(Options{Has: func(string) bool { return false }, Sysctl: fakeSysctl{}.fn()})
	if strings.Join(caps, ",") != "cpu,mem,load,fs,net,temp" {
		t.Fatalf("caps: %v", caps)
	}
}

func TestCollectUpdatesTrueNAS(t *testing.T) {
	ex := &fakeExec{out: map[string]ExecResult{
		"/usr/local/sbin/pkg version -U -R -l <": {Stderr: []byte("pkg: No active remote repositories configured.\n"), Code: 3},
	}}
	has := func(n string) bool { return n == "/usr/local/sbin/pkg" }
	r := Collect(context.Background(), Options{Sections: []string{m64proto.SecUpdates}, Exec: ex.exec, Has: has, Sysctl: fakeSysctl{}.fn(), Cache: NewCache()})
	if r.Updates != nil || len(r.Errors) != 0 || len(r.Notes) != 1 || r.Notes[0].Note != "keine Paketquelle eingeschaltet" {
		t.Fatalf("%+v", r)
	}
	// Katalog fehlt: Fehler (Abschnitt Unbekannt), ohne Schwachstellen-DB: Hinweis
	ex.out["/usr/local/sbin/pkg version -U -R -l <"] = ExecResult{Stderr: []byte("pkg: Repository OPNsense missing. 'pkg update' required\n"), Code: 1}
	r = Collect(context.Background(), Options{Sections: []string{m64proto.SecUpdates}, Exec: ex.exec, Has: has, Sysctl: fakeSysctl{}.fn(), Cache: NewCache()})
	if r.Updates != nil || len(r.Errors) != 1 || !strings.Contains(r.Errors[0].Error, "pkg update") {
		t.Fatalf("Katalog fehlt: %+v", r)
	}
	ex.out["/usr/local/sbin/pkg version -U -R -l <"] = ExecResult{}
	ex.out["/usr/local/sbin/pkg audit"] = ExecResult{Stderr: []byte("pkg: vulnxml file /var/db/pkg/vuln.xml does not exist. Try running 'pkg audit -F' first\n"), Code: 1}
	r = Collect(context.Background(), Options{Sections: []string{m64proto.SecUpdates}, Exec: ex.exec, Has: has, Sysctl: fakeSysctl{}.fn(), Cache: NewCache()})
	if r.Updates == nil || r.Updates.Pending != 0 || len(r.Notes) != 1 || !strings.Contains(r.Notes[0].Note, "Schwachstellen-Datenbank") {
		t.Fatalf("ohne vuln.xml: %+v", r)
	}
	if ex.called("/usr/sbin/pkg") || ex.called("pkg ") {
		t.Fatal("Bootstrap-pkg aufgerufen")
	}
}

func TestCollectSwapFallback(t *testing.T) {
	sc, ex, has := opnsenseHost(t, []uint64{1, 2, 3, 4, 5})
	bad := xswdev(1, 0)
	bad[0] = 9 // unbekannte Version
	sc["vm.swap_info.0"] = bad
	ex.out["swapinfo -k"] = ExecResult{Stdout: []byte("Device          1K-blocks     Used    Avail Capacity\n/dev/ada0p3       2097152    10240  2086912     0%\n")}
	r := Collect(context.Background(), Options{Sections: []string{m64proto.SecMem}, Exec: ex.exec, Has: has, Sysctl: sc.fn(), Cache: NewCache()})
	if r.Mem == nil || r.Mem.SwapTotal != 2097152*1024 || len(r.Errors) != 0 {
		t.Fatalf("%+v %+v", r.Mem, r.Errors)
	}
}

func TestCollectNetstatBroken(t *testing.T) {
	sc, ex, has := opnsenseHost(t, []uint64{1, 2, 3, 4, 5})
	ex.out["netstat "+strings.Join(netstatArgs, " ")] = ExecResult{Stdout: []byte(`{"statistics":{"interface":[{"name":"em0","network":"<Link#1>","ibytes":5}]}}`)}
	r := Collect(context.Background(), Options{Sections: []string{m64proto.SecNet, m64proto.SecBond}, Exec: ex.exec, Has: has, Sysctl: sc.fn(), Cache: NewCache()})
	if len(r.Errors) != 1 || r.Errors[0].Section != m64proto.SecNet || len(r.Bonds) != 1 {
		t.Fatalf("%+v bonds=%d", r.Errors, len(r.Bonds))
	}
}

func TestCaps(t *testing.T) {
	sc, _, has := opnsenseHost(t, []uint64{1, 2, 3, 4, 5})
	got := strings.Join(Caps(Options{Has: has, Sysctl: sc.fn()}), ",")
	if got != "cpu,mem,load,fs,net,temp,disk,bond,raid,zfs,smart,updates,reboot" {
		t.Fatalf("caps: %s", got)
	}
}

// TestCollectDeadline: ein haengendes Programm darf Collect nicht ueber die Deadline hinaus aufhalten.
func TestCollectDeadline(t *testing.T) {
	sc, _, has := opnsenseHost(t, []uint64{1, 2, 3, 4, 5})
	hang := func(ctx context.Context, name string, args ...string) (ExecResult, error) {
		<-ctx.Done()
		return ExecResult{}, errors.New(name + ": Zeitlimit")
	}
	old := refreshTimeout
	refreshTimeout = 500 * time.Millisecond // Hintergrundlauf (SMART) endet bald
	defer func() { refreshTimeout = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	start := time.Now()
	cache := NewCache()
	r := Collect(ctx, Options{Sections: []string{m64proto.SecNet, m64proto.SecDisk, m64proto.SecSmart}, Exec: hang, Has: has, Sysctl: sc.fn(), Cache: cache})
	if d := time.Since(start); d > 5500*time.Millisecond {
		t.Fatalf("Collect dauerte %s", d)
	}
	if len(r.Errors) == 0 {
		t.Fatal("Fehler erwartet")
	}
	notes := ""
	for _, n := range r.Notes {
		notes += n.Note
	}
	if !strings.Contains(notes, NoteReading) {
		t.Fatalf("SMART: Hinweis %q erwartet: %+v", NoteReading, r.Notes)
	}
	cache.Wait()
}

// TestStatfsTimeout: ein haengendes statfs (z. B. ZFS-Pool SUSPENDED) wird nach statfsLimit gemeldet und nicht
// erneut gestartet.
func TestStatfsTimeout(t *testing.T) {
	old := statfsLimit
	statfsLimit = 100 * time.Millisecond
	defer func() { statfsLimit = old }()
	release := make(chan struct{})
	var mu sync.Mutex
	started := 0
	st := func(p string) (StatFS, error) {
		if p == "/mnt/tank" {
			mu.Lock()
			started++
			mu.Unlock()
			<-release
		}
		return fixedStatfs(p)
	}
	mounts := func() ([]Mount, error) {
		return []Mount{{Device: "zroot", Mount: "/", Type: "zfs", Local: true}, {Device: "tank", Mount: "/mnt/tank", Type: "zfs", Local: true}}, nil
	}
	opt := Options{Sections: []string{m64proto.SecFS}, Sysctl: fakeSysctl{}.fn(), Mounts: mounts, Statfs: st, Cache: NewCache()}
	for i := 0; i < 3; i++ {
		r := Collect(context.Background(), opt)
		if len(r.FS) != 1 || len(r.Errors) != 1 || !strings.Contains(r.Errors[0].Error, "/mnt/tank") {
			t.Fatalf("Runde %d: %+v %+v", i, r.FS, r.Errors)
		}
	}
	mu.Lock()
	n := started
	mu.Unlock()
	if n != 1 {
		t.Fatalf("statfs %d-mal gestartet", n)
	}
	close(release)
}

func TestCollectConcurrent(t *testing.T) {
	sc, ex, has := opnsenseHost(t, []uint64{1, 2, 3, 4, 5})
	cache := NewCache()
	opt := Options{Exec: ex.exec, Has: has, Sysctl: sc.fn(), Mounts: opnsenseMounts, Statfs: fixedStatfs, Cache: cache}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = Collect(context.Background(), opt)
		}()
	}
	wg.Wait()
	cache.Wait()
	n := 0
	ex.mu.Lock()
	for _, c := range ex.calls {
		if c == "smartctl --scan-open -j" {
			n++
		}
	}
	ex.mu.Unlock()
	if n != 1 {
		t.Fatalf("SMART %d-mal gelesen (Puffer)", n)
	}
}
