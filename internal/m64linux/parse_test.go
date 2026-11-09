package m64linux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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

// section liefert den ersten Abschnitt einer aufgezeichneten Skript-Ausgabe.
func section(t *testing.T, file, name string) []byte {
	t.Helper()
	for _, s := range splitSections(readTestdata(t, file)) {
		if s.name == name {
			return s.body
		}
	}
	t.Fatalf("%s: Abschnitt %q fehlt", file, name)
	return nil
}

func TestParseStat(t *testing.T) {
	c, err := ParseStat(section(t, "script_debian12_vm.txt", "file:/proc/stat"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Cores != 12 || c.User == 0 || c.Idle == 0 {
		t.Fatalf("cpu: %+v", c)
	}
	c, err = ParseStat([]byte("cpu  1 2 3 4\ncpu0 1 2 3 4\n"))
	if err != nil || c.Cores != 1 || c.User != 1 || c.Idle != 4 || c.IOWait != 0 {
		t.Fatalf("alte Kernel: %+v %v", c, err)
	}
	if _, err := ParseStat([]byte("Muell")); err == nil {
		t.Fatal("Fehler erwartet")
	}
}

func TestParseMeminfo(t *testing.T) {
	m, err := ParseMeminfo(section(t, "script_proxmox8.txt", "file:/proc/meminfo"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Total != 65777316*1024 || m.Available != 20123456*1024 || m.SwapTotal != 8388604*1024 || m.SwapFree != 8388000*1024 {
		t.Fatalf("mem: %+v", m)
	}
	// ohne MemAvailable (Kernel < 3.14): MemFree + Buffers + Cached
	m, err = ParseMeminfo([]byte("MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 200 kB\n"))
	if err != nil || m.Available != 350*1024 {
		t.Fatalf("Schaetzung: %+v %v", m, err)
	}
	if _, err := ParseMeminfo([]byte("")); err == nil {
		t.Fatal("Fehler erwartet")
	}
}

func TestParseLoadUptime(t *testing.T) {
	l, err := ParseLoadavg([]byte("0.00 0.00 0.09 1/280 240438\n"))
	if err != nil || l.L15 != 0.09 {
		t.Fatalf("%+v %v", l, err)
	}
	if _, err := ParseLoadavg([]byte("x y")); err == nil {
		t.Fatal("Fehler erwartet")
	}
	up, err := ParseUptime([]byte("54332.87 645719.36\n"))
	if err != nil || up != 54332.87 {
		t.Fatalf("%v %v", up, err)
	}
}

func TestParseMountsEscape(t *testing.T) {
	ms := ParseMounts([]byte("/dev/sdd1 /mnt/disks/My\\040Backup ext4 ro,noatime 0 0\n"))
	if len(ms) != 1 || ms[0].Mount != "/mnt/disks/My Backup" || !ms[0].ReadOnly {
		t.Fatalf("%+v", ms)
	}
}

func TestSkipMount(t *testing.T) {
	cases := map[Mount]bool{
		{Device: "/dev/sda1", Mount: "/", Type: "ext4"}:                                  false,
		{Device: "tmpfs", Mount: "/run", Type: "tmpfs"}:                                  true,
		{Device: "overlay", Mount: "/var/lib/docker/overlay2/x/merged", Type: "overlay"}: true,
		{Device: "/dev/loop2", Mount: "/var/lib/docker", Type: "btrfs"}:                  true,
		{Device: "/dev/loop5", Mount: "/snap/core/1", Type: "squashfs"}:                  true,
		{Device: "/dev/fuse", Mount: "/etc/pve", Type: "fuse"}:                           true,
		{Device: "lxcfs", Mount: "/var/lib/lxcfs", Type: "fuse.lxcfs"}:                   true,
		{Device: "srv:/x", Mount: "/mnt/x", Type: "nfs4"}:                                true,
		{Device: "shfs", Mount: "/mnt/user", Type: "fuse.shfs"}:                          false,
		{Device: "pool", Mount: "/srv/mergerfs/pool", Type: "fuse.mergerfs"}:             false,
		{Device: "/dev/sda1", Mount: "/run/media/usb", Type: "vfat"}:                     true,
		{Device: "rootfs", Mount: "/", Type: "rootfs"}:                                   true,
	}
	for m, want := range cases {
		if got := SkipMount(m); got != want {
			t.Errorf("SkipMount(%+v) = %v, erwartet %v", m, got, want)
		}
	}
}

func TestParseDFBusyBox(t *testing.T) {
	// BusyBox ohne -T: keine Typ-Spalte; Typ kommt aus /proc/mounts
	df := section(t, "script_synology_dsm7.txt", "df")
	rows := ParseDF(df)
	if len(rows) != 11 || rows[0].Type != "" || rows[0].Mount != "/" || rows[0].Total != 8191416*1024 {
		t.Fatalf("%d %+v", len(rows), rows[0])
	}
	mounts := ParseMounts(section(t, "script_synology_dsm7.txt", "file:/proc/mounts"))
	fsl := FSFromDF(rows, mounts, nil)
	got := mountsOf(fsl)
	want := "/ /volume1 /volumeUSB1/usbshare"
	if got != want {
		t.Fatalf("Mounts %q, erwartet %q", got, want)
	}
	if fsl[1].Type != "btrfs" {
		t.Fatalf("Typ aus /proc/mounts fehlt: %+v", fsl[1])
	}
}

func mountsOf(fsl []m64proto.FS) string {
	var s []string
	for _, f := range fsl {
		s = append(s, f.Mount)
	}
	return strings.Join(s, " ")
}

func TestFSFromStatfs(t *testing.T) {
	mounts := ParseMounts(section(t, "script_proxmox8.txt", "file:/proc/mounts"))
	called := map[string]bool{}
	fsl, errs := FSFromStatfs(mounts, func(p string) (StatFS, error) {
		called[p] = true
		return StatFS{Total: 1000, Free: 400, Avail: 300, InodesTotal: 10, InodesFree: 5}, nil
	})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	want := "/ /rpool /rpool/ROOT /rpool/data /rpool/data/subvol-101-disk-0 /tank /mnt/backup"
	if got := mountsOf(fsl); got != want {
		t.Fatalf("Mounts %q, erwartet %q", got, want)
	}
	if called["/mnt/pve/nas-iso"] || called["/etc/pve"] {
		t.Fatal("statfs auf Netz-/Pseudo-FS")
	}
	if f := fsl[0]; f.Used != 600 || f.Avail != 300 || f.InodesFree != 5 || f.Type != "zfs" {
		t.Fatalf("%+v", f)
	}
}

func TestParseDiskstats(t *testing.T) {
	ds := ParseDiskstats(section(t, "script_proxmox8.txt", "file:/proc/diskstats"))
	var names []string
	for _, d := range ds {
		names = append(names, d.Name)
	}
	if strings.Join(names, " ") != "nvme0n1 nvme1n1 sda sdb" {
		t.Fatalf("%v", names)
	}
	if ds[0].ReadBytes != 98765432*512 || ds[0].WriteOps != 2345678 || ds[0].IOTimeMs != 345678 {
		t.Fatalf("%+v", ds[0])
	}
	// Synology DSM 7.2: sataN, ohne synoboot/md/zram/dm
	ds = ParseDiskstats(section(t, "script_synology_dsm7.txt", "file:/proc/diskstats"))
	names = nil
	for _, d := range ds {
		names = append(names, d.Name)
	}
	if strings.Join(names, " ") != "sata1 sata2" {
		t.Fatalf("%v", names)
	}
	for _, n := range []string{"mmcblk0", "xvda", "vdb", "hdc", "nvme10n2"} {
		if !IsWholeDisk(n) {
			t.Errorf("%s: ganze Platte erwartet", n)
		}
	}
	for _, n := range []string{"mmcblk0p1", "nvme0n1p1", "sda1", "dm-0", "loop0", "zram0", "md127", "zd16", "sr0", "mmcblk0boot0"} {
		if IsWholeDisk(n) {
			t.Errorf("%s: keine ganze Platte", n)
		}
	}
}

func TestSerialFromWWID(t *testing.T) {
	if s := serialFromWWID("t10.ATA     Samsung SSD 870 EVO 1TB                     S6PTNM0T123456K     "); s != "S6PTNM0T123456K" {
		t.Fatal(s)
	}
	if s := serialFromWWID("naa.5000c500a1b2c3d4"); s != "" {
		t.Fatal(s)
	}
}

func TestParseBonding(t *testing.T) {
	b, err := ParseBonding("bond0", section(t, "script_proxmox8.txt", "file:/proc/net/bonding/bond0"))
	if err != nil {
		t.Fatal(err)
	}
	if b.Mode != "IEEE 802.3ad Dynamic link aggregation" || b.MII != "up" || b.AggregateID != 1 || b.PartnerMAC != "74:83:c2:aa:bb:cc" {
		t.Fatalf("%+v", b)
	}
	if len(b.Members) != 2 {
		t.Fatalf("%+v", b.Members)
	}
	m0, m1 := b.Members[0], b.Members[1]
	if m0.Name != "eno1" || m0.MII != "up" || m0.SpeedMbit != 1000 || m0.AggregateID != 1 || m0.LinkFailures != 0 {
		t.Fatalf("%+v", m0)
	}
	if m1.Name != "eno2" || m1.MII != "down" || m1.SpeedMbit != 0 || m1.AggregateID != 2 || m1.LinkFailures != 3 {
		t.Fatalf("%+v", m1)
	}
	b, err = ParseBonding("bond0", section(t, "script_unraid612.txt", "file:/proc/net/bonding/bond0"))
	if err != nil || b.Mode != "fault-tolerance (active-backup)" || len(b.Members) != 1 || b.Members[0].SpeedMbit != 2500 || b.Members[0].LinkFailures != 1 {
		t.Fatalf("%+v %v", b, err)
	}
	if _, err := ParseBonding("x", []byte("Muell")); err == nil {
		t.Fatal("Fehler erwartet")
	}
}

func TestParseMdstat(t *testing.T) {
	rs := ParseMdstat(readTestdata(t, "mdstat_omv.txt"))
	if len(rs) != 7 {
		t.Fatalf("%d: %+v", len(rs), rs)
	}
	byName := map[string]m64proto.RAID{}
	for _, r := range rs {
		byName[r.Name] = r
	}
	check := func(name, state string, dev, act, failed, spare int, sync float64) {
		t.Helper()
		r := byName[name]
		if r.State != state || r.Devices != dev || r.Active != act || r.Failed != failed || r.Spare != spare {
			t.Errorf("%s: %+v", name, r)
		}
		switch {
		case sync < 0 && r.SyncPercent != nil:
			t.Errorf("%s: kein Sync erwartet, %v", name, *r.SyncPercent)
		case sync >= 0 && (r.SyncPercent == nil || *r.SyncPercent != sync):
			t.Errorf("%s: Sync %v erwartet", name, sync)
		}
	}
	check("md0", "resyncing", 4, 4, 0, 0, 12.6)
	check("md1", "recovering", 2, 1, 1, 0, 38.1)
	check("md2", "degraded", 2, 1, 0, 1, -1)
	check("md3", "active", 2, 2, 0, 0, -1)
	check("md4", "failed", 1, 0, 0, 1, -1)
	check("md5", "active", 4, 4, 0, 0, 2.5) // Pruefung: Zustand bleibt
	check("md6", "resyncing", 2, 2, 0, 0, -1)
	if byName["md0"].Level != "raid5" || len(byName["md1"].Members) != 3 || byName["md3"].Level != "raid0" {
		t.Errorf("%+v %+v", byName["md0"], byName["md1"])
	}
	// Synology: alles sauber
	for _, r := range ParseMdstat(section(t, "script_synology_dsm7.txt", "file:/proc/mdstat")) {
		if r.State != "active" || r.Devices != 2 || r.Active != 2 {
			t.Errorf("synology %+v", r)
		}
	}
}

func TestParseZpool(t *testing.T) {
	pools := ParseZpoolList(section(t, "script_proxmox8.txt", "zpool_list"))
	if len(pools) != 2 || pools[0].Name != "rpool" || pools[0].Size != 1992864825344 || pools[0].FragPct != 3 || pools[1].Health != "DEGRADED" {
		t.Fatalf("%+v", pools)
	}
	st := ParseZpoolStatus(section(t, "script_proxmox8.txt", "zpool_status"))
	mergeZpoolStatus(pools, st)
	if pools[0].Errors != "No known data errors" || !strings.HasPrefix(pools[0].ScanText, "scrub repaired 0B") {
		t.Fatalf("%+v", pools[0])
	}
	if !strings.Contains(pools[1].ScanText, "16.42% done") || !strings.HasPrefix(pools[1].Errors, "One or more devices could not be used") {
		t.Fatalf("%+v", pools[1])
	}
	// aeltere zpool-Versionen: frag mit %
	p := ParseZpoolList([]byte("data\t100\t50\t50\t7%\tONLINE\n"))
	if len(p) != 1 || p[0].FragPct != 7 {
		t.Fatalf("%+v", p)
	}
}

func TestParseSmartctl(t *testing.T) {
	nv := ParseSmartctl("/dev/nvme0", section(t, "script_proxmox8.txt", "smart:/dev/nvme0"))
	if nv.Type != "nvme" || nv.Serial != "S5GXNF0R123456A" || nv.Passed == nil || !*nv.Passed || *nv.TempC != 42 ||
		*nv.PowerOnHours != 18234 || *nv.WearPercentUsed != 7 || *nv.MediaErrors != 0 || *nv.CriticalWarning != 0 ||
		nv.CapacityBytes != 1000204886016 || nv.Error != "" {
		t.Fatalf("%+v", nv)
	}
	ata := ParseSmartctl("/dev/sda", section(t, "script_proxmox8.txt", "smart:/dev/sda"))
	if ata.Type != "ata" || ata.Model != "Samsung SSD 870 EVO 1TB" || *ata.Reallocated != 0 || *ata.Pending != 0 ||
		*ata.Uncorrectable != 0 || *ata.CRCErrors != 2 || *ata.WearPercentUsed != 4 || *ata.TempC != 33 || *ata.PowerOnHours != 12045 {
		t.Fatalf("%+v", ata)
	}
	sb := ParseSmartctl("/dev/sdb", section(t, "script_proxmox8.txt", "smart:/dev/sdb"))
	if sb.Error != SmartErrStandby || sb.Passed != nil {
		t.Fatalf("%+v", sb)
	}
	sas := ParseSmartctl("/dev/sdc", readTestdata(t, "smart_scsi_sas.json"))
	if sas.Type != "scsi" || sas.Model != "SEAGATE ST4000NM0023" || *sas.Reallocated != 12 || *sas.Uncorrectable != 3 ||
		*sas.PowerOnHours != 45678 || *sas.TempC != 38 || !*sas.Passed {
		t.Fatalf("%+v", sas)
	}
	usb := ParseSmartctl("/dev/sdd", readTestdata(t, "smart_usb_unknown.json"))
	if usb.Device != "/dev/sdd" || !strings.Contains(usb.Error, "Unknown USB bridge") || usb.Passed != nil {
		t.Fatalf("%+v", usb)
	}
	fail := ParseSmartctl("/dev/sde", readTestdata(t, "smart_ata_failing.json"))
	if fail.Passed == nil || *fail.Passed || *fail.WearPercentUsed != 91 || *fail.Reallocated != 3 {
		t.Fatalf("%+v", fail)
	}
	old := ParseSmartctl("/dev/sata1", readTestdata(t, "smart_smartctl65.txt"))
	if !strings.HasPrefix(old.Error, "keine JSON-Ausgabe") {
		t.Fatalf("%+v", old)
	}
	vm := ParseSmartctl("/dev/sda", section(t, "script_debian12_vm.txt", "smart:/dev/sda"))
	if vm.Error != "SMART nicht verfuegbar" || vm.Model != "QEMU QEMU HARDDISK" || vm.TempC != nil {
		t.Fatalf("%+v", vm)
	}
	if s := ParseSmartctl("/dev/x", []byte("{kaputt")); !strings.HasPrefix(s.Error, "JSON") {
		t.Fatalf("%+v", s)
	}
}

func TestParseSmartScan(t *testing.T) {
	devs, err := ParseSmartScan([]byte(`{"devices":[{"name":"/dev/sda","type":"sat"},{"name":"/dev/nvme0","type":"nvme"},
		{"name":"/dev/sdb; rm -rf /","type":"sat"},{"name":"/dev/bus/0","type":"megaraid,1"},{"name":"/dev/sdc","type":"sat -x"},
		{"name":"/dev/../etc/passwd","type":"sat"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 3 || devs[0] != (SmartDevice{"/dev/sda", "sat"}) || devs[2] != (SmartDevice{"/dev/bus/0", "megaraid,1"}) {
		t.Fatalf("%+v", devs)
	}
	devs, err = ParseSmartScan([]byte("/dev/sda -d sat # /dev/sda [SAT], ATA device\n# /dev/sdb -d usbjmicron # open failed\n/dev/nvme0 -d nvme # /dev/nvme0, NVMe device\n/dev/sdX$(id) -d sat #\n"))
	if err != nil || len(devs) != 2 || devs[1].Name != "/dev/nvme0" || devs[1].Type != "nvme" {
		t.Fatalf("%+v %v", devs, err)
	}
}

func TestParseSystemd(t *testing.T) {
	f := ParseSystemdFailed([]byte("zfs-import@tank.service loaded failed failed Import ZFS pool tank\n● foo.mount loaded failed failed Foo\n"))
	if len(f) != 2 || f[0] != "zfs-import@tank.service" || f[1] != "foo.mount" {
		t.Fatalf("%v", f)
	}
	if f := ParseSystemdFailed(nil); f == nil || len(f) != 0 {
		t.Fatalf("leere Liste erwartet: %#v", f)
	}
	if s := ParseSystemdState([]byte("degraded\n")); s != "degraded" {
		t.Fatal(s)
	}
}

func TestParseUpdates(t *testing.T) {
	cases := []struct {
		mgr        string
		list, sec  string
		pend, secN int
		wantMgr    string
	}{
		{"aptcheck", "12;3", "", 12, 3, "apt"},
		{"apt", string(section(t, "script_debian12_vm.txt", "updates:apt")), "", 29, 23, "apt"},
		{"dnf", `
kernel.x86_64                     6.10.9-200.fc40          updates
openssl-libs.x86_64               1:3.2.2-3.fc40           updates
a-very-long-package-name-that-wraps.noarch
                                  1.2.3-1.fc40             updates
Obsoleting Packages
grub2-tools.x86_64                1:2.06-121.fc40          updates
    grub2-tools.x86_64            1:2.06-120.fc40          @updates
`, `FEDORA-2024-1a2b3c4d5e Important/Sec. openssl-libs-1:3.2.2-3.fc40.x86_64
FEDORA-2024-1a2b3c4d5e Important/Sec. openssl-1:3.2.2-3.fc40.x86_64
FEDORA-2024-9f8e7d6c5b Moderate/Sec.  kernel-6.10.9-200.fc40.x86_64
FEDORA-2024-0000000000 bugfix         foo-1.0-1.fc40.noarch
`, 3, 3, "dnf"},
		{"dnf", "kernel.x86_64 6.10.9-200.fc41 updates\n", `Name                 Type     Severity  Package                         Issued
FEDORA-2024-1a2b3c4d security Important openssl-libs-1:3.2.2-3.fc41.x86_64 2024-09-10 01:02:03
`, 1, 1, "dnf"},
		{"zypper", `S | Repository             | Name     | Current Version | Available Version | Arch
--+------------------------+----------+-----------------+-------------------+-------
v | Main Update Repository | aaa_base | 84.87-1.1       | 84.87-2.1         | x86_64
v | Main Update Repository | openssl  | 3.1.4-1.1       | 3.1.4-2.1         | x86_64
`, `Repository             | Name               | Category | Severity  | Interactive | Status | Summary
-----------------------+--------------------+----------+-----------+-------------+--------+--------
Main Update Repository | openSUSE-2024-1234 | security | important | ---         | needed | Security update for openssl
Main Update Repository | openSUSE-2024-1200 | security | moderate  | ---         | applied | Security update for curl
`, 2, 1, "zypper"},
		{"pacman", "linux 6.10.8.arch1-1 -> 6.10.9.arch1-1\nopenssl 3.3.1-1 -> 3.3.2-1\nfoo 1-1 -> 2-1 [ignored]\n", "", 2, 0, "pacman"},
		{"apk", "busybox-1.36.1-r29 x86_64 {busybox} (GPL-2.0-only) [upgradable from: busybox-1.36.1-r28]\nmusl-1.2.5-r1 x86_64 {musl} (MIT) [upgradable from: musl-1.2.5-r0]\n", "", 2, 0, "apk"},
		{"opkg", "dnsmasq - 2.89-4 - 2.90-1\nluci-base - 23.051 - 23.051.1\n", "", 2, 0, "opkg"},
	}
	for _, c := range cases {
		u, err := ParseUpdates(c.mgr, []byte(c.list), []byte(c.sec))
		if err != nil {
			t.Fatalf("%s: %v", c.mgr, err)
		}
		if u.Pending != c.pend || u.Security != c.secN || u.Manager != c.wantMgr {
			t.Errorf("%s: %+v, erwartet %d/%d", c.mgr, u, c.pend, c.secN)
		}
	}
	if _, err := ParseUpdates("aptcheck", []byte("Traceback"), nil); err == nil {
		t.Fatal("Fehler erwartet")
	}
	if _, err := ParseUpdates("brew", nil, nil); err == nil {
		t.Fatal("Fehler erwartet")
	}
}

func TestReadTemps(t *testing.T) {
	r, err := ParseScriptOutput(readTestdata(t, "script_proxmox8.txt"), testNow)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]m64proto.Temp{}
	var names []string
	for _, tp := range r.Temps {
		got[tp.Name] = tp
		names = append(names, tp.Name)
	}
	want := "acpitz/temp1 | nvme@nvme0/Composite | nvme@nvme0/Sensor 1 | nvme@nvme1/Composite | coretemp/Package id 0 | coretemp/Core 0 | thermal/x86_pkg_temp"
	if got := strings.Join(names, " | "); got != want {
		t.Fatalf("Namen %q", got)
	}
	c := got["nvme@nvme0/Composite"]
	if c.C != 41.85 || c.Crit == nil || *c.Crit != 84.85 || c.High == nil || *c.High != 81.85 || c.Label != "Composite" {
		t.Fatalf("%+v", c)
	}
	if s := got["nvme@nvme0/Sensor 1"]; s.Crit != nil { // -273150 ist kein Grenzwert
		t.Fatalf("%+v", s)
	}
	// Pi: hwmon cpu_thermal, Zone cpu-thermal entfaellt
	r, err = ParseScriptOutput(readTestdata(t, "script_raspios12.txt"), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Temps) != 1 || r.Temps[0].Name != "cpu_thermal/temp1" || r.Temps[0].C != 47.236 || *r.Temps[0].Crit != 110 {
		t.Fatalf("%+v", r.Temps)
	}
}

func TestClip(t *testing.T) {
	s := clip(strings.Repeat("ä", 400) + "\x00\n")
	if len(s) > maxText || !strings.HasPrefix(s, "ää") || strings.ContainsAny(s, "\x00\n") {
		t.Fatalf("%q", s)
	}
	if clip("a\xffb") != "a?b" {
		t.Fatal(clip("a\xffb"))
	}
}
