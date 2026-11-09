package promscrape

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
)

var testNow = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func loadFixture(t testing.TB, name string) *Metrics {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(b, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestNodeReportReal(t *testing.T) {
	m := loadFixture(t, "node_exporter-1.12.1.txt")
	if k, v := detect(m); k != ExporterNode || v != "1.12.1" {
		t.Fatalf("detect = %q %q", k, v)
	}
	r := nodeReport(m, testNow)
	if r.V != m64proto.Version || r.Time != testNow.UnixMilli() {
		t.Errorf("Kopf %+v", r)
	}
	if r.Uptime < 60000 || r.Uptime > 80000 { // 1794238330 - 1794171014
		t.Errorf("Uptime %v", r.Uptime)
	}
	if r.CPU == nil || r.CPU.Cores != 12 || r.CPU.Idle == 0 || r.CPU.User == 0 || r.CPU.Util != nil {
		t.Fatalf("CPU %+v", r.CPU)
	}
	if r.Mem == nil || r.Mem.Total != 8324374528 || r.Mem.Available != 7449853952 || r.Mem.SwapTotal != 1022357504 || r.Mem.SwapFree != 918548480 {
		t.Errorf("Mem %+v", r.Mem)
	}
	if r.Load == nil || r.Load.L1 != 0.14 || r.Load.L5 != 0.04 || r.Load.L15 != 0.17 {
		t.Errorf("Load %+v", r.Load)
	}
	if len(r.FS) != 1 || r.FS[0].Mount != "/" || r.FS[0].Type != "ext4" || r.FS[0].Total != 51510796288 ||
		r.FS[0].Avail != 13829779456 || r.FS[0].Used != 51510796288-16479633408 || r.FS[0].InodesTotal == 0 {
		t.Errorf("FS %+v", r.FS)
	}
	if len(r.Disks) != 1 || r.Disks[0].Name != "sda" || r.Disks[0].WriteBytes != 59730313216 || r.Disks[0].IOTimeMs != 796648 ||
		r.Disks[0].Rotational == nil || *r.Disks[0].Rotational {
		t.Errorf("Disks %+v", r.Disks)
	}
	kinds := map[string]m64proto.NetIf{}
	for _, n := range r.Net {
		kinds[n.Name] = n
	}
	if e := kinds["ens18"]; e.Kind != "physical" || !e.Up || e.RxBytes != 8688610395 || e.SpeedMbit != 0 || e.MAC == "" || e.MTU != 1500 {
		t.Errorf("ens18 %+v", e)
	}
	for _, v := range []string{"lo", "docker0", "veth978671e", "br-d28b5f971274"} {
		if kinds[v].Kind != "virtual" {
			t.Errorf("%s nicht virtuell: %+v", v, kinds[v])
		}
	}
	if r.Systemd == nil || len(r.Systemd.Failed) != 0 || r.Systemd.State != "running" {
		t.Errorf("Systemd %+v", r.Systemd)
	}
	if r.Reboot == nil || !r.Reboot.Required {
		t.Errorf("Reboot %+v", r.Reboot)
	}
	if r.Updates == nil || r.Updates.Manager != "apt" || r.Updates.Pending != 7 || r.Updates.Security != 2 {
		t.Errorf("Updates %+v", r.Updates)
	}
	if len(r.Bonds)+len(r.RAID)+len(r.ZFS)+len(r.Temps) != 0 {
		t.Errorf("unerwartet: %+v %+v %+v %+v", r.Bonds, r.RAID, r.ZFS, r.Temps)
	}
	if fc := failedCollectors(m, ExporterNode); strings.Join(fc, ",") != "bcachefs,bonding,fibrechannel,infiniband,ipvs,kernel_hung,mdadm,nfs,nfsd,tapestats,watchdog,zfs" {
		t.Errorf("failed %v", fc)
	}
}

func TestNodeReportE2E(t *testing.T) {
	m := loadFixture(t, "node_exporter-e2e-excerpt.txt")
	r := nodeReport(m, testNow)

	raid := map[string]m64proto.RAID{}
	for _, x := range r.RAID {
		raid[x.Name] = x
	}
	if x := raid["md0"]; x.State != "active" || x.Devices != 2 || x.Active != 2 || x.Failed != 0 || x.SyncPercent != nil || x.Level != "mdraid" {
		t.Errorf("md0 %+v", x)
	}
	if x := raid["md11"]; x.Failed != 1 || x.Spare != 2 {
		t.Errorf("md11 %+v", x)
	}
	// Wiederaufbau auf die Reserve nach einem Ausfall: Zustand recovering mit Fortschritt (wie beim Agent); die
	// defekte Platte (Failed) meldet der Mapper weiter als raid_degraded
	if x := raid["md6"]; x.State != "recovering" || x.SyncPercent == nil || x.Failed != 1 {
		t.Errorf("md6 %+v", x)
	}
	var syncing int
	for _, x := range r.RAID {
		if x.SyncPercent != nil {
			syncing++
			if *x.SyncPercent < 0 || *x.SyncPercent > 100 {
				t.Errorf("Sync %s %v", x.Name, *x.SyncPercent)
			}
		}
	}
	if syncing == 0 {
		t.Error("kein RAID im Sync")
	}

	bonds := map[string]m64proto.Bond{}
	for _, b := range r.Bonds {
		bonds[b.Name] = b
	}
	if b := bonds["int"]; len(b.Members) != 2 || b.Members[0].MII != "up" || b.Members[1].MII != "down" || b.MII != "up" {
		t.Errorf("int %+v", b)
	}
	if b := bonds["dmz"]; len(b.Members) != 2 || b.Members[1].MII != "up" {
		t.Errorf("dmz %+v", b)
	}
	if b := bonds["bond0"]; len(b.Members) != 0 || b.MII != "down" {
		t.Errorf("bond0 %+v", b)
	}
	for _, n := range r.Net {
		if n.Name == "bond0" && n.Kind != "bond" {
			t.Errorf("bond0 Art %q", n.Kind)
		}
		if n.Name == "eth0" && (n.SpeedMbit != 1000 || !n.Up) {
			t.Errorf("eth0 %+v", n)
		}
	}

	zfs := map[string]string{}
	for _, z := range r.ZFS {
		zfs[z.Name] = z.Health
	}
	if zfs["pool1"] != "ONLINE" || zfs["poolz1"] != "DEGRADED" || zfs["pool2"] != "SUSPENDED" {
		t.Errorf("ZFS %v", zfs)
	}

	temps := map[string]m64proto.Temp{}
	for _, x := range r.Temps {
		temps[x.Name] = x
	}
	if x, ok := temps["coretemp@platform_coretemp_0/Core 0"]; !ok || x.C != 54 || x.Crit == nil || *x.Crit != 100 || x.Label != "Core 0" {
		t.Errorf("coretemp: %+v (%v)", x, keys(temps))
	}
	if _, ok := temps["hwmon4/foosensor"]; !ok {
		t.Errorf("hwmon4: %v", keys(temps))
	}
	if _, ok := temps["hwmon4/foosensor#2"]; !ok {
		t.Errorf("doppelter Name nicht nummeriert: %v", keys(temps))
	}
	if _, ok := temps["thermal/cpu-thermal"]; !ok {
		t.Errorf("thermal: %v", keys(temps))
	}

	disks := map[string]m64proto.DiskIO{}
	for _, d := range r.Disks {
		disks[d.Name] = d
	}
	if d := disks["sda"]; d.Serial != "2160A0D5FVGG" || d.Model != "TOSHIBA KSDB4U86" || d.Rotational == nil || !*d.Rotational {
		t.Errorf("sda %+v", d)
	}
	if d := disks["nvme0n1"]; d.Serial != "S252B6CU1HG3M1" {
		t.Errorf("nvme %+v", d)
	}
	for n := range disks {
		if strings.HasPrefix(n, "dm-") || strings.HasPrefix(n, "sr") || strings.Contains(n, "p1") {
			t.Errorf("keine ganze Platte: %s", n)
		}
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestNodeFilters(t *testing.T) {
	in := `node_filesystem_size_bytes{device="/dev/sda1",fstype="ext4",mountpoint="/"} 1000
node_filesystem_free_bytes{device="/dev/sda1",fstype="ext4",mountpoint="/"} 400
node_filesystem_avail_bytes{device="/dev/sda1",fstype="ext4",mountpoint="/"} 300
node_filesystem_size_bytes{device="/dev/sda1",fstype="ext4",mountpoint="/var/lib/docker/overlay"} 1000
node_filesystem_free_bytes{device="/dev/sda1",fstype="ext4",mountpoint="/var/lib/docker/overlay"} 400
node_filesystem_avail_bytes{device="/dev/sda1",fstype="ext4",mountpoint="/var/lib/docker/overlay"} 300
node_filesystem_size_bytes{device="/dev/sdb1",fstype="btrfs",mountpoint="/srv/data/sub"} 2000
node_filesystem_free_bytes{device="/dev/sdb1",fstype="btrfs",mountpoint="/srv/data/sub"} 1000
node_filesystem_avail_bytes{device="/dev/sdb1",fstype="btrfs",mountpoint="/srv/data/sub"} 1000
node_filesystem_size_bytes{device="/dev/sdb1",fstype="btrfs",mountpoint="/srv"} 2000
node_filesystem_free_bytes{device="/dev/sdb1",fstype="btrfs",mountpoint="/srv"} 1000
node_filesystem_avail_bytes{device="/dev/sdb1",fstype="btrfs",mountpoint="/srv"} 1000
node_filesystem_size_bytes{device="server:/x",fstype="nfs4",mountpoint="/mnt/nfs"} 2000
node_filesystem_free_bytes{device="server:/x",fstype="nfs4",mountpoint="/mnt/nfs"} 1000
node_filesystem_avail_bytes{device="server:/x",fstype="nfs4",mountpoint="/mnt/nfs"} 1000
node_filesystem_size_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/tmp"} 2000
node_filesystem_free_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/tmp"} 1000
node_filesystem_avail_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/tmp"} 1000
node_filesystem_size_bytes{device="/dev/sdc1",device_error="permission denied",fstype="ext4",mountpoint="/data"} 0
node_filesystem_size_bytes{device="/dev/sdd1",fstype="xfs",mountpoint="/broken"} 5000
node_filesystem_device_error{device="/dev/sdd1",fstype="xfs",mountpoint="/broken"} 1
node_filesystem_free_bytes{device="/dev/sdd1",fstype="xfs",mountpoint="/broken"} 1000
node_filesystem_avail_bytes{device="/dev/sdd1",fstype="xfs",mountpoint="/broken"} 1000
node_filesystem_size_bytes{device="/dev/sde1",fstype="ext4",mountpoint="/weird"} NaN
node_filesystem_size_bytes{device="/dev/sdf1",fstype="ext4",mountpoint="/neg"} 100
node_filesystem_free_bytes{device="/dev/sdf1",fstype="ext4",mountpoint="/neg"} 500
node_filesystem_avail_bytes{device="/dev/sdf1",fstype="ext4",mountpoint="/neg"} -5
node_cpu_seconds_total{cpu="0",mode="idle"} 1.5
node_cpu_seconds_total{cpu="0",mode="user"} -3
node_cpu_seconds_total{cpu="1",mode="idle"} NaN
node_cpu_seconds_total{cpu="1",mode="user"} 1e300
node_memory_MemTotal_bytes 1000
node_memory_MemFree_bytes 100
node_memory_Buffers_bytes 100
node_memory_Cached_bytes 2000
node_load1 0.5
node_load5 NaN
node_load15 1
`
	m, err := Parse([]byte(in), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	r := nodeReport(m, testNow)
	var mounts []string
	for _, f := range r.FS {
		mounts = append(mounts, f.Mount)
		if f.Used > f.Total || f.Avail > f.Total {
			t.Errorf("FS ausserhalb: %+v", f)
		}
	}
	if strings.Join(mounts, ",") != "/,/srv,/neg" {
		t.Errorf("Mounts %v", mounts)
	}
	if r.CPU.Idle != 150 || r.CPU.User != 0 || r.CPU.Cores != 2 {
		t.Errorf("CPU %+v", r.CPU)
	}
	if r.Mem.Available != 1000 { // Fallback MemFree+Buffers+Cached, gedeckelt auf Total
		t.Errorf("Mem %+v", r.Mem)
	}
	if r.Load != nil {
		t.Errorf("Load mit NaN: %+v", r.Load)
	}
	if r.Systemd != nil || r.Reboot != nil || r.Updates != nil {
		t.Error("Abschnitte ohne Daten")
	}
}

func TestNodeSystemdFailed(t *testing.T) {
	m, _ := Parse([]byte(`node_systemd_unit_state{name="a.service",state="failed",type="simple"} 1
node_systemd_unit_state{name="a.service",state="active",type="simple"} 0
node_systemd_unit_state{name="b.service",state="failed",type="simple"} 0
node_systemd_unit_state{name="c.mount",state="failed",type=""} 1
node_systemd_system_running 0
node_reboot_required 0
`), Limits{})
	r := nodeReport(m, testNow)
	if r.Systemd == nil || strings.Join(r.Systemd.Failed, ",") != "a.service,c.mount" || r.Systemd.State != "degraded" {
		t.Errorf("Systemd %+v", r.Systemd)
	}
	if r.Reboot == nil || r.Reboot.Required {
		t.Errorf("Reboot %+v", r.Reboot)
	}
}

func TestTicksU64(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want uint64
	}{{1.234, 123}, {-1, 0}, {0, 0}, {1e16, 0}} {
		if got := ticks(tc.in); got != tc.want {
			t.Errorf("ticks(%v) = %d", tc.in, got)
		}
	}
	if u64(-1) != 0 || u64(2.6) != 3 || u64(1e30) == 0 {
		t.Error("u64")
	}
}

// PB3/PB4: mdraid mit NaN-Zaehlern bzw. im Wiederaufbau (md meldet dabei noch degraded).
func TestNodeRAIDEdge(t *testing.T) {
	m, err := Parse([]byte(`node_md_state{device="md0",state="active"} 0
node_md_state{device="md0",state="recovering"} 1
node_md_disks_required{device="md0"} 2
node_md_disks{device="md0",state="active"} 1
node_md_disks{device="md0",state="failed"} 0
node_md_disks{device="md0",state="spare"} 1
node_md_degraded{device="md0"} 1
node_md_blocks{device="md0"} 1000
node_md_blocks_synced{device="md0"} 250
node_md_state{device="md1",state="active"} 1
node_md_disks_required{device="md1"} 2
node_md_disks{device="md1",state="active"} 2
node_md_disks{device="md1",state="failed"} NaN
node_md_disks{device="md1",state="spare"} NaN
node_md_state{device="md2",state="active"} 1
node_md_disks_required{device="md2"} 2
node_md_disks{device="md2",state="active"} 1
node_md_degraded{device="md2"} 1
`), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	r := nodeReport(m, testNow)
	if len(r.RAID) != 3 {
		t.Fatalf("RAID %+v", r.RAID)
	}
	if md0 := r.RAID[0]; md0.State != "recovering" || md0.SyncPercent == nil || *md0.SyncPercent != 25 {
		t.Errorf("md0 (Wiederaufbau) %+v", md0)
	}
	if md1 := r.RAID[1]; md1.Failed != 0 || md1.Spare != 0 || md1.State != "active" {
		t.Errorf("md1 (NaN) %+v", md1)
	}
	if md2 := r.RAID[2]; md2.State != "active, degraded" || md2.SyncPercent != nil {
		t.Errorf("md2 (degraded) %+v", md2)
	}
}

// PB5: FreeBSD-node_exporter nennt die Interrupt-Zeit "interrupt"; PB2: ohne freien Speicher kein Abschnitt.
func TestNodeFreeBSDCPUAndMem(t *testing.T) {
	m, _ := Parse([]byte(`node_cpu_seconds_total{cpu="0",mode="user"} 10
node_cpu_seconds_total{cpu="0",mode="nice"} 0
node_cpu_seconds_total{cpu="0",mode="system"} 5
node_cpu_seconds_total{cpu="0",mode="interrupt"} 3
node_cpu_seconds_total{cpu="0",mode="idle"} 100
node_memory_MemTotal_bytes 1000
`), Limits{})
	r := nodeReport(m, testNow)
	if r.CPU == nil || r.CPU.IRQ != 300 || r.CPU.User != 1000 || r.CPU.Idle != 10000 {
		t.Errorf("CPU %+v", r.CPU)
	}
	if r.Mem != nil {
		t.Errorf("Mem ohne freien Speicher: %+v", r.Mem)
	}
}
