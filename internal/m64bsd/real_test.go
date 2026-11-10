package m64bsd

// Tests mit echten Ausgaben: Dateien testdata/*_freebsd145* sind am 2026-11-10 auf FreeBSD 14.5-RELEASE-p2 (amd64,
// offizielles VM-Abbild in QEMU: AHCI-Platte ada0, NVMe nda0, virtio vtbd0/vtbd1 als gmirror, em0/em1/vtnet0, lagg0
// ueber em1+vtnet0, vlan10, bridge0, epair0, tap0; pkg 2.8.4, smartmontools 7.5) mit genau den Aufrufen des Sammlers
// aufgezeichnet.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64linux"
	"github.com/ipv64net/node64/internal/m64proto"
)

func netByName(ifs []m64proto.NetIf) map[string]m64proto.NetIf {
	m := map[string]m64proto.NetIf{}
	for _, n := range ifs {
		m[n.Name] = n
	}
	return m
}

func TestRealNetLACP(t *testing.T) {
	counters, down, err := ParseNetstatJSON(readTestdata(t, "netstat_ibn_freebsd145.json"))
	if err != nil {
		t.Fatal(err)
	}
	ifs, bonds := BuildNet(counters, down, ParseIfconfig(readTestdata(t, "ifconfig_freebsd145_lacp.txt")))
	m := netByName(ifs)
	if len(ifs) != 9 || m["lo0"].Name != "" {
		t.Fatalf("Schnittstellen: %+v", ifs)
	}
	em0 := m["em0"]
	if em0.Kind != "physical" || !em0.Up || em0.SpeedMbit != 1000 || em0.Duplex != "full" || em0.MTU != 1500 ||
		em0.MAC != "52:54:00:64:00:01" || em0.RxBytes != 48202917 || em0.RxPackets != 37044 || em0.TxBytes == 0 {
		t.Fatalf("em0: %+v", em0)
	}
	// Mitglieder des lagg: eigene Adresse aus hwaddr (ether zeigt die des Verbunds)
	if v := m["vtnet0"]; v.Master != "lagg0" || v.MAC != "52:54:00:64:00:03" || v.SpeedMbit != 10000 || v.Kind != "physical" {
		t.Fatalf("vtnet0: %+v", v)
	}
	if v := m["em1"]; v.Master != "lagg0" || v.MAC != "52:54:00:64:00:02" {
		t.Fatalf("em1: %+v", v)
	}
	if v := m["lagg0"]; v.Kind != "bond" || !v.Up || v.MAC != "52:54:00:64:00:02" || v.TxErrors != 8 {
		t.Fatalf("lagg0: %+v", v)
	}
	for name, kind := range map[string]string{"vlan10": "vlan", "bridge0": "bridge", "epair0a": "virtual", "epair0b": "virtual", "tap0": "virtual"} {
		if m[name].Kind != kind {
			t.Errorf("%s: Art %q statt %q", name, m[name].Kind, kind)
		}
	}
	if m["vlan10"].Master != "bridge0" || !m["epair0a"].Up || m["epair0b"].Up || m["tap0"].Up {
		t.Fatalf("Zustand: vlan10 %+v epair0a %+v epair0b %+v tap0 %+v", m["vlan10"], m["epair0a"], m["epair0b"], m["tap0"])
	}
	// LACP ohne Gegenstelle: beide Mitglieder verteilen nicht (flags=0<>)
	if len(bonds) != 1 || bonds[0].Name != "lagg0" || bonds[0].Mode != "IEEE 802.3ad (lacp)" || len(bonds[0].Members) != 2 ||
		bonds[0].Members[0].MII != "down" || bonds[0].Members[1].MII != "down" {
		t.Fatalf("lagg0: %+v", bonds)
	}
}

func TestRealNetFailover(t *testing.T) {
	cfgs := ParseIfconfig(readTestdata(t, "ifconfig_freebsd145_failover.txt"))
	_, bonds := BuildNet(nil, nil, cfgs)
	if len(bonds) != 1 || bonds[0].Mode != "failover" || bonds[0].MII != "up" || len(bonds[0].Members) != 2 {
		t.Fatalf("%+v", bonds)
	}
	// em1 ist aktiv (MASTER,ACTIVE), vtnet0 steht bereit (flags=0<>, Link vorhanden): beide gelten als "up"
	for _, s := range bonds[0].Members {
		if s.MII != "up" || s.SpeedMbit == 0 {
			t.Errorf("Mitglied: %+v", s)
		}
	}
	for _, c := range cfgs {
		if c.Name == "lagg0" && (len(c.LaggPorts) != 2 || !hasWord(c.LaggPorts[0].Flags, "ACTIVE") || len(c.LaggPorts[1].Flags) != 0) {
			t.Fatalf("laggports: %+v", c.LaggPorts)
		}
	}
}

func TestRealIostatGeom(t *testing.T) {
	ds, err := ParseIostat(readTestdata(t, "iostat_xI_freebsd145.txt"))
	if err != nil {
		t.Fatal(err)
	}
	mergeGeom(ds, ParseGeomDisks(readTestdata(t, "geom_disk_list_freebsd145.txt")))
	var names []string
	by := map[string]m64proto.DiskIO{}
	for _, d := range ds {
		names = append(names, d.Name)
		by[d.Name] = d
	}
	// md0/md1 (Speicherplatten), cd0 und pass0..2 sind keine Platten
	if strings.Join(names, ",") != "vtbd0,vtbd1,nda0,ada0" {
		t.Fatalf("Platten: %v", names)
	}
	ada := by["ada0"]
	if ada.ReadOps != 1983 || ada.WriteOps != 4885 || ada.ReadBytes != 82227*1024 || ada.WriteBytes != 801419776 ||
		ada.IOTimeMs != 12100 || ada.Model != "QEMU HARDDISK" || ada.Serial != "M64BSDBOOT0001" || ada.Rotational != nil {
		t.Fatalf("ada0: %+v", ada)
	}
	if n := by["nda0"]; n.Model != "QEMU NVMe Ctrl" || n.Serial != "M64NVME0001" || n.Rotational == nil || *n.Rotational {
		t.Fatalf("nda0: %+v", n)
	}
	if v := by["vtbd0"]; v.Model != "" || v.Serial != "M64VTBD1" || v.IOTimeMs != 800 {
		t.Fatalf("vtbd0: %+v", v)
	}
}

func TestRealGmirror(t *testing.T) {
	for file, want := range map[string]m64proto.RAID{
		"gmirror_status_freebsd145_complete.txt":      {State: "active", Devices: 2, Active: 2},
		"gmirror_status_freebsd145_degraded.txt":      {State: "degraded", Devices: 1, Active: 1},
		"gmirror_status_freebsd145_synchronizing.txt": {State: "recovering", Devices: 2, Active: 1, SyncPercent: ptrF64(57)},
	} {
		got := ParseGeomStatus(geomMirror, readTestdata(t, file))
		if len(got) != 1 {
			t.Fatalf("%s: %+v", file, got)
		}
		g := got[0]
		if g.Name != "mirror/gm0" || g.Level != "gmirror" || g.State != want.State || g.Devices != want.Devices || g.Active != want.Active ||
			g.Failed != 0 || (g.SyncPercent == nil) != (want.SyncPercent == nil) || (g.SyncPercent != nil && *g.SyncPercent != *want.SyncPercent) {
			t.Errorf("%s: %+v", file, g)
		}
	}
}

func TestRealZpool(t *testing.T) {
	pools := m64linux.ParseZpoolList(readTestdata(t, "zpool_list_freebsd145.txt"))
	m64linux.MergeZpoolStatus(pools, m64linux.ParseZpoolStatus(readTestdata(t, "zpool_status_freebsd145.txt")))
	if len(pools) != 3 || pools[0].Name != "tank" || pools[1].Name != "tmir" || pools[2].Name != "zroot" {
		t.Fatalf("%+v", pools)
	}
	if p := pools[2]; p.Health != "ONLINE" || p.Size != 4831838208 || p.Alloc != 3786301440 || p.FragPct != 22 || p.Errors != "No known data errors" {
		t.Fatalf("zroot: %+v", p)
	}
	if p := pools[1]; p.Health != "DEGRADED" || !strings.Contains(p.Errors, "taken offline") {
		t.Fatalf("tmir: %+v", p)
	}
}

func TestRealPkg(t *testing.T) {
	if n := ParsePkgVersion(readTestdata(t, "pkg_version_freebsd145.txt")); n != 1 {
		t.Fatalf("pkg version: %d", n)
	}
	// pkg 2.8: "34 problem(s) in 1 package(s) found." (ohne "installed")
	if n, noDB, ok := ParsePkgAudit(readTestdata(t, "pkg_audit_freebsd145_vuln.txt"), nil, 1); !ok || noDB || n != 1 {
		t.Fatalf("audit: %d %v %v", n, noDB, ok)
	}
	if n, _, ok := ParsePkgAudit([]byte("7 problem(s) in 3 package(s) found.\n"), nil, 1); !ok || n != 3 {
		t.Fatalf("Summenzeile pkg 2: %d %v", n, ok)
	}
	if n, noDB, ok := ParsePkgAudit(readTestdata(t, "pkg_audit_freebsd145_clean.txt"), nil, 0); !ok || noDB || n != 0 {
		t.Fatalf("audit sauber: %d %v %v", n, noDB, ok)
	}
	// Meldung von pkg 2.8 ohne Pfad
	if _, noDB, ok := ParsePkgAudit(nil, []byte("pkg: vulnxml file vuln.xml does not exist. Try running 'pkg audit -F' first\n"), 1); ok || !noDB {
		t.Fatalf("ohne Datenbank: %v %v", noDB, ok)
	}
}

func TestRealVersionSwap(t *testing.T) {
	rb, ok := ParseFreeBSDVersion(readTestdata(t, "freebsd_version_freebsd145.txt"))
	if !ok || rb.Required {
		t.Fatalf("freebsd-version: %+v %v", rb, ok)
	}
	total, free, err := ParseSwapinfo(readTestdata(t, "swapinfo_freebsd145.txt"))
	if err != nil || total != 1<<30 || free != 1<<30 {
		t.Fatalf("swapinfo: %d %d %v", total, free, err)
	}
}

// Die Suche von smartctl nennt unter FreeBSD 14 auch cd0 und nda0 (NVMe ueber CAM, "INQUIRY failed"); gelesen werden
// nur ada0 und nvme0.
func TestRealSmart(t *testing.T) {
	devs, err := m64linux.ParseSmartScan(readTestdata(t, "smartctl_scan_freebsd145.json"))
	if err != nil || len(devs) != 4 {
		t.Fatalf("scan: %+v %v", devs, err)
	}
	devs = smartDisks(devs)
	if len(devs) != 2 || devs[0].Name != "/dev/ada0" || devs[0].Type != "atacam" || devs[1].Name != "/dev/nvme0" || devs[1].Type != "nvme" {
		t.Fatalf("Platten: %+v", devs)
	}
	for _, name := range []string{"/dev/da0", "/dev/ada12", "/dev/nvme1", "/dev/nvd0", "/dev/cdrom", "/dev/mfid0"} {
		if smartSkipRE.MatchString(name) {
			t.Errorf("%s uebersprungen", name)
		}
	}
	ex := &fakeExec{out: map[string]ExecResult{
		"smartctl --scan-open -j":                       {Stdout: readTestdata(t, "smartctl_scan_freebsd145.json")},
		"smartctl -j -a -n standby -d atacam /dev/ada0": {Stdout: readTestdata(t, "smartctl_ada0_freebsd145.json")},
		"smartctl -j -a -n standby -d nvme /dev/nvme0":  {Stdout: readTestdata(t, "smartctl_nvme0_freebsd145.json")},
	}}
	cache := NewCache()
	r := Collect(context.Background(), Options{Sections: []string{m64proto.SecSmart}, Exec: ex.exec,
		Has: func(n string) bool { return n == "smartctl" }, Sysctl: fakeSysctl{}.fn(), Cache: cache,
		Now: func() time.Time { return time.Unix(1794297000, 0) }})
	cache.Wait()
	if len(r.Errors) != 0 || len(r.SMART) != 2 {
		t.Fatalf("%+v", r)
	}
	if ex.called("smartctl -j -a -n standby -d atacam /dev/cd0") || ex.called("smartctl -j -a -n standby -d scsi /dev/nda0") {
		t.Fatalf("cd0/nda0 abgefragt: %v", ex.calls)
	}
	ada, nv := r.SMART[0], r.SMART[1]
	if ada.Device != "/dev/ada0" || ada.Model != "QEMU HARDDISK" || ada.Serial != "M64BSDBOOT0001" || ada.Error != "" ||
		ada.Passed == nil || !*ada.Passed || ada.TempC == nil || *ada.TempC != 31 || ada.CapacityBytes != 6477840384 {
		t.Fatalf("ada0: %+v", ada)
	}
	if nv.Device != "/dev/nvme0" || nv.Type != "nvme" || nv.Serial != "M64NVME0001" || nv.Passed == nil || !*nv.Passed ||
		nv.TempC == nil || *nv.TempC != 50 || nv.CriticalWarning == nil || *nv.CriticalWarning != 0 {
		t.Fatalf("nvme0: %+v", nv)
	}
}
