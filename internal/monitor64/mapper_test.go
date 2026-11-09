package monitor64

import (
	"testing"

	"github.com/ipv64net/node64/internal/m64proto"
)

func u64(v uint64) *uint64   { return &v }
func f64(v float64) *float64 { return &v }
func bptr(v bool) *bool      { return &v }
func svcBy(l []Service, key string) *Service {
	for i := range l {
		if l[i].Key == key {
			return &l[i]
		}
	}
	return nil
}
func metric(s *Service, name string) (float64, bool) {
	for _, m := range s.Metrics {
		if m.Name == name {
			return m.Value, true
		}
	}
	return 0, false
}
func hasFact(s *Service, code string) bool {
	for _, f := range s.Facts {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestMapReportRates(t *testing.T) {
	prev := &m64proto.Report{Time: 1_000_000,
		CPU:   &m64proto.CPU{Cores: 4, User: 1000, System: 500, Idle: 8000, IOWait: 500},
		Net:   []m64proto.NetIf{{Name: "enp1s0", Kind: "physical", Up: true, SpeedMbit: 1000, RxBytes: 0, TxBytes: 0, RxPackets: 1000, TxPackets: 1000}},
		Disks: []m64proto.DiskIO{{Name: "sda", Serial: "WD-1", ReadBytes: 0, WriteBytes: 0}},
	}
	cur := &m64proto.Report{Time: 1_060_000, // 60 s spaeter
		CPU:   &m64proto.CPU{Cores: 4, User: 1300, System: 700, Idle: 8450, IOWait: 550},
		Load:  &m64proto.Load{L1: 1, L5: 2, L15: 3},
		Mem:   &m64proto.Mem{Total: 1000, Available: 250, SwapTotal: 100, SwapFree: 50},
		FS:    []m64proto.FS{{Mount: "/", Total: 100, Used: 90, Avail: 10}},
		Net:   []m64proto.NetIf{{Name: "enp1s0", Kind: "physical", Up: true, SpeedMbit: 1000, RxBytes: 750_000_000, TxBytes: 75_000_000, RxPackets: 101000, TxPackets: 101000, RxErrors: 20}, {Name: "veth1", Kind: "virtual", Up: true}},
		Disks: []m64proto.DiskIO{{Name: "sda", Serial: "WD-1", ReadBytes: 6_000_000, WriteBytes: 0}},
		SMART: []m64proto.SMART{{Device: "/dev/sda", Serial: "WD-1", Model: "WD Red", Passed: bptr(true), TempC: f64(36), Pending: u64(0)}},
	}
	out := MapReport(prev, cur)
	cpu := svcBy(out, "cpu")
	if v, ok := metric(cpu, "util"); !ok || v != 50 { // 1000 Jiffies, davon 500 idle+iowait
		t.Fatalf("cpu util = %v %v", v, ok)
	}
	if v, _ := metric(svcBy(out, "load"), "per_core"); v != 0.5 {
		t.Fatalf("load per core = %v", v)
	}
	if v, _ := metric(svcBy(out, "mem"), "used"); v != 75 {
		t.Fatalf("mem used = %v", v)
	}
	if v, _ := metric(svcBy(out, "swap"), "used"); v != 50 {
		t.Fatalf("swap used = %v", v)
	}
	if v, _ := metric(svcBy(out, "fs:/"), "used"); v != 90 {
		t.Fatalf("fs used = %v", v)
	}
	ifs := svcBy(out, "if:enp1s0")
	if v, _ := metric(ifs, "in"); v != 100 { // 750 MB in 60 s = 100 Mbit/s
		t.Fatalf("if in = %v", v)
	}
	if v, _ := metric(ifs, "util"); v != 10 {
		t.Fatalf("if util = %v", v)
	}
	if v, _ := metric(ifs, "errrate"); v != 0.01 { // 20 / 200000 Pakete
		t.Fatalf("if errrate = %v", v)
	}
	if svcBy(out, "if:veth1") != nil {
		t.Fatal("virtual interface must not be a service")
	}
	d := svcBy(out, "disk:WD-1")
	if d == nil {
		t.Fatal("disk by serial missing")
	}
	if v, _ := metric(d, "read"); v != 100_000 {
		t.Fatalf("disk read = %v", v)
	}
	if v, _ := metric(d, "temp"); v != 36 {
		t.Fatalf("disk temp = %v", v)
	}
}

func TestMapReportFirstAndCounterReset(t *testing.T) {
	cur := &m64proto.Report{Time: 2000, CPU: &m64proto.CPU{Cores: 2, User: 10, Idle: 10}}
	if _, ok := metric(svcBy(MapReport(nil, cur), "cpu"), "util"); ok {
		t.Fatal("first report must not yield a rate")
	}
	prev := &m64proto.Report{Time: 1000, CPU: &m64proto.CPU{Cores: 2, User: 1000, Idle: 1000}} // Neustart: Zaehler kleiner
	if _, ok := metric(svcBy(MapReport(prev, cur), "cpu"), "util"); ok {
		t.Fatal("counter reset must not yield a rate")
	}
}

func TestMapFacts(t *testing.T) {
	prev := &m64proto.Report{Time: 1, SMART: []m64proto.SMART{{Device: "/dev/sdb", Serial: "S2", Pending: u64(0)}}}
	cur := &m64proto.Report{Time: 2,
		SMART: []m64proto.SMART{{Device: "/dev/sdb", Serial: "S2", Passed: bptr(true), Pending: u64(8)}},
		Bonds: []m64proto.Bond{{Name: "bond0", Mode: "IEEE 802.3ad Dynamic link aggregation", AggregateID: 1,
			Members: []m64proto.BondSlave{{Name: "enp3s0", MII: "up", AggregateID: 1}, {Name: "enp4s0", MII: "down", AggregateID: 2}}}},
		RAID:    []m64proto.RAID{{Name: "md0", Level: "raid1", State: "clean, degraded", Devices: 2, Active: 1}},
		ZFS:     []m64proto.ZPool{{Name: "tank", Health: "DEGRADED", Size: 100, Alloc: 50, Free: 50}},
		Updates: &m64proto.Updates{Manager: "apt", Pending: 3, Security: 1},
		Reboot:  &m64proto.Reboot{Required: true},
		Local:   []m64proto.LocalCheck{{Name: "backup", State: -1, Metrics: []m64proto.Metric{{Name: "age", Value: 30, Warn: f64(24), Crit: f64(48)}}}},
	}
	out := MapReport(prev, cur)
	if !hasFact(svcBy(out, "disk:S2"), "smart_sectors_rising") {
		t.Fatal("rising sectors not detected")
	}
	b := svcBy(out, "bond:bond0")
	if !hasFact(b, "bond_member_down") || hasFact(b, "lacp_mismatch") { // enp4s0 ist down, zaehlt nicht als anderer Aggregator
		t.Fatalf("bond facts = %+v", b.Facts)
	}
	if !hasFact(svcBy(out, "raid:md0"), "raid_degraded") || !hasFact(svcBy(out, "zfs:tank"), "zfs_degraded") {
		t.Fatal("raid/zfs degraded not detected")
	}
	if !hasFact(svcBy(out, "updates"), "updates_security") || !hasFact(svcBy(out, "reboot"), "reboot_required") {
		t.Fatal("updates/reboot facts missing")
	}
	if !hasFact(svcBy(out, "local:backup"), "local_warn") {
		t.Fatal("local check P-state not evaluated")
	}
}

func TestTextHelpers(t *testing.T) {
	if bytesText(7_644_000_000_000) != "7,6 TB" || speedText(10000) != "10 Gbit/s" || speedText(2500) != "2,5 Gbit/s" || mbitText(312.4) != "312 Mbit/s" {
		t.Fatal(bytesText(7_644_000_000_000), speedText(2500), mbitText(312.4))
	}
}
