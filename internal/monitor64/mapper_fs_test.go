package monitor64

import (
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/model/modeltest"
)

func fsMetric(s *Service, name string) (Metric, bool) {
	if s == nil {
		return Metric{}, false
	}
	for _, m := range s.Metrics {
		if m.Name == name {
			return m, true
		}
	}
	return Metric{}, false
}

func factText(s *Service, code string) string {
	if s == nil {
		return "<kein Dienst>"
	}
	for _, f := range s.Facts {
		if f.Code == code {
			return modeltest.DE(f.Text)
		}
	}
	return ""
}

// Inodes gehoeren zum Dateisystem: eigene Schwelle (fs.inodes), kein eigener Dienst; ohne Inode-Grenze (btrfs, FAT)
// gibt es den Wert nicht.
func TestMapFSInodes(t *testing.T) {
	out := MapReport(nil, &m64proto.Report{Time: 1, FS: []m64proto.FS{
		{Mount: "/", Type: "ext4", Total: 100 << 30, Used: 40 << 30, Avail: 60 << 30, InodesTotal: 1000, InodesFree: 80},
		{Mount: "/srv", Type: "xfs", Total: 100 << 30, Used: 40 << 30, Avail: 60 << 30, InodesTotal: 1000, InodesFree: 900},
		{Mount: "/data", Type: "btrfs", Total: 100 << 30, Used: 40 << 30, Avail: 60 << 30},
	}})
	root := svcBy(out, "fs:/")
	in, ok := fsMetric(root, "inodes")
	if !ok || in.Value != 92 || in.Rule != RuleFSInodes || in.Unit != "%" {
		t.Errorf("fs:/ inodes = %+v", in)
	}
	if u, _ := fsMetric(root, "used"); u.Rule != RuleFS {
		t.Errorf("fs:/ used = %+v", u)
	}
	if txt := modeltest.DE(root.Text); !strings.Contains(txt, "Inodes 92 %") {
		t.Errorf("fs:/ Text %q", txt)
	}
	srv := svcBy(out, "fs:/srv")
	if in, ok := fsMetric(srv, "inodes"); !ok || in.Value != 10 || strings.Contains(modeltest.DE(srv.Text), "Inodes") {
		t.Errorf("fs:/srv inodes = %+v, Text %q", in, srv.Text)
	}
	if _, ok := fsMetric(svcBy(out, "fs:/data"), "inodes"); ok {
		t.Error("btrfs ohne Inode-Grenze hat einen Inode-Wert")
	}
}

func TestMapBtrfsAndZFS(t *testing.T) {
	out := MapReport(nil, &m64proto.Report{Time: 1,
		Btrfs: []m64proto.Btrfs{
			{UUID: "3f1c8a2e-1111-2222-3333-444455556666", Label: "daten", Profile: "raid1", Devices: 2, Missing: 1, Errors: 13, MetaTotal: 2 << 30, MetaUsed: 1 << 30},
			{UUID: "9a8b7c6d-1111-2222-3333-444455556666", Profile: "single", Devices: 1},
		},
		ZFS: []m64proto.ZPool{{Name: "tank", Health: "ONLINE", Size: 100, Alloc: 50, Free: 50, FragPct: 37}},
	})
	b := svcBy(out, "btrfs:daten")
	if b.Kind != "btrfs" || factText(b, "raid_degraded") != "fehlende Geräte: 1" || factText(b, "device_warn") != "Gerätefehler: 13 (btrfs device stats)" {
		t.Errorf("btrfs:daten Facts %+v", b.Facts)
	}
	if txt := modeltest.DE(b.Text); txt != "raid1 · Geräte: 2 · Metadaten 50 % · fehlende Geräte: 1 · Gerätefehler: 13 (btrfs device stats)" {
		t.Errorf("btrfs:daten Text %q", txt)
	}
	ok := svcBy(out, "btrfs:9a8b7c6d") // ohne Label: Anfang der UUID
	if len(ok.Facts) != 0 || modeltest.DE(ok.Text) != "single · Geräte: 1" {
		t.Errorf("btrfs ohne Label: %+v %q", ok.Facts, ok.Text)
	}
	z := svcBy(out, "zfs:tank")
	if f, has := fsMetric(z, "frag"); !has || f.Value != 37 || !strings.Contains(modeltest.DE(z.Text), "Fragmentierung 37 %") {
		t.Errorf("zfs frag: %+v %q", z.Metrics, z.Text)
	}
}

// Raspberry Pi: Unterspannung jetzt ist kritisch, frueher eine Warnung; Drosselung jetzt eine Warnung.
func TestMapPower(t *testing.T) {
	for _, tc := range []struct {
		flags      uint32
		crit, warn string
		text       string
	}{
		{0, "", "", "in Ordnung"},
		{0x50005, "Unterspannung – Netzteil und Kabel prüfen", "gedrosselt", "Unterspannung – Netzteil und Kabel prüfen · gedrosselt"},
		{0x50000, "", "Unterspannung seit dem Start aufgetreten", "Unterspannung seit dem Start aufgetreten · seit dem Start gedrosselt gewesen"},
		{0x80008, "", "gedrosselt", "gedrosselt"},
		{0x20000, "", "", "seit dem Start gedrosselt gewesen"},
	} {
		out := MapReport(nil, &m64proto.Report{Time: 1, Power: &m64proto.Power{Flags: tc.flags}})
		s := svcBy(out, "power")
		if s.Kind != "power" || factText(s, "device_crit") != tc.crit || factText(s, "device_warn") != tc.warn || modeltest.DE(s.Text) != tc.text {
			t.Errorf("%#x: crit %q warn %q Text %q", tc.flags, factText(s, "device_crit"), factText(s, "device_warn"), modeltest.DE(s.Text))
		}
	}
	if out := MapReport(nil, &m64proto.Report{Time: 1}); len(out) != 0 {
		t.Errorf("ohne Pi: %+v", out)
	}
}
