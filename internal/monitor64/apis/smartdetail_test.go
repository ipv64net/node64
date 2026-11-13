package apis

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

func smartFixture(t *testing.T, name string) smartResp {
	t.Helper()
	var r smartResp
	if err := json.Unmarshal([]byte(fixture(t, name)), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func smartValueOf(d *model.SmartDetail, name string) (string, bool) {
	for _, v := range d.Values {
		if v.Name == name {
			return v.Text, true
		}
	}
	return "", false
}

// Proxmox VE und PBS: alle Werte aus disks/smart zum Nachschlagen – ATA als Tabelle, NVMe als benannte Werte
// (Proxmox VE: Text von smartctl, PBS: Attribute mit Namen).
func TestSmartDetailOf(t *testing.T) {
	at := time.Unix(1700000000, 0)
	ok := true
	d := smartDetailOf(smartFixture(t, "pve/smart_sda.json"), diskEntry{DevPath: "/dev/sda", Type: "hdd", Model: " WDC WD40EFRX ", Serial: "WD-1", Size: 4e12}, &ok, at)
	if d == nil || d.Type != "ata" || d.Model != "WDC WD40EFRX" || d.Serial != "WD-1" || d.Size != 4e12 || d.Passed == nil || !*d.Passed || !d.At.Equal(at) ||
		len(d.Attrs) < 4 || len(d.Values) != 0 {
		t.Fatalf("PVE ATA: %+v", d)
	}
	if a := d.Attrs[0]; a.ID != 1 || a.Name != "Raw_Read_Error_Rate" || a.Value == nil || *a.Value != 200 || *a.Worst != 200 || *a.Thresh != 51 || a.Raw != "0" || a.Failed != "" {
		t.Fatalf("PVE Attribut 1: %+v", a)
	}

	n := smartDetailOf(smartFixture(t, "pve/smart_nvme.json"), diskEntry{DevPath: "/dev/nvme0n1", Type: "nvme", Serial: "unknown"}, nil, at)
	if n == nil || n.Type != "nvme" || n.Serial != "" || n.Passed != nil || len(n.Attrs) != 0 {
		t.Fatalf("PVE NVMe: %+v", n)
	}
	for name, want := range map[string]string{"Critical Warning": "0x00", "Temperature": "41 Celsius", "Available Spare": "100%", "Power On Hours": "12,345"} {
		if got, ok := smartValueOf(n, name); !ok || got != want {
			t.Errorf("PVE NVMe %q = %q (vorhanden %v), erwartet %q", name, got, ok, want)
		}
	}

	p := smartDetailOf(smartFixture(t, "pbs/smart_sda.json"), diskEntry{Name: "sda", DiskType: "hdd"}, &ok, at)
	if p == nil || p.Type != "ata" || len(p.Attrs) < 4 {
		t.Fatalf("PBS ATA: %+v", p)
	}
	if a := p.Attrs[0]; a.ID != 5 || *a.Value != 100 || *a.Thresh != 10 || a.Raw != "0" {
		t.Fatalf("PBS Attribut 5: %+v", a)
	}
	pn := smartDetailOf(smartFixture(t, "pbs/smart_nvme.json"), diskEntry{Name: "nvme0n1", DiskType: "nvme"}, &ok, at)
	if got, has := smartValueOf(pn, "Percentage Used"); pn == nil || pn.Type != "nvme" || !has || got != "6%" {
		t.Fatalf("PBS NVMe: %+v", pn)
	}

	// Attribut unter der Schwelle, ueberlange Texte, Antwort ohne Werte
	f := smartDetailOf(smartResp{Attributes: []smartAttr{
		{ID: []byte(`"  5"`), Name: "Reallocated_Sector_Ct", Value: []byte(`"001"`), Worst: []byte(`"001"`), Threshold: []byte(`"010"`), Raw: []byte(`"4000"`), Fail: "FAILING_NOW"},
		{ID: []byte(`9`), Name: "Power_On_Hours", Raw: []byte(`"1"`), Fail: "In_the_past"},
	}}, diskEntry{Name: "sdb"}, nil, at)
	if f.Attrs[0].Failed != "now" || *f.Attrs[0].Value != 1 || f.Attrs[1].Failed != "past" || f.Attrs[1].Value != nil {
		t.Fatalf("Zustand der Attribute: %+v", f.Attrs)
	}
	if smartDetailOf(smartResp{Health: "PASSED"}, diskEntry{Name: "sdc"}, &ok, at) != nil {
		t.Error("Satz ohne Werte")
	}
}

// Der Platten-Dienst von Proxmox VE traegt den Satz (und behaelt ihn zwischen den SMART-Abfragen).
func TestPVEDiskCarriesSmartDetail(t *testing.T) {
	f, cfg := pveFake(t)
	cfg.Node = "pve1"
	p, err := NewPVE(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 2; round++ {
		svcs, _ := p.Collect(t.Context())
		n := 0
		for _, s := range svcs {
			if s.Kind == "disk" && s.Smart != nil {
				n++
				if len(s.Smart.Attrs) == 0 && len(s.Smart.Values) == 0 {
					t.Errorf("Runde %d: %s ohne Werte", round, s.Key)
				}
			}
		}
		if n < 2 {
			t.Fatalf("Runde %d: %d Platten mit Satz", round, n)
		}
	}
	_ = f
}
