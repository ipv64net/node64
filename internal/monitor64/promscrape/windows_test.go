package promscrape

import (
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/m64proto"
)

func TestWindowsReport032(t *testing.T) {
	m := loadFixture(t, "windows_exporter-0.32.txt")
	if k, v := detect(m); k != ExporterWindows || v != "0.32.1" {
		t.Fatalf("detect = %q %q", k, v)
	}
	io := winIO{}
	r := windowsReport(m, testNow, io)
	if r.Uptime != 100000 {
		t.Errorf("Uptime %v", r.Uptime)
	}
	// privileged enthaelt interrupt und dpc: nicht doppelt zaehlen
	if c := r.CPU; c == nil || c.Cores != 2 || c.User != 260075 || c.System != 160100 || c.Idle != 17300100 || c.IRQ != 0 || c.SoftIRQ != 0 {
		t.Errorf("CPU %+v", r.CPU)
	}
	if mm := r.Mem; mm == nil || mm.Total != 8589934592 || mm.Available != 4294967296 || mm.SwapTotal != 2e9 || mm.SwapFree != 1.5e9 {
		t.Errorf("Mem %+v", r.Mem)
	}
	if r.Load != nil {
		t.Error("Windows hat keine Load")
	}
	if len(r.FS) != 2 || r.FS[0].Mount != "C:" || r.FS[0].Type != "NTFS" || r.FS[0].Total != 127e9 || r.FS[0].Avail != 30e9 ||
		r.FS[0].Used != 97e9 || r.FS[1].Mount != "D:" {
		t.Errorf("FS %+v", r.FS)
	}
	if len(r.Disks) != 2 || r.Disks[0].Name != "PhysicalDrive0" || r.Disks[0].ReadBytes != 12e9 || r.Disks[0].IOTimeMs != (1794700000-86000)*1000 {
		t.Errorf("Disks %+v", r.Disks)
	}
	nets := map[string]m64proto.NetIf{}
	for _, n := range r.Net {
		nets[n.Name] = n
	}
	if n := nets["Intel[R] Ethernet Connection I219-V"]; !n.Up || n.SpeedMbit != 1000 || n.Kind != "physical" || n.RxErrors != 3 || n.MAC != "02:00:00:00:01:01" {
		t.Errorf("I219 %+v", n)
	}
	if n := nets["Intel[R] Wi-Fi 6 AX201 160MHz"]; n.Up || n.Kind != "physical" {
		t.Errorf("WLAN %+v", n)
	}
	if n := nets["Hyper-V Virtual Ethernet Adapter"]; n.Kind != "virtual" || !n.Up {
		t.Errorf("Hyper-V %+v", n)
	}
	svc := map[string]m64proto.WinService{}
	for _, s := range r.WinSvc {
		svc[s.Name] = s
	}
	if s := svc["Themes"]; s.State != "running" || s.StartType != "auto" || s.Display != "Themes" {
		t.Errorf("Themes %+v", s)
	}
	if s := svc["wuauserv"]; s.State != "stopped" || s.StartType != "manual" || s.Display != "Windows Update" {
		t.Errorf("wuauserv %+v", s)
	}
	if s := svc["Spooler"]; s.State != "stopped" || s.StartType != "auto" {
		t.Errorf("Spooler %+v", s)
	}
	// Busy-Zeit springt nie zurueck (Leerlauf waechst schneller als die Uhr)
	m2, _ := Parse([]byte(strings.ReplaceAll(fixtureText(t, "windows_exporter-0.32.txt"), `idle_seconds_total{disk="0 C:"} 86000`,
		`idle_seconds_total{disk="0 C:"} 86100`)), Limits{})
	r2 := windowsReport(m2, testNow, io)
	if r2.Disks[0].IOTimeMs != r.Disks[0].IOTimeMs {
		t.Errorf("Busy zurueck: %d -> %d", r.Disks[0].IOTimeMs, r2.Disks[0].IOTimeMs)
	}
}

func TestWindowsReportOld(t *testing.T) {
	m := loadFixture(t, "windows_exporter-0.25.txt")
	if k, _ := detect(m); k != ExporterWindows {
		t.Fatalf("detect %q", k)
	}
	r := windowsReport(m, testNow, winIO{})
	if r.CPU == nil || r.CPU.Cores != 1 || r.CPU.User != 70000 || r.CPU.System != 30000 {
		t.Errorf("CPU %+v", r.CPU)
	}
	if r.Mem == nil || r.Mem.Total != 4294967296 || r.Mem.Available != 1073741824 || r.Mem.SwapTotal != 1073741824 || r.Mem.SwapFree != 536870912 {
		t.Errorf("Mem %+v", r.Mem)
	}
	if r.Uptime != 100000 {
		t.Errorf("Uptime %v", r.Uptime)
	}
	if len(r.FS) != 1 || r.FS[0].Used != 48e9 {
		t.Errorf("FS %+v", r.FS)
	}
	if len(r.Net) != 1 || !r.Net[0].Up || r.Net[0].SpeedMbit != 10000 {
		t.Errorf("Net %+v", r.Net)
	}
	if len(r.WinSvc) != 1 || r.WinSvc[0].Name != "w32time" || r.WinSvc[0].Display != "Windows-Zeitgeber" || r.WinSvc[0].StartType != "auto" || r.WinSvc[0].State != "running" {
		t.Errorf("WinSvc %+v", r.WinSvc)
	}
}

func TestDetect(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"node_cpu_seconds_total{cpu=\"0\",mode=\"idle\"} 1\n", ExporterNode},
		{"windows_service_state{service=\"a\",state=\"running\"} 1\n", ExporterWindows},
		{"nginx_up 1\n", ExporterOther},
	} {
		m, _ := Parse([]byte(tc.in), Limits{})
		if k, _ := detect(m); k != tc.want {
			t.Errorf("%q -> %q", tc.in, k)
		}
	}
}
