package monitor64

import (
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/model/modeltest"
)

func TestMapWinSvc(t *testing.T) {
	if mapWinSvc(nil) != nil {
		t.Fatal("ohne Dienste kein Eintrag")
	}
	list := []m64proto.WinService{
		{Name: "Dhcp", Display: "DHCP-Client", State: "running", StartType: "auto"},
		{Name: "MSSQLSERVER", Display: "SQL Server (MSSQLSERVER)", State: "stopped", StartType: "auto"},
		{Name: "Spooler", Display: "Druckwarteschlange", State: "paused", StartType: "auto"},
		{Name: "W32Time", State: "start_pending", StartType: "auto"},                                               // Uebergang zaehlt nicht
		{Name: "GoogleUpdaterService157.0.8089.0", Display: "Google Updater", State: "stopped", StartType: "auto"}, // beendet sich selbst
		{Name: "", State: "stopped", StartType: "auto"},
	}
	out := mapWinSvc(list)
	if len(out) != 6 {
		t.Fatalf("%d Dienste: %+v", len(out), out)
	}
	sum := svcBy(out, "winsvc")
	if sum == nil || &out[0] != sum || !sum.Default || sum.Kind != "winsvc" || !hasFact(sum, "winsvc_stopped") {
		t.Fatalf("Zusammenfassung = %+v", sum)
	}
	if v, _ := metric(sum, "stopped"); v != 2 {
		t.Fatalf("gestoppt = %v", v)
	}
	if v, _ := metric(sum, "auto"); v != 5 {
		t.Fatalf("auto = %v", v)
	}
	// Texte sind uebersetzbar: geprueft wird, was ein Betrachter sieht
	if txt := modeltest.DE(sum.Text); txt != "2 von 5 automatischen Diensten gestoppt: SQL Server (MSSQLSERVER), Druckwarteschlange" ||
		modeltest.EN(sum.Text) != "2 of 5 automatic services stopped: SQL Server (MSSQLSERVER), Druckwarteschlange" ||
		!strings.Contains(sum.Facts[0].Text, "Druckwarteschlange") || modeltest.DE(sum.Name) != "Windows-Dienste" || modeltest.EN(sum.Name) != "Windows services" {
		t.Fatalf("Text = %q / %q / %q", sum.Text, sum.Facts[0].Text, sum.Name)
	}
	// einzelne Dienste: nur auf Wunsch uebernommen, gestoppt mit Fact (auch der Updater, wenn ausdruecklich uebernommen)
	sql := svcBy(out, "winsvc:MSSQLSERVER")
	if sql == nil || sql.Default || sql.Name != "SQL Server (MSSQLSERVER)" || !hasFact(sql, "winsvc_stopped") || sql.Text != "stopped" {
		t.Fatalf("MSSQLSERVER = %+v", sql)
	}
	if v, _ := metric(sql, "running"); v != 0 {
		t.Fatal("running")
	}
	if d := svcBy(out, "winsvc:Dhcp"); d == nil || hasFact(d, "winsvc_stopped") {
		t.Fatalf("Dhcp = %+v", d)
	}
	if w := svcBy(out, "winsvc:W32Time"); w == nil || hasFact(w, "winsvc_stopped") || w.Name != "W32Time" {
		t.Fatalf("W32Time = %+v", w)
	}
	if g := svcBy(out, "winsvc:GoogleUpdaterService157.0.8089.0"); g == nil || !hasFact(g, "winsvc_stopped") {
		t.Fatalf("Updater = %+v", g)
	}

	// alles laeuft: kein Fact
	ok := mapWinSvc([]m64proto.WinService{{Name: "Dhcp", State: "running", StartType: "auto"}})
	if hasFact(&ok[0], "winsvc_stopped") || modeltest.DE(ok[0].Text) != "1 automatische Dienste, keiner gestoppt" ||
		modeltest.EN(ok[0].Text) != "1 automatic services, none stopped" {
		t.Fatalf("%+v", ok[0])
	}
}

// Ein Windows-Bericht, wie ihn m64win liefert, ergibt sinnvolle Dienste (CPU aus Zaehlern, Laufwerke, Platten mit SMART).
func TestMapWindowsReport(t *testing.T) {
	prev := &m64proto.Report{Time: 1_000_000, CPU: &m64proto.CPU{Cores: 8, User: 1000, System: 1000, Idle: 8000},
		Disks: []m64proto.DiskIO{{Name: "PhysicalDrive0", Serial: "S1", Model: "Samsung SSD", ReadBytes: 0, IOTimeMs: 1_000_000}}}
	cur := &m64proto.Report{Time: 1_010_000, CPU: &m64proto.CPU{Cores: 8, User: 1100, System: 1100, Idle: 8800},
		FS:    []m64proto.FS{{Mount: "C:", Type: "NTFS", Total: 1000, Used: 600, Avail: 400}},
		Disks: []m64proto.DiskIO{{Name: "PhysicalDrive0", Serial: "S1", Model: "Samsung SSD", ReadBytes: 10_000, IOTimeMs: 1_005_000}},
		SMART: []m64proto.SMART{{Device: "PhysicalDrive0", Type: "nvme", Serial: "S1", Model: "Samsung SSD", Passed: bptr(true), TempC: f64(41)}},
	}
	out := MapReport(prev, cur)
	if v, ok := metric(svcBy(out, "cpu"), "util"); !ok || v != 20 {
		t.Fatalf("cpu util = %v %v", v, ok)
	}
	if fs := svcBy(out, "fs:C:"); fs == nil || modeltest.DE(fs.Name) != "Laufwerk C:" || modeltest.EN(fs.Name) != "Drive C:" {
		t.Fatalf("fs = %+v", fs)
	}
	d := svcBy(out, "disk:S1")
	if d == nil || !strings.Contains(d.Text, "SMART ok") {
		t.Fatalf("disk = %+v", d)
	}
	if v, _ := metric(d, "busy"); v != 50 {
		t.Fatalf("busy = %v", v)
	}
}

// KE2: windows_exporter liefert Vorlagen und Instanzen der Benutzerdienste sowie Trigger-Dienste ungefiltert – sie
// zaehlen nicht als gestoppt.
func TestMapWinSvcExporterNoise(t *testing.T) {
	list := []m64proto.WinService{
		{Name: "Dhcp", State: "running", StartType: "auto"},
		{Name: "CDPUserSvc", State: "stopped", StartType: "auto"},                     // Vorlage
		{Name: "CDPUserSvc_4f2a1", State: "running", StartType: "auto"},               // Instanz
		{Name: "OneSyncSvc_4F2A1", State: "stopped", StartType: "auto"},               // Instanz ohne Vorlage in der Liste
		{Name: "FooUserSvc", State: "stopped", StartType: "auto"},                     // unbekannte Vorlage mit Instanz
		{Name: "FooUserSvc_abcd12", State: "stopped", StartType: "auto"},              // ... und ihre Instanz
		{Name: "WpnUserService", State: "stopped", StartType: "auto"},                 // Vorlage ohne Instanz (niemand angemeldet)
		{Name: "DoSvc", State: "stopped", StartType: "auto"},                          // Trigger-Start
		{Name: "SgrmBroker", State: "stopped", StartType: "auto"},                     // Trigger-Start
		{Name: "Backup_cafe", Display: "Backup", State: "stopped", StartType: "auto"}, // kein Benutzerdienst
	}
	out := mapWinSvc(list)
	sum := svcBy(out, "winsvc")
	if v, _ := metric(sum, "stopped"); v != 1 || !strings.Contains(sum.Text, "Backup") {
		t.Fatalf("Zusammenfassung = %+v", sum)
	}
	if d := svcBy(out, "winsvc:FooUserSvc_abcd12"); d == nil || !hasFact(d, "winsvc_stopped") {
		t.Fatalf("einzeln uebernommen weiter ueberwacht: %+v", d)
	}
}
