package proxmox

import (
	"context"
	"testing"
	"time"
)

func pveHGuest(typ string, vmid int, cpu float64, mem, disk int64) Resource {
	return Resource{Type: typ, Node: "pve1", VMID: vmid, Name: "g", State: StateRunning, Status: "running", CPU: cpu,
		Mem: mem, MaxMem: 1000, Disk: disk, MaxDisk: 1000, NetIn: 100, NetOut: 50, DiskRead: 10, DiskWrite: 20}
}

func pveCount(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.r.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestHistoryRecordMerge(t *testing.T) {
	ctx := context.Background()
	s, _ := pveTestStore(t)
	sys := pveNewSystem(t, s)
	base := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return base.Add(time.Minute) }

	tpl := pveHGuest(TypeQEMU, 900, 0.5, 500, 0)
	tpl.Template = true
	stopped := pveHGuest(TypeLXC, 300, 0, 0, 0)
	stopped.State, stopped.Status = StateStopped, "stopped"
	node := Resource{Type: TypeNode, Node: "pve1", State: StateOnline, CPU: 0.1, Mem: 100, MaxMem: 1000, Disk: 300, MaxDisk: 1000}

	snap := &Snapshot{SystemID: sys.ID, Time: base.Add(5 * time.Second), OK: true, Resources: []Resource{
		pveHGuest(TypeQEMU, 100, 0.2, 400, 0), pveHGuest(TypeLXC, 200, 0.1, 100, 500), tpl, stopped, node}}
	if err := s.Record(ctx, snap); err != nil {
		t.Fatal(err)
	}
	snap.Time = base.Add(35 * time.Second)
	snap.Resources[0] = pveHGuest(TypeQEMU, 100, 0.6, 600, 0)
	if err := s.Record(ctx, snap); err != nil {
		t.Fatal(err)
	}
	// nicht erreichbar: nichts
	if err := s.Record(ctx, &Snapshot{SystemID: sys.ID, Time: base.Add(40 * time.Second), OK: false}); err != nil {
		t.Fatal(err)
	}
	if n := pveCount(t, s, "pve_hist_1m"); n != 3 {
		t.Fatalf("Zeilen 1m: %d (erwartet qemu/100, lxc/200, node)", n)
	}
	pts, err := s.Series(ctx, sys.ID, "qemu/100", base, base.Add(time.Hour))
	if err != nil || len(pts) != 1 {
		t.Fatalf("Series: %v %v", pts, err)
	}
	p := pts[0]
	if p.CPU != 40 || p.CPUMax != 60 || p.Mem != 50 || p.Disk != nil || p.NetIn != 100 || p.DiskWrite != 20 || !p.T.Equal(base) {
		t.Fatalf("zusammengefasst: %+v", p)
	}
	pts, _ = s.Series(ctx, sys.ID, "lxc/200", base, base.Add(time.Hour))
	if len(pts) != 1 || pts[0].Disk == nil || *pts[0].Disk != 50 {
		t.Fatalf("LXC Disk: %+v", pts)
	}
	// laufend gesehen (ExpectRunning automatisch), gestoppter und Node nicht
	ss, _ := s.Settings(ctx, sys.ID)
	if it := ss.Item("qemu/100"); it == nil || !it.SeenRunning {
		t.Fatalf("seen_running qemu/100: %+v", it)
	}
	if ss.Item("lxc/300") != nil || ss.Item("node/pve1") != nil || ss.Item("qemu/900") != nil {
		t.Fatalf("falsch gemerkt: %+v", ss.Items)
	}
	// Backup eines gestoppten Gasts (laeuft nur mit Lock) und die Abfrage direkt danach: Werte ja, „lief schon“ nein
	bk := pveHGuest(TypeQEMU, 103, 0.1, 100, 0)
	bk.State, bk.Lock = StateBackup, "backup"
	after := pveHGuest(TypeQEMU, 104, 0.1, 100, 0)
	after.AfterLock = true
	if err := s.Record(ctx, &Snapshot{SystemID: sys.ID, Time: base.Add(50 * time.Second), OK: true, Resources: []Resource{bk, after}}); err != nil {
		t.Fatal(err)
	}
	if pts, _ := s.Series(ctx, sys.ID, "qemu/103", base, base.Add(time.Hour)); len(pts) != 1 {
		t.Fatalf("Werte waehrend Backup: %+v", pts)
	}
	ss, _ = s.Settings(ctx, sys.ID)
	if ss.Item("qemu/103") != nil || ss.Item("qemu/104") != nil {
		t.Fatalf("Backup bzw. nach Lock als gelaufen gemerkt: %+v %+v", ss.Item("qemu/103"), ss.Item("qemu/104"))
	}
	// Einstellungen behalten seen_running
	if err := s.SaveSettings(ctx, &Settings{SystemID: sys.ID, Key: "qemu/100", Muted: true}); err != nil {
		t.Fatal(err)
	}
	ss, _ = s.Settings(ctx, sys.ID)
	if it := ss.Item("qemu/100"); !it.SeenRunning || !it.Muted {
		t.Fatalf("nach SaveSettings: %+v", it)
	}
}

func TestHistoryCompactPruneSeries(t *testing.T) {
	ctx := context.Background()
	s, _ := pveTestStore(t)
	sys := pveNewSystem(t, s)
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	rec := func(at time.Time, cpu float64) {
		t.Helper()
		snap := &Snapshot{SystemID: sys.ID, Time: at, OK: true, Resources: []Resource{pveHGuest(TypeLXC, 200, cpu, 500, 100)}}
		if err := s.Record(ctx, snap); err != nil {
			t.Fatal(err)
		}
	}
	// 2 h lang alle 30 s: erste Stunde CPU 10 %, zweite 30 %; Minute 0–4 zusaetzlich mit Spitze
	for i := 0; i < 240; i++ {
		at := base.Add(time.Duration(i) * 30 * time.Second)
		cpu := 0.1
		if i >= 120 {
			cpu = 0.3
		}
		if i == 3 {
			cpu = 0.9
		}
		rec(at, cpu)
	}
	rec(base.Add(2*time.Hour), 0.3) // schliesst die zweite Stunde ab
	if n := pveCount(t, s, "pve_hist_5m"); n != 24 {
		t.Fatalf("5-min-Werte: %d", n)
	}
	if n := pveCount(t, s, "pve_hist_1h"); n != 2 {
		t.Fatalf("Stundenwerte: %d", n)
	}
	var n, cpu, cpuMax int64
	s.r.QueryRow(`SELECT n, cpu, cpu_max FROM pve_hist_5m WHERE t = ?`, base.Unix()).Scan(&n, &cpu, &cpuMax)
	if n != 10 || cpu != 1800 || cpuMax != 9000 { // (9*10 % + 90 %)/10 = 18 %
		t.Fatalf("5 min: n=%d cpu=%d max=%d", n, cpu, cpuMax)
	}
	s.r.QueryRow(`SELECT n, cpu, cpu_max FROM pve_hist_1h WHERE t = ?`, base.Add(time.Hour).Unix()).Scan(&n, &cpu, &cpuMax)
	if n != 120 || cpu != 3000 || cpuMax != 3000 {
		t.Fatalf("1 h: n=%d cpu=%d max=%d", n, cpu, cpuMax)
	}

	// Aufloesung nach Alter des Beginns
	s.now = func() time.Time { return base.Add(3 * time.Hour) }
	if s.Resolution(base) != Step1m || s.Resolution(base.Add(-44*time.Hour)) != Step1m || s.Resolution(base.Add(-46*time.Hour)) != Step5m {
		t.Fatal("bis 48 h: 1 min")
	}
	if s.Resolution(base.Add(-3*24*time.Hour)) != Step5m || s.Resolution(base.Add(-40*24*time.Hour)) != Step1h {
		t.Fatal("5 min bzw. 1 h")
	}
	pts, _ := s.Series(ctx, sys.ID, "lxc/200", base, base.Add(3*time.Hour))
	if len(pts) != 121 {
		t.Fatalf("1-min-Punkte: %d", len(pts))
	}
	s.now = func() time.Time { return base.Add(10 * 24 * time.Hour) }
	pts, _ = s.Series(ctx, sys.ID, "lxc/200", base, base.Add(3*time.Hour))
	// 24 verdichtete Werte + das noch nicht verdichtete Ende (02:00) aus den 1-Minuten-Werten
	if len(pts) != 25 || pts[0].CPU != 18 || pts[0].CPUMax != 90 || !pts[24].T.Equal(base.Add(2*time.Hour)) || pts[24].CPU != 30 {
		t.Fatalf("5-min-Punkte: %d %+v", len(pts), pts)
	}
	s.now = func() time.Time { return base.Add(40 * 24 * time.Hour) }
	pts, _ = s.Series(ctx, sys.ID, "lxc/200", base, base.Add(3*time.Hour))
	if len(pts) != 3 || pts[1].CPU != 30 || !pts[2].T.Equal(base.Add(2*time.Hour)) {
		t.Fatalf("Stundenpunkte: %+v", pts)
	}

	// Aufraeumen: 51 h spaeter sind die 1-min-Werte weg, 5 min und 1 h bleiben
	rec(base.Add(51*time.Hour), 0.1)
	if n := pveCount(t, s, "pve_hist_1m"); n != 1 {
		t.Fatalf("1 min nach 51 h: %d", n)
	}
	if n := pveCount(t, s, "pve_hist_5m"); n < 24 {
		t.Fatalf("5 min nach 51 h: %d", n)
	}
	// kuerzere Aufbewahrung: 5 min 2 Tage, Stunden 3 Tage
	s.SetRetention(2, 3)
	rec(base.Add(4*24*time.Hour), 0.1)
	var old int
	s.r.QueryRow(`SELECT count(*) FROM pve_hist_5m WHERE t < ?`, base.Add(2*24*time.Hour).Unix()).Scan(&old)
	if old != 0 {
		t.Fatalf("alte 5-min-Werte: %d", old)
	}
	s.r.QueryRow(`SELECT count(*) FROM pve_hist_1h WHERE t < ?`, base.Add(24*time.Hour).Unix()).Scan(&old)
	if old != 0 {
		t.Fatalf("alte Stundenwerte: %d", old)
	}
	if n := pveCount(t, s, "pve_hist_1h"); n == 0 {
		t.Fatal("Stundenwerte innerhalb 3 Tagen fehlen")
	}
	// 0 = unbegrenzt
	s.SetRetention(30, 0)
	rec(base.Add(400*24*time.Hour), 0.1)
	if n := pveCount(t, s, "pve_hist_1h"); n == 0 {
		t.Fatal("Stundenwerte trotz unbegrenzt geloescht")
	}

	// Loeschen des Systems entfernt den Verlauf
	if err := s.DeleteSystem(ctx, sys.ID); err != nil {
		t.Fatal(err)
	}
	if pveCount(t, s, "pve_hist_1m")+pveCount(t, s, "pve_hist_5m")+pveCount(t, s, "pve_hist_1h") != 0 {
		t.Fatal("Verlauf nach Loeschen")
	}
}
