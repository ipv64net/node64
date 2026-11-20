package apis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// udFake: UNAS Pro (UniFi OS 6.0.18, Drive 4.4.31; Antworten aus testdata/unifi_drive, anonymisiert) - ohne Network
// Application, wie die echte Konsole.
func udFake(t *testing.T) *fakeUnifi {
	t.Helper()
	f := newFakeUnifi(true)
	f.noNetwork = true
	f.drive, f.driveFail = map[string]string{}, map[string]int{}
	for file, path := range map[string]string{"storage.json": "/storage", "device-info.json": "/systems/device-info", "network-io.json": "/systems/network-io"} {
		b, err := os.ReadFile(filepath.Join("testdata", "unifi_drive", file))
		if err != nil {
			t.Fatal(err)
		}
		f.drive[udPrefix+path] = string(b)
	}
	return f
}

// UNAS Pro mit API-Schluessel: der UniFi-Zugang erkennt Drive (ohne Network) und liefert Pool, Platten und System.
func TestUnifiDriveUNASPro(t *testing.T) {
	f := udFake(t)
	u, now := unifiFor(t, f, UnifiConfig{Secret: ufTestKey})
	*now = time.Date(2026, 11, 16, 16, 0, 0, 0, time.UTC)
	res := deRes(u.Test(context.Background()))
	if !res.OK || res.Version != "6.0.18" || res.Summary != "UniFi Drive: 1 Pool(s), 7 Platte(n)" {
		t.Fatalf("Test: %+v", res)
	}
	svcs, err := u.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", deErr(err))
	}
	pool := svcByKey(t, svcs, "raid:pool1")
	if m := mustMetric(t, pool, "used"); !near(m.Value, 30.54) || m.Max != 19960289034240 || len(pool.Facts) != 0 || de(pool.Name) != "Pool 1" ||
		de(pool.Text) != "RAID 5 · in Ordnung · 13,9 TB von 20,0 TB frei · 6 Platte(n)" {
		t.Errorf("Pool: %q %q %+v %+v", de(pool.Name), de(pool.Text), pool.Metrics, pool.Facts)
	}
	d1 := svcByKey(t, svcs, "disk:WD-WX0000000001")
	if de(d1.Name) != "Schacht 1 (WDC WD40EFPX-68C6CN0)" || mustMetric(t, d1, "temp").Value != 33 || mustMetric(t, d1, "power_on_hours").Value != 14213 ||
		mustMetric(t, d1, "realloc").Value != 0 || len(d1.Facts) != 0 || !strings.Contains(de(d1.Text), "im Pool 1 ·") {
		t.Errorf("Platte 1: %q %q %+v", de(d1.Name), de(d1.Text), d1.Facts)
	}
	if d7 := svcByKey(t, svcs, "disk:WD-WX0000000007"); !strings.Contains(de(d7.Text), "keinem Pool zugeordnet") {
		t.Errorf("Platte 7: %q", de(d7.Text))
	}
	sys := svcByKey(t, svcs, "drive")
	if de(sys.Name) != "UNAS Pro" || !strings.HasPrefix(de(sys.Text), "UniFi OS 6.0.18 · Drive 4.4.31 · läuft seit ") || mustMetric(t, sys, "out").Value <= 0 {
		t.Errorf("System: %q %q %+v", de(sys.Name), de(sys.Text), sys.Metrics)
	}
	if m := mustMetric(t, svcByKey(t, svcs, "cpu"), "util"); !near(m.Value, 2.6) {
		t.Errorf("CPU: %+v", m)
	}
	if m := mustMetric(t, svcByKey(t, svcs, "mem"), "used"); !near(m.Value, 20.92) {
		t.Errorf("RAM: %+v", m)
	}
	if m := mustMetric(t, svcByKey(t, svcs, "temp:cpu"), "temp"); m.Value != 60 {
		t.Errorf("CPU-Temperatur: %+v", m)
	}
	if e1, e2 := svcByKey(t, svcs, "if:enp0s1"), svcByKey(t, svcs, "if:enp0s2"); e1.Default || !hasFact(e1, "if_down") || !e2.Default || de(e2.Text) != "10 GbE" {
		t.Errorf("Ports: %+v / %+v", e1, e2)
	}
	if hasSvc(svcs, "system") || hasSvc(svcs, "updates") {
		t.Error("Dienste der Network Application ohne Network")
	}
}

// Gestoerter Pool und Platte: Redundanz fehlt, Platte mit Zustand und Risiko, Sektoren steigen.
func TestUnifiDriveDegraded(t *testing.T) {
	f := udFake(t)
	st := f.drive[udPrefix+"/storage"]
	st = strings.Replace(st, `"status": "fullyOperational"`, `"status": "degraded"`, 1)
	st = strings.Replace(st, `"currentProtection": 1`, `"currentProtection": 0`, 1)
	st = strings.Replace(st, `"state": "optimal"`, `"state": "failed"`, 1)
	st = strings.Replace(st, `"badSectorCount": 0`, `"badSectorCount": 3`, 1)
	f.drive[udPrefix+"/storage"] = st
	u, now := unifiFor(t, f, UnifiConfig{Secret: ufTestKey})
	svcs, err := u.Collect(context.Background())
	if err != nil {
		t.Fatal(deErr(err))
	}
	pool := svcByKey(t, svcs, "raid:pool1")
	if !hasFact(pool, "raid_degraded") || !strings.Contains(de(pool.Facts[0].Text), "Redundanz 0 statt 1") {
		t.Errorf("Pool: %+v", pool.Facts)
	}
	d1 := svcByKey(t, svcs, "disk:WD-WX0000000001")
	if !hasFact(d1, "disk_errors") || !hasFact(d1, "smart_sectors") || mustMetric(t, d1, "realloc").Value != 3 {
		t.Errorf("Platte 1: %+v", d1.Facts)
	}
	f.mu.Lock()
	f.drive[udPrefix+"/storage"] = strings.Replace(st, `"badSectorCount": 3`, `"badSectorCount": 5`, 1)
	f.mu.Unlock()
	*now = now.Add(time.Minute)
	svcs, _ = u.Collect(context.Background())
	if d1 := svcByKey(t, svcs, "disk:WD-WX0000000001"); !hasFact(d1, "smart_sectors_rising") {
		t.Errorf("steigende Sektoren: %+v", d1.Facts)
	}
}

// Systemwerte fehlen: Pool und Platten kommen, Teilfehler nur fuer die Systemdienste; ohne storage ein Fehler.
func TestUnifiDrivePartial(t *testing.T) {
	f := udFake(t)
	f.driveFail[udPrefix+"/systems/device-info"] = 500
	u, _ := unifiFor(t, f, UnifiConfig{Secret: ufTestKey})
	svcs, err := u.Collect(context.Background())
	pe := partialOf(t, err)
	if !pe.Affects("cpu") || !pe.Affects("drive") || pe.Affects("raid:pool1") || pe.Affects("disk:WD-WX0000000001") || !hasSvc(svcs, "raid:pool1") {
		t.Errorf("Teilfehler: %v", pe.Prefixes)
	}
	f.mu.Lock()
	f.driveFail[udPrefix+"/storage"] = 500
	f.mu.Unlock()
	if _, err := u.Collect(context.Background()); err == nil || IsPartial(err) {
		t.Errorf("ohne storage: %v", err)
	}
}

// Konsole mit Network und Drive: beide Teile; faellt Drive aus, bleibt Network (Teilfehler).
func TestUnifiNetworkAndDrive(t *testing.T) {
	f := udFake(t)
	f.noNetwork = false
	u, _ := unifiFor(t, f, UnifiConfig{Secret: ufTestKey})
	svcs, err := u.Collect(context.Background())
	if err != nil {
		t.Fatal(deErr(err))
	}
	if !hasSvc(svcs, "system") || !hasSvc(svcs, "raid:pool1") || !hasSvc(svcs, "drive") {
		t.Fatalf("beide Apps erwartet: %d Dienste", len(svcs))
	}
	if res := deRes(u.Test(context.Background())); !res.OK || !strings.Contains(res.Summary, "UniFi Drive: 1 Pool(s)") {
		t.Errorf("Test: %+v", res)
	}
	f.mu.Lock()
	f.driveFail[udPrefix+"/storage"] = 503
	f.mu.Unlock()
	svcs, err = u.Collect(context.Background())
	if pe := partialOf(t, err); !pe.Affects("raid:pool1") || pe.Affects("system") || !hasSvc(svcs, "system") {
		t.Errorf("Drive faellt aus: %v", pe.Prefixes)
	}
}

// Network-Konsole ohne Drive (UDM): wie bisher, Drive wird nur bei der Erkennung gefragt.
func TestUnifiNetworkWithoutDrive(t *testing.T) {
	f := newFakeUnifi(true)
	u, _ := unifiFor(t, f, UnifiConfig{Secret: ufTestKey})
	svcs, err := u.Collect(context.Background())
	if err != nil || hasSvc(svcs, "drive") || hasSvc(svcs, "raid:pool1") {
		t.Fatalf("UDM: %v %d", err, len(svcs))
	}
	if _, err := u.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Stuendliche Erkennung: scheitert Drive dabei nur kurz (503), bleibt Drive erkannt (Teilfehler statt fehlender
// Dienste); erst ein 404 heisst "nicht installiert".
func TestUnifiDetectKeepsAppOnError(t *testing.T) {
	f := udFake(t)
	f.noNetwork = false
	u, now := unifiFor(t, f, UnifiConfig{Secret: ufTestKey})
	if _, err := u.Collect(context.Background()); err != nil {
		t.Fatal(deErr(err))
	}
	redetect := func(status int) error {
		t.Helper()
		*now = now.Add(ufAppsEvery + time.Minute) // naechste stuendliche Erkennung
		f.mu.Lock()
		f.driveFail[udPrefix+"/storage"] = status
		f.mu.Unlock()
		_, err := u.Collect(context.Background())
		return err
	}
	err := redetect(503)
	if pe := partialOf(t, err); !pe.Affects("raid:pool1") || !u.apps.drive || !u.apps.at.Equal(*now) {
		t.Fatalf("Drive nach 503 nicht mehr erkannt: %v drive=%v", pe.Prefixes, u.apps.drive)
	}
	if err := redetect(404); err != nil || u.apps.drive {
		t.Fatalf("404: %v drive=%v", deErr(err), u.apps.drive)
	}
}
