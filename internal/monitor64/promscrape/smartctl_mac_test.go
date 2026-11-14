package promscrape_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/monitor64"
	"github.com/ipv64net/node64/internal/monitor64/promscrape"
)

// #135: smartctl_exporter ueber den Prometheus-Zugang. Testdaten: echte Ausgabe von smartctl_exporter 0.14.0, gefuettert
// mit aufgezeichneten smartctl-Ausgaben (NVMe, SATA-SSD, SAS, kaputte SSD, schlafende Platte). Es entstehen dieselben
// Platten-Dienste wie beim Agent – mit Zustand, Temperatur, Verschleiss, Sektoren und allen Werten fuer den SMART-Dialog.
func TestSmartctlExporter(t *testing.T) {
	srv := httptest.NewServer(&bodyServer{body: read(t, "smartctl_exporter-0.14.0.txt")})
	defer srv.Close()
	c, err := promscrape.New(promscrape.Config{URL: srv.URL, Map: monitor64.MapReport})
	if err != nil {
		t.Fatal(err)
	}
	res := c.Test(context.Background())
	if !res.OK || !strings.HasPrefix(res.Version, "smartctl_exporter 0.14.0") {
		t.Fatalf("Test: %+v", res)
	}
	svcs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	by := byKey(svcs)
	nv, ok := by["disk:S5GXNF0R123456A"]
	if !ok || nv.Kind != "disk" || nv.Name != "nvme0 (Samsung SSD 980 PRO 1TB)" || len(nv.Facts) != 0 {
		t.Fatalf("NVMe: %+v (Dienste %v)", nv, keys(by))
	}
	if m, _ := metric(nv, "temp"); m.Value != 42 || m.Rule != "disk.temp_nvme" {
		t.Errorf("NVMe-Temperatur: %+v", m)
	}
	if m, _ := metric(nv, "wear"); m.Value != 7 {
		t.Errorf("NVMe-Verschleiss: %+v", m)
	}
	if nv.Smart == nil || len(nv.Smart.Values) < 5 || nv.Smart.Firmware != "5B2QGXA7" {
		t.Errorf("NVMe SMART-Dialog: %+v", nv.Smart)
	}
	sa := by["disk:S6PTNM0T123456K"]
	if m, _ := metric(sa, "temp"); m.Value != 33 || sa.Smart == nil || len(sa.Smart.Attrs) < 10 {
		t.Fatalf("SATA: %+v", sa)
	}
	// SAS: neu zugewiesene Bloecke (grown defects) und nicht korrigierte Fehler wie beim Agent
	sas := by["disk:Z1Z0ABCD0000C1234567"]
	if m, _ := metric(sas, "realloc"); m.Value != 12 {
		t.Errorf("SAS realloc: %+v", sas.Metrics)
	}
	if m, _ := metric(sas, "uncorr"); m.Value != 3 {
		t.Errorf("SAS uncorr: %+v", sas.Metrics)
	}
	// kaputte SSD: smart_status fehlt, Exit-Status 24 ("DISK FAILING") -> SMART FAILED; alle Attribute im Dialog
	bad := by["disk:1530ABCDEF12"]
	failed := false
	for _, f := range bad.Facts {
		if f.Code == "smart_failed" {
			failed = true
		}
	}
	if !failed || !strings.Contains(bad.Text, "SMART FAILED") {
		t.Errorf("kaputte SSD: %+v", bad)
	}
	if m, _ := metric(bad, "wear"); m.Value != 91 {
		t.Errorf("Verschleiss aus Attribut 202: %+v", bad.Metrics)
	}
	var a202 bool
	for _, a := range bad.Smart.Attrs {
		if a.ID == 202 && *a.Value == 9 && *a.Worst == 9 && *a.Thresh == 1 && a.Raw == "91" && a.Failed == "" {
			a202 = true
		}
	}
	if !a202 {
		t.Errorf("Attribut 202 (Wert 9, Schwelle 1, Rohwert 91): %+v", bad.Smart.Attrs)
	}
	// schlafende Platte: der Exporter liefert sie nicht – kein Dienst, kein Fehler
	for k := range by {
		if strings.Contains(k, "sdb") {
			t.Errorf("schlafende Platte als Dienst: %s", k)
		}
	}
}

// #114: macOS mit node_exporter – RAM und Swap wie unter Linux (Belegung wie in der Aktivitaetsanzeige).
func TestNodeExporterDarwinMemory(t *testing.T) {
	srv := httptest.NewServer(&bodyServer{body: read(t, "node_exporter-darwin-nachgebaut.txt")})
	defer srv.Close()
	c, err := promscrape.New(promscrape.Config{URL: srv.URL, Map: monitor64.MapReport})
	if err != nil {
		t.Fatal(err)
	}
	svcs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	by := byKey(svcs)
	mem, ok := by["mem"]
	if !ok {
		t.Fatalf("kein RAM-Dienst: %v", keys(by))
	}
	// belegt: (7 GiB - 0,5 GiB) + 2 GiB + 1 GiB = 9,5 GiB von 16 GiB = 59,38 %
	if m, _ := metric(mem, "used"); m.Value != 59.38 || m.Rule != "mem.used" {
		t.Errorf("RAM: %+v", mem.Metrics)
	}
	sw, ok := by["swap"]
	if m, _ := metric(sw, "used"); !ok || m.Value != 25 {
		t.Errorf("Swap: %+v", sw)
	}
	if _, ok := by["load"]; !ok {
		t.Error("Load fehlt")
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
