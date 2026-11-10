package promscrape_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64"
	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/monitor64/model/modeltest"
	"github.com/ipv64net/node64/internal/monitor64/promscrape"
)

// Der Bericht aus node_exporter bzw. windows_exporter passt zum Mapper des Kerns (dieselben Dienste wie beim Agent).

type bodyServer struct {
	mu   sync.Mutex
	body string
}

func (b *bodyServer) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, _ = w.Write([]byte(b.body))
}

func (b *bodyServer) set(s string) {
	b.mu.Lock()
	b.body = s
	b.mu.Unlock()
}

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// byKey: Dienste nach Schluessel, mit deutschen Texten (Namen und Texte sind uebersetzbar).
func byKey(svcs []model.Service) map[string]model.Service {
	out := map[string]model.Service{}
	for _, s := range svcs {
		out[s.Key] = modeltest.Service("de", s)
	}
	return out
}

func metric(s model.Service, name string) (model.Metric, bool) {
	for _, m := range s.Metrics {
		if m.Name == name {
			return m, true
		}
	}
	return model.Metric{}, false
}

func hasFact(s model.Service, code string) bool {
	for _, f := range s.Facts {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestMapperNodeExporter(t *testing.T) {
	text := read(t, "node_exporter-1.12.1.txt")
	bs := &bodyServer{body: text}
	srv := httptest.NewServer(bs)
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
	for _, k := range []string{"cpu", "load", "mem", "swap", "fs:/", "disk:sda", "if:ens18", "systemd", "updates", "reboot"} {
		if _, ok := by[k]; !ok {
			t.Errorf("Dienst %s fehlt (%d Dienste)", k, len(svcs))
		}
	}
	for _, k := range []string{"if:lo", "if:docker0", "if:veth978671e", "fs:/run"} {
		if _, ok := by[k]; ok {
			t.Errorf("Dienst %s darf nicht da sein", k)
		}
	}
	if m, ok := metric(by["fs:/"], "used"); !ok || m.Rule != model.RuleFS || m.Value <= 0 {
		t.Errorf("fs:/ %+v", by["fs:/"])
	}
	if m, ok := metric(by["load"], "per_core"); !ok || m.Rule != model.RuleLoad {
		t.Errorf("load %+v", by["load"])
	}
	if !hasFact(by["reboot"], "reboot_required") || !hasFact(by["updates"], "updates_security") {
		t.Errorf("Facts: %+v %+v", by["reboot"], by["updates"])
	}
	if _, ok := metric(by["cpu"], "util"); ok {
		t.Error("CPU-Rate schon in der ersten Runde")
	}
	// zweite Runde: Zaehler steigen -> Raten
	next := strings.NewReplacer(
		`node_cpu_seconds_total{cpu="0",mode="idle"} 66497.93`, `node_cpu_seconds_total{cpu="0",mode="idle"} 66557.93`,
		`node_cpu_seconds_total{cpu="0",mode="user"} 602.93`, `node_cpu_seconds_total{cpu="0",mode="user"} 662.93`,
		`node_network_receive_bytes_total{device="ens18"} 8.688610395e+09`, `node_network_receive_bytes_total{device="ens18"} 8.788610395e+09`,
		`node_disk_read_bytes_total{device="sda"} 5.46809344e+09`, `node_disk_read_bytes_total{device="sda"} 5.56809344e+09`,
	).Replace(text)
	bs.set(next)
	time.Sleep(20 * time.Millisecond)
	svcs, err = c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	by = byKey(svcs)
	if m, ok := metric(by["cpu"], "util"); !ok || m.Rule != model.RuleCPU || m.Value <= 0 || m.Value > 100 {
		t.Errorf("CPU-Rate %+v", by["cpu"])
	}
	if m, ok := metric(by["if:ens18"], "in"); !ok || m.Value <= 0 {
		t.Errorf("Netz-Rate %+v", by["if:ens18"])
	}
	if m, ok := metric(by["disk:sda"], "read"); !ok || m.Value <= 0 {
		t.Errorf("Disk-Rate %+v", by["disk:sda"])
	}
}

func TestMapperNodeE2E(t *testing.T) {
	srv := httptest.NewServer(&bodyServer{body: read(t, "node_exporter-e2e-excerpt.txt")})
	defer srv.Close()
	c, _ := promscrape.New(promscrape.Config{URL: srv.URL, Map: monitor64.MapReport})
	svcs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	by := byKey(svcs)
	if !hasFact(by["raid:md6"], "raid_degraded") || hasFact(by["raid:md0"], "raid_degraded") || !hasFact(by["raid:md11"], "raid_degraded") {
		t.Errorf("RAID: %+v / %+v / %+v", by["raid:md6"], by["raid:md0"], by["raid:md11"])
	}
	if !hasFact(by["bond:int"], "bond_member_down") || hasFact(by["bond:dmz"], "bond_member_down") {
		t.Errorf("Bond: %+v / %+v", by["bond:int"], by["bond:dmz"])
	}
	if !hasFact(by["zfs:poolz1"], "zfs_degraded") || hasFact(by["zfs:pool1"], "zfs_degraded") {
		t.Errorf("ZFS: %+v / %+v", by["zfs:poolz1"], by["zfs:pool1"])
	}
	if s, ok := by["disk:2160A0D5FVGG"]; !ok || s.Name != "sda (TOSHIBA KSDB4U86)" {
		t.Errorf("Platte nach Seriennummer: %+v", s)
	}
	if m, ok := metric(by["temp:coretemp@platform_coretemp_0/Core 0"], "temp"); !ok || m.Rule != model.RuleTemp || m.Value != 54 {
		t.Errorf("Temperatur %+v", by["temp:coretemp@platform_coretemp_0/Core 0"])
	}
}

func TestMapperWindowsExporter(t *testing.T) {
	srv := httptest.NewServer(&bodyServer{body: read(t, "windows_exporter-0.32.txt")})
	defer srv.Close()
	c, _ := promscrape.New(promscrape.Config{URL: srv.URL, Map: monitor64.MapReport})
	svcs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	by := byKey(svcs)
	for _, k := range []string{"cpu", "mem", "swap", "fs:C:", "fs:D:", "disk:PhysicalDrive0", "if:Intel[R] Ethernet Connection I219-V",
		"winsvc:Themes", "winsvc:wuauserv", "winsvc:Spooler"} {
		if _, ok := by[k]; !ok {
			t.Errorf("Dienst %s fehlt", k)
		}
	}
	if _, ok := by["if:Hyper-V Virtual Ethernet Adapter"]; ok {
		t.Error("virtuelle Karte als Dienst")
	}
	if s := by["fs:C:"]; s.Name != "Laufwerk C:" {
		t.Errorf("Laufwerk %+v", s)
	}
	// Sammeldienst "Windows-Dienste" vorgeschlagen, einzelne Dienste nur auf Wunsch (mapWinSvc)
	if !by["winsvc"].Default || by["winsvc:Themes"].Default || by["winsvc:wuauserv"].Default {
		t.Error("Default der Windows-Dienste (Sammeldienst ja, einzelne nein)")
	}
	if by["if:Intel[R] Wi-Fi 6 AX201 160MHz"].Default {
		t.Error("Port ohne Link als Default")
	}
}

// Echter node_exporter (auf der Box: M64_PROM_LIVE_URL=http://127.0.0.1:19100/metrics), sonst uebersprungen.
func TestLiveNodeExporter(t *testing.T) {
	url := os.Getenv("M64_PROM_LIVE_URL")
	if url == "" {
		t.Skip("M64_PROM_LIVE_URL nicht gesetzt")
	}
	c, err := promscrape.New(promscrape.Config{URL: url, Map: monitor64.MapReport})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	res := c.Test(context.Background())
	if !res.OK {
		t.Fatalf("Test: %+v", res)
	}
	t.Logf("Test: %s / %s / Warnung %q", res.Version, res.Summary, res.Warning)
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	svcs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	by := byKey(svcs)
	for _, s := range svcs {
		t.Logf("%-22s %-28s default=%-5v %s %v", s.Key, s.Name, s.Default, s.Text, s.Metrics)
	}
	if m, ok := metric(by["cpu"], "util"); !ok || m.Value < 0 || m.Value > 100 {
		t.Errorf("CPU %+v", by["cpu"])
	}
	if _, ok := by["fs:/"]; !ok {
		t.Error("fs:/ fehlt")
	}
	if _, ok := by["mem"]; !ok {
		t.Error("mem fehlt")
	}
}

// Ein Exporter darf ueber keinen Label-Wert (Geraet, Einhaengepunkt, Sensor, Dienstname) ein eigenes Token
// einschleusen: an jeden Label-Wert wird ein Token gehaengt, danach darf kein Dienst es enthalten.
func TestNoInjection(t *testing.T) {
	const evil = "i18n:monitor64.state.crit"
	re := regexp.MustCompile(`(\w+)="([^"]*)"`)
	for _, name := range []string{"node_exporter-1.12.1.txt", "windows_exporter-0.32.txt"} {
		text := re.ReplaceAllStringFunc(read(t, name), func(m string) string {
			p := re.FindStringSubmatch(m)
			switch p[1] {
			case "mode", "le", "quantile", "state", "status", "start_mode": // steuern die Auswertung
				return m
			}
			return p[1] + `="` + p[2] + " " + evil + `"`
		})
		srv := httptest.NewServer(&bodyServer{body: text})
		c, err := promscrape.New(promscrape.Config{URL: srv.URL, Map: monitor64.MapReport,
			Metrics: []promscrape.CustomMetric{{Name: "node_filesystem_avail_bytes", Labels: map[string]string{}, Title: evil}}})
		if err != nil {
			t.Fatal(err)
		}
		var svcs []model.Service
		for i := 0; i < 2; i++ { // zweite Runde: Raten
			if svcs, err = c.Collect(context.Background()); err != nil && len(svcs) == 0 {
				t.Fatalf("%s: %v", name, err)
			}
		}
		res := c.Test(context.Background())
		srv.Close()
		if len(svcs) < 8 {
			t.Fatalf("%s: nur %d Dienste", name, len(svcs))
		}
		seen := false
		check := func(what, s string) {
			seen = seen || strings.Contains(s, "monitor64.state")
			for _, k := range model.Keys(s) {
				if k == "monitor64.state.crit" {
					t.Errorf("%s: %s enthaelt ein Token des Exporters: %q", name, what, s)
				}
			}
			if strings.Contains(modeltest.DE(s), "Kritisch") {
				t.Errorf("%s: %s uebersetzt den Text des Exporters: %q", name, what, modeltest.DE(s))
			}
		}
		for _, s := range svcs {
			check(s.Key+" Name", s.Name)
			check(s.Key+" Text", s.Text)
			for _, f := range s.Facts {
				check(s.Key+" Fact", f.Text)
			}
		}
		if err != nil {
			check("Fehler", err.Error())
		}
		check("Test", res.Error+" "+res.Warning+" "+res.Summary)
		if !seen {
			t.Errorf("%s: der Text des Exporters kommt in keinem Dienst an", name)
		}
	}
}
