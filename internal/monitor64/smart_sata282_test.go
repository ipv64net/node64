package monitor64

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64linux"
	"github.com/ipv64net/node64/internal/m64proto"
)

// Issue #282: SATA-Platte per SSH (echte smartctl-Ausgabe einer WD Red Pro) landet am Dienst der Platte aus
// diskstats (gleiche Seriennummer aus /sys): ein Dienst je Platte mit I/O, SMART-Zustand, Temperatur und Satz.
func TestMapDisksSATAFromScript282(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "m64linux", "testdata", "smart_ata_wd161kfgx.json"))
	if err != nil {
		t.Fatal(err)
	}
	disks := []m64proto.DiskIO{{Name: "sda", Model: "WDC WD161KFGX-68", Serial: "2BJ9TESTX", ReadBytes: 1000, WriteBytes: 1000, IOTimeMs: 10}}
	out := "\n<<<m64:start>>>\n1\n<<<m64:smart:/dev/sda>>>\n" + string(b) + "\n<<<m64:end>>>\n"
	cur, err := m64linux.ParseScriptOutput([]byte(out), time.Unix(1795600000, 0))
	if err != nil {
		t.Fatal(err)
	}
	cur.Disks = disks
	prev := &m64proto.Report{Time: cur.Time - 60000, Disks: []m64proto.DiskIO{{Name: "sda", Serial: "2BJ9TESTX"}}}
	svcs := mapDisks(prev, cur, 60)
	if len(svcs) != 1 {
		t.Fatalf("ein Dienst je Platte erwartet: %v", keysOf(svcs))
	}
	s := svcs[0]
	if s.Key != "disk:2BJ9TESTX" || s.Smart == nil || len(s.Smart.Attrs) != 18 || s.Smart.Passed == nil || !*s.Smart.Passed {
		t.Fatalf("Dienst %+v", s)
	}
	got := map[string]float64{}
	for _, m := range s.Metrics {
		got[m.Name] = m.Value
	}
	for _, name := range []string{"read", "write", "busy", "temp", "realloc", "pending", "uncorr", "crc"} {
		if _, ok := got[name]; !ok {
			t.Errorf("Messwert %s fehlt: %v", name, got)
		}
	}
	if got["temp"] != 37 || !strings.Contains(s.Text, "SMART ok") || len(s.Facts) != 0 {
		t.Fatalf("Text %q, Werte %v, Facts %+v", s.Text, got, s.Facts)
	}
}
