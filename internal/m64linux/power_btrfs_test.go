package m64linux

import (
	"testing"

	"github.com/ipv64net/node64/internal/m64proto"
)

func files(kv ...string) map[string][]byte {
	m := map[string][]byte{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = []byte(kv[i+1])
	}
	return m
}

// Raspberry Pi: Stand der Firmware (get_throttled) bzw. Unterspannungs-Alarm des hwmon-Geraets rpi_volt.
func TestReadPower(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string][]byte
		want  *uint32
	}{
		{"kein Pi", files("/sys/class/hwmon/hwmon0/name", "coretemp"), nil},
		{"alles gut", files(piThrottled, "0\n"), u32(0)},
		{"Unterspannung jetzt und seit Start", files(piThrottled, "50005\n"), u32(0x50005)},
		{"mit 0x", files(piThrottled, "0x50000"), u32(0x50000)},
		{"unlesbar, hwmon ohne Alarm", files(piThrottled, "xyz", "/sys/class/hwmon/hwmon1/name", "rpi_volt", "/sys/class/hwmon/hwmon1/in0_lcrit_alarm", "0"), u32(0)},
		{"nur hwmon mit Alarm", files("/sys/class/hwmon/hwmon0/name", "cpu_thermal", "/sys/class/hwmon/hwmon1/name", "rpi_volt", "/sys/class/hwmon/hwmon1/in0_lcrit_alarm", "1\n"), u32(m64proto.PowerUnderVolt)},
		{"hwmon ohne Alarm-Datei", files("/sys/class/hwmon/hwmon1/name", "rpi_volt"), nil},
	} {
		got := readPower(newMapSource(tc.files))
		switch {
		case tc.want == nil && got != nil:
			t.Errorf("%s: %+v, erwartet nil", tc.name, got)
		case tc.want != nil && (got == nil || got.Flags != *tc.want):
			t.Errorf("%s: %+v, erwartet %#x", tc.name, got, *tc.want)
		}
	}
}

func u32(v uint32) *uint32 { return &v }

// btrfs aus /sys/fs/btrfs: wie der Agent die Dateien sieht (error_stats mehrzeilig) und wie das Skript sie liefert
// (je Zaehler eine Zeile).
func TestReadBtrfs(t *testing.T) {
	const b = "/sys/fs/btrfs/3f1c8a2e-1111-2222-3333-444455556666"
	base := []string{
		"/sys/fs/btrfs/features/raid56", "0",
		b + "/label", "daten\n",
		b + "/devices/sda", "1", b + "/devices/sdb", "1",
		b + "/devinfo/1/missing", "0", b + "/devinfo/2/missing", "1",
		b + "/allocation/data/total_bytes", "107374182400", b + "/allocation/data/bytes_used", "53687091200",
		b + "/allocation/data/raid1/total_bytes", "107374182400",
		b + "/allocation/metadata/total_bytes", "2147483648", b + "/allocation/metadata/bytes_used", "1610612736",
	}
	agent := append(append([]string{}, base...),
		b+"/devinfo/1/error_stats", "write_errs 0\nread_errs 3\nflush_errs 0\ncorruption_errs 9\ngeneration_errs 0\n",
		b+"/devinfo/2/error_stats", "write_errs 1\nread_errs 0\nflush_errs 0\ncorruption_errs 0\ngeneration_errs 0\n")
	script := append(append([]string{}, base...),
		b+"/devinfo/1/error_stats/read_errs", "3", b+"/devinfo/1/error_stats/corruption_errs", "9", b+"/devinfo/1/error_stats/write_errs", "0",
		b+"/devinfo/2/error_stats/write_errs", "1")
	for name, f := range map[string][]string{"Agent": agent, "Skript": script} {
		got := readBtrfs(newMapSource(files(f...)))
		if len(got) != 1 {
			t.Fatalf("%s: %d Dateisysteme", name, len(got))
		}
		g := got[0]
		if g.Label != "daten" || g.Devices != 2 || g.Missing != 1 || g.Errors != 13 || g.Profile != "raid1" ||
			g.DataTotal != 107374182400 || g.DataUsed != 53687091200 || g.MetaTotal != 2147483648 || g.MetaUsed != 1610612736 {
			t.Errorf("%s: %+v", name, g)
		}
	}
	// aelterer Kernel ohne devinfo: Geraete aus devices, keine Fehlerzaehler
	old := readBtrfs(newMapSource(files(b+"/devices/sda", "1", b+"/allocation/metadata/total_bytes", "1024", b+"/allocation/metadata/bytes_used", "512")))
	if len(old) != 1 || old[0].Devices != 1 || old[0].Missing != 0 || old[0].Errors != 0 || old[0].Label != "" {
		t.Errorf("ohne devinfo: %+v", old)
	}
	if got := readBtrfs(newMapSource(files("/sys/fs/btrfs/features/raid56", "0"))); len(got) != 0 {
		t.Errorf("ohne Dateisystem: %+v", got)
	}
}
