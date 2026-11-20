// Package procstat liest Kennzahlen des eigenen Prozesses (CPU-Zeit, Arbeitsspeicher, offene Dateien) und den
// Speicherplatz eines Verzeichnisses - fuer /api/metrics. Nur unter Linux; anderswo melden die Funktionen "nicht da".
package procstat

import (
	"strconv"
	"strings"
)

// Stat sind die Kennzahlen des eigenen Prozesses.
type Stat struct {
	CPUSeconds float64 // verbrauchte CPU-Zeit (Anwendung + Kernel)
	RSS        uint64  // belegter Arbeitsspeicher in Bytes
	VSize      uint64  // virtueller Speicher in Bytes
	Threads    int
	OpenFDs    int    // offene Dateien und Verbindungen
	MaxFDs     uint64 // Grenze fuer offene Dateien (0 = unbekannt)
}

// Disk ist der Speicherplatz eines Dateisystems in Bytes.
type Disk struct {
	Size uint64
	Free uint64 // fuer den Prozess nutzbar
}

// userHZ: Takt, in dem der Kernel CPU-Zeiten in /proc angibt (unter Linux fest 100).
const userHZ = 100

// parseStat wertet den Inhalt von /proc/self/stat aus. Der Prozessname steht in Klammern und darf Leerzeichen
// und Klammern enthalten, deshalb zaehlen die Felder ab der letzten schliessenden Klammer.
func parseStat(line string, pageSize int) (Stat, bool) {
	i := strings.LastIndexByte(line, ')')
	if i < 0 {
		return Stat{}, false
	}
	f := strings.Fields(line[i+1:])
	// f[0] ist Feld 3 (state): utime 14, stime 15, num_threads 20, vsize 23, rss 24
	if len(f) < 22 {
		return Stat{}, false
	}
	utime, err1 := strconv.ParseUint(f[11], 10, 64)
	stime, err2 := strconv.ParseUint(f[12], 10, 64)
	threads, err3 := strconv.Atoi(f[17])
	vsize, err4 := strconv.ParseUint(f[20], 10, 64)
	rss, err5 := strconv.ParseUint(f[21], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
		return Stat{}, false
	}
	return Stat{CPUSeconds: float64(utime+stime) / userHZ, RSS: rss * uint64(pageSize), VSize: vsize, Threads: threads}, true
}

// parseLimit wertet eine cgroup-Speichergrenze aus ("max" bzw. sehr grosse Werte = keine Grenze).
func parseLimit(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "max" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v == 0 || v >= 1<<60 {
		return 0, false
	}
	return v, true
}

// cgroupV2Path: Pfad der eigenen cgroup v2 aus /proc/self/cgroup (Zeile "0::/pfad"); "" ohne bzw. bei einem Pfad
// ausserhalb des eigenen Namensraums ("/../..").
func cgroupV2Path(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), "0::"); ok && strings.HasPrefix(p, "/") && !strings.Contains(p, "..") {
			return p
		}
	}
	return ""
}
