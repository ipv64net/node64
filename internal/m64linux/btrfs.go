package m64linux

import (
	"sort"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

const btrfsMax = 32 // hoechstens so viele Dateisysteme je Bericht

// readBtrfs liest die eingehaengten btrfs-Dateisysteme aus /sys/fs/btrfs/<UUID> (ohne Befehle und ohne root):
// Geraete, fehlende Geraete (devinfo/<id>/missing), Fehlerzaehler der Geraete (devinfo/<id>/error_stats, ab Kernel
// 5.14 – wie "btrfs device stats") und die Belegung von Daten und Metadaten (allocation/...). Aeltere Kernel ohne
// devinfo liefern nur Geraete-Anzahl und Belegung.
func readBtrfs(src source) []m64proto.Btrfs {
	var out []m64proto.Btrfs
	for _, id := range src.ReadDir("/sys/fs/btrfs") {
		base := "/sys/fs/btrfs/" + id
		if !src.Exists(base+"/allocation/data/total_bytes") && !src.Exists(base+"/allocation/metadata/total_bytes") {
			continue // "features" und anderes
		}
		b := m64proto.Btrfs{UUID: clip(id), Label: clip(readStr(src, base+"/label")), Devices: len(src.ReadDir(base + "/devices"))}
		for _, dev := range src.ReadDir(base + "/devinfo") {
			d := base + "/devinfo/" + dev
			if readStr(src, d+"/missing") == "1" {
				b.Missing++
			}
			b.Errors += btrfsErrors(src, d+"/error_stats")
		}
		if n := len(src.ReadDir(base + "/devinfo")); n > b.Devices {
			b.Devices = n
		}
		b.DataTotal, b.DataUsed = btrfsU64(src, base+"/allocation/data/total_bytes"), btrfsU64(src, base+"/allocation/data/bytes_used")
		b.MetaTotal, b.MetaUsed = btrfsU64(src, base+"/allocation/metadata/total_bytes"), btrfsU64(src, base+"/allocation/metadata/bytes_used")
		// Profil der Daten: Unterordner von allocation/data (single, dup, raid1, raid10 ...)
		var prof []string
		for _, n := range src.ReadDir(base + "/allocation/data") {
			if src.Exists(base + "/allocation/data/" + n + "/total_bytes") {
				prof = append(prof, clip(n))
			}
		}
		sort.Strings(prof)
		b.Profile = strings.Join(prof, "+")
		out = append(out, b)
		if len(out) >= btrfsMax {
			break
		}
	}
	return out
}

func btrfsU64(src source, p string) uint64 {
	if v, ok := readInt(src, p); ok && v > 0 {
		return uint64(v)
	}
	return 0
}

// btrfsErrors summiert die Zaehler aus error_stats ("write_errs 0\nread_errs 0\n..."). Das Skript fuer SSH liefert
// die Zeilen einzeln als <datei>/<zaehler>.
func btrfsErrors(src source, p string) uint64 {
	var sum uint64
	if b, err := src.ReadFile(p); err == nil {
		for _, ln := range lines(b) {
			if f := strings.Fields(ln); len(f) == 2 {
				sum += u64(f[1])
			}
		}
		return sum
	}
	for _, n := range src.ReadDir(p) {
		sum += btrfsU64(src, p+"/"+n)
	}
	return sum
}
