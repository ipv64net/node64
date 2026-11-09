package m64linux

import (
	"regexp"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// wholeDiskRE: ganze Platten (keine Partitionen, dm, loop, ram, zram, md, zd). sataN: Synology DSM 7.2.
var wholeDiskRE = regexp.MustCompile(`^(sd[a-z]+|hd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+|sata[0-9]+)$`)

// IsWholeDisk sagt, ob ein Blockgeraet eine ganze Platte ist.
func IsWholeDisk(name string) bool { return wholeDiskRE.MatchString(name) }

// ParseDiskstats liest /proc/diskstats (nur ganze Platten; Sektoren zu 512 Byte).
func ParseDiskstats(b []byte) []m64proto.DiskIO {
	var out []m64proto.DiskIO
	seen := map[string]bool{}
	for _, ln := range lines(b) {
		f := strings.Fields(ln)
		if len(f) < 14 || !IsWholeDisk(f[2]) || seen[f[2]] {
			continue
		}
		seen[f[2]] = true
		out = append(out, m64proto.DiskIO{
			Name:       f[2],
			ReadOps:    u64(f[3]),
			ReadBytes:  u64(f[5]) * 512,
			WriteOps:   u64(f[7]),
			WriteBytes: u64(f[9]) * 512,
			IOTimeMs:   u64(f[12]),
		})
		if len(out) >= maxItems {
			break
		}
	}
	return out
}

// diskSysInfo ergaenzt Modell, Seriennummer und rotational aus /sys/block/<name>.
func diskSysInfo(src source, d *m64proto.DiskIO) {
	base := "/sys/block/" + d.Name
	d.Model = clip(readStr(src, base+"/device/model"))
	if d.Model == "" && strings.HasPrefix(d.Name, "mmcblk") {
		d.Model = clip(readStr(src, base+"/device/name"))
	}
	d.Serial = clip(readStr(src, base+"/device/serial"))
	if d.Serial == "" {
		d.Serial = serialFromWWID(readStr(src, base+"/device/wwid"))
	}
	switch readStr(src, base+"/queue/rotational") {
	case "0":
		d.Rotational = ptrBool(false)
	case "1":
		d.Rotational = ptrBool(true)
	}
}

// serialFromWWID holt die Seriennummer aus einer T10-WWID ("t10.ATA     Modell     SERIAL").
func serialFromWWID(w string) string {
	if !strings.HasPrefix(w, "t10.") {
		return ""
	}
	f := strings.Fields(w)
	if len(f) < 2 {
		return ""
	}
	return clip(f[len(f)-1])
}

// readDisks liest Platten-I/O samt Modell.
func readDisks(src source) ([]m64proto.DiskIO, error) {
	b, err := src.ReadFile("/proc/diskstats")
	if err != nil {
		return nil, err
	}
	ds := ParseDiskstats(b)
	for i := range ds {
		diskSysInfo(src, &ds[i])
	}
	return ds, nil
}
