package m64bsd

import (
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// wholeDiskRE: ganze Platten unter FreeBSD (SATA ada, SCSI/USB/SAS da, NVMe nvd/nda, virtio vtbd, Xen xbd, SD
// mmcsd/sdda, RAID-Controller mfid/mrsas). Keine Partitionen, cd, pass, md, ses, zvol.
var wholeDiskRE = regexp.MustCompile(`^(ada|da|nvd|nda|vtbd|xbd|mmcsd|sdda|mfid|mfisyspd|aacd|amrd|ipsd|twed|idad|mlxd|pst|ad)[0-9]+$`)

// IsWholeDisk sagt, ob ein Geraetename eine ganze Platte ist.
func IsWholeDisk(name string) bool { return len(name) <= 32 && wholeDiskRE.MatchString(name) }

// iostatArgs: erweiterte Statistik (-x) als Summen (-I) seit dem Start, nur Platten (-d), ein Bericht (-c 1), alle
// Geraete (-n).
var iostatArgs = []string{"-x", "-I", "-d", "-c", "1", "-n", "1024"}

// ParseIostat liest "iostat -x -I -d -c 1": Kopf "device r/i w/i kr/i kw/i qlen tsvc_t/i sb/i", eine Zeile je
// Geraet mit Summen seit dem Start (Vorgaenge, KiB, Sekunden belegt). Die Spalten werden ueber den Kopf gesucht.
func ParseIostat(b []byte) ([]m64proto.DiskIO, error) {
	col := map[string]int{}
	var out []m64proto.DiskIO
	seen := map[string]bool{}
	for _, ln := range lines(b) {
		f := strings.Fields(ln)
		if len(f) == 0 {
			continue
		}
		if f[0] == "device" {
			col = map[string]int{}
			for i, h := range f {
				col[h] = i
			}
			continue
		}
		if len(col) == 0 || len(f) != len(col) || !IsWholeDisk(f[0]) || seen[f[0]] {
			continue
		}
		get := func(name string) (float64, bool) {
			i, ok := col[name]
			if !ok || i >= len(f) {
				return 0, false
			}
			v, err := strconv.ParseFloat(f[i], 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1e18 {
				return 0, false
			}
			return v, true
		}
		ro, ok1 := get("r/i")
		wo, ok2 := get("w/i")
		rk, ok3 := get("kr/i")
		wk, ok4 := get("kw/i")
		sb, ok5 := get("sb/i")
		if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
			continue
		}
		seen[f[0]] = true
		out = append(out, m64proto.DiskIO{Name: f[0], ReadOps: uint64(ro), WriteOps: uint64(wo),
			ReadBytes: uint64(rk * 1024), WriteBytes: uint64(wk * 1024), IOTimeMs: uint64(sb * 1000)})
		if len(out) >= maxItems {
			break
		}
	}
	if len(col) == 0 {
		return nil, errFormat
	}
	if _, ok := col["sb/i"]; !ok { // ohne -I (Raten statt Summen) taugen die Werte nicht
		return nil, errFormat
	}
	return out, nil
}

// GeomDisk sind die Angaben aus "geom disk list" zu einer Platte.
type GeomDisk struct {
	Model      string
	Serial     string
	Rotational *bool
}

// ParseGeomDisks liest "geom disk list" (Klasse DISK): descr = Modell, ident = Seriennummer (wie smartctl),
// rotationrate = 0 (SSD), Umdrehungen oder "unknown".
func ParseGeomDisks(b []byte) map[string]GeomDisk {
	out := map[string]GeomDisk{}
	var name string
	var cur GeomDisk
	flush := func() {
		if name != "" && IsWholeDisk(name) && len(out) < maxItems {
			out[name] = cur
		}
	}
	for _, ln := range lines(b) {
		k, v, ok := strings.Cut(strings.TrimSpace(ln), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Geom name":
			flush()
			name, cur = v, GeomDisk{}
		case "descr":
			cur.Model = clipN(v, 100)
		case "ident":
			if v != "(null)" {
				cur.Serial = clipN(v, 100)
			}
		case "rotationrate":
			switch n, err := strconv.Atoi(v); {
			case err != nil:
			case n == 0:
				cur.Rotational = ptrBool(false)
			case n > 0:
				cur.Rotational = ptrBool(true)
			}
		}
	}
	flush()
	return out
}

// mergeGeom traegt Modell, Seriennummer und rotational in die Platten-Zaehler ein.
func mergeGeom(ds []m64proto.DiskIO, g map[string]GeomDisk) {
	for i := range ds {
		if d, ok := g[ds[i].Name]; ok {
			ds[i].Model, ds[i].Serial, ds[i].Rotational = d.Model, d.Serial, d.Rotational
		}
	}
}
