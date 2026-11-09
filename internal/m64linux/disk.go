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

// diskSysInfo ergaenzt Modell, Seriennummer und rotational aus /sys/block/<name>. byID: Seriennummern aus
// /dev/disk/by-id (Name -> Seriennummer).
//
// Die Seriennummer soll dieselbe sein, die smartctl meldet (SMART.Serial ist der Schluessel des Platten-Dienstes):
// device/serial (NVMe, MMC), VPD-Seite 0x80 (SATA ueber libata, SAS, viele USB-Bruecken), T10-WWID (ATA), by-id
// (ata-/nvme-). Nur wenn das alles fehlt, gilt die WWID selbst (naa./eui.) als stabiler Schluessel.
func diskSysInfo(src source, d *m64proto.DiskIO, byID map[string]string) {
	base := "/sys/block/" + d.Name
	d.Model = clip(readStr(src, base+"/device/model"))
	if d.Model == "" && strings.HasPrefix(d.Name, "mmcblk") {
		d.Model = clip(readStr(src, base+"/device/name"))
	}
	d.Serial = clip(readStr(src, base+"/device/serial"))
	if d.Serial == "" {
		if b, err := src.ReadFile(base + "/device/vpd_pg80"); err == nil {
			d.Serial = ParseVPD80(b)
		}
	}
	wwid := readStr(src, base+"/device/wwid")
	if wwid == "" {
		wwid = readStr(src, base+"/wwid")
	}
	if d.Serial == "" {
		d.Serial = serialFromWWID(wwid)
	}
	if d.Serial == "" {
		d.Serial = byID[d.Name]
	}
	if d.Serial == "" {
		d.Serial = idFromWWID(wwid)
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

// wwnRE: WWID mit weltweit eindeutiger Kennung (SCSI/SAS naa., NVMe eui./nguid).
var wwnRE = regexp.MustCompile(`^(naa|eui)\.[0-9a-fA-F]{8,32}$`)

// idFromWWID liefert eine naa.- bzw. eui.-WWID als Ersatz-Schluessel (keine Seriennummer, aber stabil).
func idFromWWID(w string) string {
	if !wwnRE.MatchString(w) {
		return ""
	}
	return strings.ToLower(w)
}

// ParseVPD80 liest die VPD-Seite 0x80 (Unit Serial Number, binaer: 4 Byte Kopf, dann ASCII) aus
// /sys/block/<name>/device/vpd_pg80. "" bei fremdem Inhalt.
func ParseVPD80(b []byte) string {
	if len(b) < 5 || b[1] != 0x80 {
		return ""
	}
	n := int(b[2])<<8 | int(b[3])
	if n == 0 || 4+n > len(b) {
		return ""
	}
	s := strings.TrimSpace(strings.Trim(string(b[4:4+n]), string([]byte{0})))
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return ""
		}
	}
	if len(s) > 64 {
		return ""
	}
	return s
}

// byIDSerials liest /dev/disk/by-id: "ata-MODELL_SERIAL" bzw. "nvme-MODELL_SERIAL" -> Platte. Partitionen,
// WWN- und EUI-Namen zaehlen nicht; der erste Name je Platte gilt (sortiert: ohne Namespace-Endung "_1").
func byIDSerials(src source) map[string]string {
	out := map[string]string{}
	const dir = "/dev/disk/by-id"
	for _, n := range src.ReadDir(dir) {
		var rest string
		switch {
		case strings.HasPrefix(n, "ata-"):
			rest = n[len("ata-"):]
		case strings.HasPrefix(n, "nvme-") && !strings.HasPrefix(n, "nvme-eui.") && !strings.HasPrefix(n, "nvme-nvme."):
			rest = n[len("nvme-"):]
		default:
			continue
		}
		if i := strings.LastIndex(rest, "-part"); i >= 0 && isDigits(rest[i+len("-part"):]) {
			continue
		}
		i := strings.LastIndexByte(rest, '_')
		if i < 0 || i == len(rest)-1 {
			continue
		}
		disk := linkBase(src, dir+"/"+n)
		if !IsWholeDisk(disk) {
			continue
		}
		if _, ok := out[disk]; !ok {
			out[disk] = clip(rest[i+1:])
		}
	}
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// readDisks liest Platten-I/O samt Modell und Seriennummer.
func readDisks(src source) ([]m64proto.DiskIO, error) {
	b, err := src.ReadFile("/proc/diskstats")
	if err != nil {
		return nil, err
	}
	ds := ParseDiskstats(b)
	byID := byIDSerials(src)
	for i := range ds {
		diskSysInfo(src, &ds[i], byID)
	}
	return ds, nil
}

// nvmeCtrlRE: NVMe-Controller, wie smartctl ihn meldet (/dev/nvme0; die Platte heisst nvme0n1).
var nvmeCtrlRE = regexp.MustCompile(`^nvme[0-9]+$`)

// fillSmartSerials traegt Seriennummer (und Modell) aus /sys in SMART-Eintraege ohne eigene ein, vor allem bei
// schlafenden Platten (smartctl -n standby liefert dann nichts), damit der Dienst-Schluessel gleich bleibt.
func fillSmartSerials(sm []m64proto.SMART, disks []m64proto.DiskIO) {
	byName := map[string]*m64proto.DiskIO{}
	for i := range disks {
		byName[disks[i].Name] = &disks[i]
	}
	for i := range sm {
		name := strings.TrimPrefix(sm[i].Device, "/dev/")
		d := byName[name]
		if d == nil && nvmeCtrlRE.MatchString(name) {
			d = byName[name+"n1"]
		}
		if d == nil {
			continue
		}
		if sm[i].Serial == "" {
			sm[i].Serial = d.Serial
		}
		if sm[i].Model == "" {
			sm[i].Model = d.Model
		}
	}
}
