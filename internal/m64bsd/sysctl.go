package m64bsd

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
)

// SysctlFunc liest einen sysctl-Wert roh (wie unix.SysctlRaw: args werden an die MIB angehaengt, z. B.
// "vm.swap_info", 0). Zahlen stehen in der Byte-Reihenfolge des Hosts.
type SysctlFunc func(name string, args ...int) ([]byte, error)

// longSize ist sizeof(long) des Hosts (FreeBSD: ILP32 bzw. LP64, also die Zeigergroesse wie Go-int).
var longSize = strconv.IntSize / 8

// CPUSTATES von FreeBSD (sys/resource.h): CP_USER, CP_NICE, CP_SYS, CP_INTR, CP_IDLE.
const cpuStates = 5

// decodeUint liest eine vorzeichenlose Zahl aus 4 bzw. 8 Bytes (u_int, u_long, uint64_t).
func decodeUint(b []byte) (uint64, bool) {
	switch len(b) {
	case 4:
		return uint64(binary.NativeEndian.Uint32(b)), true
	case 8:
		return binary.NativeEndian.Uint64(b), true
	}
	return 0, false
}

// decodeLong liest ein long an Stelle off (Breite ls).
func decodeLong(b []byte, off, ls int) (uint64, bool) {
	if off < 0 || off+ls > len(b) {
		return 0, false
	}
	return decodeUint(b[off : off+ls])
}

// sysU64 liest eine Zahl (4 oder 8 Bytes) per sysctl.
func sysU64(sc SysctlFunc, name string) (uint64, error) {
	b, err := sc(name)
	if err != nil {
		return 0, fmt.Errorf("sysctl %s: %w", name, err)
	}
	v, ok := decodeUint(b)
	if !ok {
		return 0, fmt.Errorf("sysctl %s: %w", name, errFormat)
	}
	return v, nil
}

// sysStr liest einen Text per sysctl ("" bei Fehler).
func sysStr(sc SysctlFunc, name string) string {
	b, err := sc(name)
	if err != nil {
		return ""
	}
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return clip(string(b))
}

// sysExists sagt, ob es einen sysctl gibt (z. B. ob ein Kernel-Modul geladen ist).
func sysExists(sc SysctlFunc, name string) bool {
	_, err := sc(name)
	return err == nil
}

// ParseCPTime liest kern.cp_time (CPUSTATES longs: user, nice, sys, intr, idle; Ticks seit dem Start). ls ist
// sizeof(long). Kerne setzt der Aufrufer.
func ParseCPTime(b []byte, ls int) (*m64proto.CPU, error) {
	if (ls != 4 && ls != 8) || len(b) < cpuStates*ls || len(b)%ls != 0 {
		return nil, errFormat
	}
	var v [cpuStates]uint64
	for i := range v {
		v[i], _ = decodeLong(b, i*ls, ls)
	}
	return &m64proto.CPU{User: v[0], Nice: v[1], System: v[2], IRQ: v[3], Idle: v[4]}, nil
}

// cpTimesCores liest die Zahl der Kerne aus kern.cp_times (CPUSTATES longs je Kern).
func cpTimesCores(b []byte, ls int) int {
	if ls <= 0 || len(b) == 0 || len(b)%(cpuStates*ls) != 0 {
		return 0
	}
	return len(b) / (cpuStates * ls)
}

// ParseLoadavg liest vm.loadavg (struct loadavg { fixpt_t ldavg[3]; long fscale; }).
func ParseLoadavg(b []byte, ls int) (*m64proto.Load, error) {
	off := 12 // fscale folgt den drei uint32; bei 8-Byte-long auf 16 ausgerichtet
	if ls == 8 {
		off = 16
	}
	fscale, ok := decodeLong(b, off, ls)
	if !ok || len(b) < 12 || fscale == 0 || fscale > 1<<30 {
		return nil, errFormat
	}
	var l [3]float64
	for i := range l {
		l[i] = math.Round(float64(binary.NativeEndian.Uint32(b[i*4:]))/float64(fscale)*100) / 100
	}
	return &m64proto.Load{L1: l[0], L5: l[1], L15: l[2]}, nil
}

// ParseBoottime liest kern.boottime (struct timeval) und liefert die Unix-Sekunden. time_t ist 64 Bit (amd64,
// arm64, armv7; 16 Bytes mit Ausrichtung), nur i386 hat 32 Bit (8 Bytes).
func ParseBoottime(b []byte) (int64, error) {
	var sec int64
	switch {
	case len(b) >= 16:
		sec = int64(binary.NativeEndian.Uint64(b))
	case len(b) == 8:
		sec = int64(int32(binary.NativeEndian.Uint32(b)))
	default:
		return 0, errFormat
	}
	if sec <= 0 {
		return 0, errFormat
	}
	return sec, nil
}

// ParseXswdev liest einen Eintrag von vm.swap_info.N (struct xswdev) und liefert Groesse und Belegung in Seiten.
// Version 2 (FreeBSD >= 12, dev_t 64 Bit): 32 Bytes bei 64-Bit-Ausrichtung (amd64, arm64, armv7), 24 Bytes auf
// i386. Version 1 (FreeBSD 11, dev_t 32 Bit): 20 Bytes.
func ParseXswdev(b []byte) (nblks, used uint64, err error) {
	if len(b) < 20 {
		return 0, 0, errFormat
	}
	off := 0
	switch ver := binary.NativeEndian.Uint32(b); {
	case ver == 2 && len(b) >= 32:
		off = 20
	case ver == 2 && len(b) >= 24:
		off = 16
	case ver == 1:
		off = 12
	default:
		return 0, 0, errFormat
	}
	n := int32(binary.NativeEndian.Uint32(b[off:]))
	u := int32(binary.NativeEndian.Uint32(b[off+4:]))
	if n < 0 || u < 0 || u > n {
		return 0, 0, errFormat
	}
	return uint64(n), uint64(u), nil
}

// ParseIK liest eine Temperatur im sysctl-Format "IK" (int, Zehntel-Kelvin) in Grad Celsius; ok=false bei
// unplausiblen Werten.
func ParseIK(b []byte) (float64, bool) {
	if len(b) != 4 {
		return 0, false
	}
	v := int32(binary.NativeEndian.Uint32(b))
	c := math.Round((float64(v)/10-273.15)*10) / 10
	if c <= -60 || c >= 200 {
		return 0, false
	}
	return c, true
}

// readCPU liest CPU-Zaehler und Kerne.
func readCPU(sc SysctlFunc) (*m64proto.CPU, error) {
	b, err := sc("kern.cp_time")
	if err != nil {
		return nil, fmt.Errorf("sysctl kern.cp_time: %w", err)
	}
	c, err := ParseCPTime(b, longSize)
	if err != nil {
		return nil, fmt.Errorf("sysctl kern.cp_time: %w", err)
	}
	if n, err := sysU64(sc, "hw.ncpu"); err == nil && n > 0 && n <= 1<<16 {
		c.Cores = int(n)
	} else if b, err := sc("kern.cp_times"); err == nil {
		c.Cores = cpTimesCores(b, longSize)
	}
	if c.Cores <= 0 || c.Cores > 1<<16 {
		c.Cores = 1
	}
	return c, nil
}

// MemValues sind die Rohwerte fuer den Speicher (Seiten bzw. Bytes).
type MemValues struct {
	Physmem  uint64 // hw.physmem (Bytes)
	PageSize uint64 // hw.pagesize
	Free     uint64 // vm.stats.vm.v_free_count (Seiten)
	Inactive uint64 // v_inactive_count
	Cache    uint64 // v_cache_count (ab FreeBSD 12 immer 0)
	ARC      uint64 // kstat.zfs.misc.arcstats.size (Bytes)
	ARCMin   uint64 // kstat.zfs.misc.arcstats.c_min (Bytes)
}

// MemFromValues rechnet den verfuegbaren Speicher: freie, inaktive und Cache-Seiten sowie der ZFS-ARC oberhalb
// seiner Mindestgroesse (gibt der Kernel bei Bedarf frei, zaehlt sonst als "wired"). Laundry (schmutzige Seiten)
// zaehlt nicht.
func MemFromValues(v MemValues) (*m64proto.Mem, error) {
	if v.Physmem == 0 || v.PageSize == 0 || v.PageSize > 1<<24 {
		return nil, errFormat
	}
	const maxPages = 1 << 40 // gegen Ueberlauf bei feindlichen Werten
	pages := v.Free + v.Inactive + v.Cache
	if v.Free > maxPages || v.Inactive > maxPages || v.Cache > maxPages {
		return nil, errFormat
	}
	avail := pages * v.PageSize
	if v.ARC > v.ARCMin && v.ARC-v.ARCMin < v.Physmem {
		avail += v.ARC - v.ARCMin
	}
	if avail > v.Physmem {
		avail = v.Physmem
	}
	return &m64proto.Mem{Total: v.Physmem, Available: avail}, nil
}

// readMem liest RAM (ohne Swap).
func readMem(sc SysctlFunc) (*m64proto.Mem, uint64, error) {
	var v MemValues
	var err error
	for _, it := range []struct {
		name string
		dst  *uint64
	}{{"hw.physmem", &v.Physmem}, {"hw.pagesize", &v.PageSize}, {"vm.stats.vm.v_free_count", &v.Free},
		{"vm.stats.vm.v_inactive_count", &v.Inactive}} {
		if *it.dst, err = sysU64(sc, it.name); err != nil {
			return nil, 0, err
		}
	}
	v.Cache, _ = sysU64(sc, "vm.stats.vm.v_cache_count")
	v.ARC, _ = sysU64(sc, "kstat.zfs.misc.arcstats.size")
	if v.ARC > 0 {
		v.ARCMin, _ = sysU64(sc, "kstat.zfs.misc.arcstats.c_min")
	}
	m, err := MemFromValues(v)
	if err != nil {
		return nil, 0, fmt.Errorf("sysctl vm.stats.vm: %w", err)
	}
	return m, v.PageSize, nil
}

// maxSwapDevs begrenzt die abgefragten Swap-Geraete.
const maxSwapDevs = 64

// readSwap summiert vm.swap_info.N (Bytes). ok=false: Format unbekannt (Aufrufer nimmt swapinfo -k).
func readSwap(sc SysctlFunc, pageSize uint64) (total, free uint64, ok bool) {
	var nb, used uint64
	for i := 0; i < maxSwapDevs; i++ {
		b, err := sc("vm.swap_info", i)
		if err != nil { // ENOENT hinter dem letzten Geraet (ohne Swap gleich beim ersten)
			break
		}
		n, u, err := ParseXswdev(b)
		if err != nil {
			return 0, 0, false
		}
		nb += n
		used += u
	}
	return nb * pageSize, (nb - used) * pageSize, true
}

// readTemps liest CPU-Temperaturen (coretemp/amdtemp: dev.cpu.N.temperature, tjmax als Grenze) und ACPI-Zonen
// (hw.acpi.thermal.tzN.temperature, _CRT als Grenze).
func readTemps(sc SysctlFunc, cores int) []m64proto.Temp {
	var out []m64proto.Temp
	if cores <= 0 || cores > maxItems {
		cores = maxItems
	}
	for i := 0; i < cores && len(out) < maxItems; i++ {
		p := "dev.cpu." + strconv.Itoa(i)
		b, err := sc(p + ".temperature")
		if err != nil {
			if i == 0 { // ohne coretemp/amdtemp gibt es keinen
				break
			}
			continue
		}
		c, ok := ParseIK(b)
		if !ok {
			continue
		}
		t := m64proto.Temp{Name: "cpu/" + strconv.Itoa(i), Label: "CPU " + strconv.Itoa(i), C: c}
		if b, err := sc(p + ".coretemp.tjmax"); err == nil {
			if x, ok := ParseIK(b); ok && x > 0 {
				t.Crit = ptrF64(x)
			}
		}
		out = append(out, t)
	}
	for i := 0; i < 32 && len(out) < maxItems; i++ {
		tz := "tz" + strconv.Itoa(i)
		p := "hw.acpi.thermal." + tz
		b, err := sc(p + ".temperature")
		if err != nil {
			break
		}
		c, ok := ParseIK(b)
		if !ok {
			continue
		}
		t := m64proto.Temp{Name: "acpi/" + tz, Label: "ACPI " + tz, C: c}
		if b, err := sc(p + "._CRT"); err == nil {
			if x, ok := ParseIK(b); ok && x > 0 {
				t.Crit = ptrF64(x)
			}
		}
		if b, err := sc(p + "._HOT"); err == nil {
			if x, ok := ParseIK(b); ok && x > 0 {
				t.High = ptrF64(x)
			}
		}
		out = append(out, t)
	}
	return out
}

// readBoottime liest die Startzeit (Unix-Sekunden, 0 = unbekannt).
func readBoottime(sc SysctlFunc) int64 {
	b, err := sc("kern.boottime")
	if err != nil {
		return 0
	}
	sec, err := ParseBoottime(b)
	if err != nil {
		return 0
	}
	return sec
}

// uptimeFrom rechnet die Laufzeit aus Startzeit und Uhr (0 bei Uhr vor dem Start).
func uptimeFrom(boot int64, now time.Time) float64 {
	if boot <= 0 {
		return 0
	}
	up := float64(now.UnixMilli()-boot*1000) / 1000
	if up < 0 {
		return 0
	}
	return up
}
