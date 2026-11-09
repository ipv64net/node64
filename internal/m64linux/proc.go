package m64linux

import (
	"errors"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

var errFormat = errors.New("unbekanntes Format")

// ParseStat liest /proc/stat: Summenzeile "cpu" und Zahl der Kerne ("cpu0", "cpu1", ...).
func ParseStat(b []byte) (*m64proto.CPU, error) {
	var c *m64proto.CPU
	cores := 0
	for _, ln := range lines(b) {
		f := strings.Fields(ln)
		if len(f) < 5 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		if f[0] != "cpu" {
			if _, err := strconv.Atoi(f[0][3:]); err == nil {
				cores++
			}
			continue
		}
		v := make([]uint64, 8)
		for i := 0; i < 8 && i+1 < len(f); i++ {
			v[i] = u64(f[i+1])
		}
		c = &m64proto.CPU{User: v[0], Nice: v[1], System: v[2], Idle: v[3], IOWait: v[4], IRQ: v[5], SoftIRQ: v[6], Steal: v[7]}
	}
	if c == nil {
		return nil, errFormat
	}
	if cores == 0 {
		cores = 1
	}
	c.Cores = cores
	return c, nil
}

// ParseMeminfo liest /proc/meminfo (kB -> Bytes). Fehlt MemAvailable (Kernel < 3.14), wird es geschaetzt.
func ParseMeminfo(b []byte) (*m64proto.Mem, error) {
	vals := map[string]uint64{}
	for _, ln := range lines(b) {
		k, rest, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v := u64(f[0])
		if len(f) > 1 && strings.EqualFold(f[1], "kB") {
			v *= 1024
		}
		vals[k] = v
	}
	total, ok := vals["MemTotal"]
	if !ok || total == 0 {
		return nil, errFormat
	}
	avail, ok := vals["MemAvailable"]
	if !ok {
		avail = vals["MemFree"] + vals["Buffers"] + vals["Cached"]
		if avail > total {
			avail = total
		}
	}
	return &m64proto.Mem{Total: total, Available: avail, SwapTotal: vals["SwapTotal"], SwapFree: vals["SwapFree"]}, nil
}

// ParseLoadavg liest /proc/loadavg.
func ParseLoadavg(b []byte) (*m64proto.Load, error) {
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return nil, errFormat
	}
	var v [3]float64
	for i := range v {
		x, err := strconv.ParseFloat(f[i], 64)
		if err != nil {
			return nil, errFormat
		}
		v[i] = x
	}
	return &m64proto.Load{L1: v[0], L5: v[1], L15: v[2]}, nil
}

// ParseUptime liest /proc/uptime (Sekunden seit dem Start).
func ParseUptime(b []byte) (float64, error) {
	f := strings.Fields(string(b))
	if len(f) < 1 {
		return 0, errFormat
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil || v < 0 {
		return 0, errFormat
	}
	return v, nil
}

// readProcBasics fuellt Uptime, CPU, Mem und Load aus der Quelle.
func readProcBasics(src source, r *m64proto.Report, want func(string) bool) {
	if b, err := src.ReadFile("/proc/uptime"); err == nil {
		if up, err := ParseUptime(b); err == nil {
			r.Uptime = up
		}
	}
	type item struct {
		sec, file string
		set       func([]byte) error
	}
	items := []item{
		{m64proto.SecCPU, "/proc/stat", func(b []byte) (err error) { r.CPU, err = ParseStat(b); return }},
		{m64proto.SecMem, "/proc/meminfo", func(b []byte) (err error) { r.Mem, err = ParseMeminfo(b); return }},
		{m64proto.SecLoad, "/proc/loadavg", func(b []byte) (err error) { r.Load, err = ParseLoadavg(b); return }},
	}
	for _, it := range items {
		if !want(it.sec) {
			continue
		}
		b, err := src.ReadFile(it.file)
		if err == nil {
			err = it.set(b)
			if err != nil {
				err = errors.New(it.file + ": " + err.Error())
			}
		}
		addErr(r, it.sec, err)
	}
}
