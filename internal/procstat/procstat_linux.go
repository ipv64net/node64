//go:build linux

package procstat

import (
	"os"

	"golang.org/x/sys/unix"
)

// Self liefert die Kennzahlen des eigenen Prozesses aus /proc/self.
func Self() (Stat, bool) {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return Stat{}, false
	}
	st, ok := parseStat(string(b), os.Getpagesize())
	if !ok {
		return Stat{}, false
	}
	if d, err := os.Open("/proc/self/fd"); err == nil {
		names, _ := d.Readdirnames(-1)
		d.Close()
		if len(names) > 0 {
			st.OpenFDs = len(names) - 1 // ohne den Deskriptor dieser Auflistung
		}
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err == nil {
		st.MaxFDs = uint64(lim.Cur)
	}
	return st, true
}

// MemoryLimit liefert die Speichergrenze des Containers (cgroup v2, sonst v1); false ohne Grenze.
func MemoryLimit() (uint64, bool) {
	for _, p := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		if b, err := os.ReadFile(p); err == nil {
			return parseLimit(string(b))
		}
	}
	return 0, false
}

// DiskOf liefert den Speicherplatz des Dateisystems, auf dem path liegt.
func DiskOf(path string) (Disk, bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return Disk{}, false
	}
	bs := uint64(st.Frsize)
	if bs == 0 {
		bs = uint64(st.Bsize)
	}
	return Disk{Size: st.Blocks * bs, Free: st.Bavail * bs}, true
}
