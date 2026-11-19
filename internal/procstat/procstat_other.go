//go:build !linux

package procstat

// Self gibt es nur unter Linux (Entwicklung unter Windows: keine Werte).
func Self() (Stat, bool) { return Stat{}, false }

// MemoryLimit gibt es nur unter Linux.
func MemoryLimit() (uint64, bool) { return 0, false }

// DiskOf gibt es nur unter Linux.
func DiskOf(string) (Disk, bool) { return Disk{}, false }
