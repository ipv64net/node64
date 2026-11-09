package m64bsd

import (
	"strings"

	"github.com/ipv64net/node64/internal/m64linux"
	"github.com/ipv64net/node64/internal/m64proto"
)

// Mount ist ein eingehaengtes Dateisystem (getfsstat).
type Mount struct {
	Device   string // f_mntfromname, z. B. /dev/ada0p2, zroot/ROOT/default
	Mount    string // f_mntonname
	Type     string // f_fstypename: ufs, zfs, msdosfs, tmpfs ...
	ReadOnly bool   // MNT_RDONLY
	Local    bool   // MNT_LOCAL
}

// StatFS sind die Groessen eines Dateisystems (statfs).
type StatFS struct {
	Total, Free, Avail      uint64 // Bytes; Free inkl. root-Reserve
	InodesTotal, InodesFree uint64
}

// Pseudo-Dateisysteme und Doppelungen, die Monitor64 nicht meldet. Netz-Dateisysteme fallen schon ueber MNT_LOCAL
// heraus (statfs kann bei totem Server haengen).
var skipFSTypes = map[string]bool{
	"devfs": true, "fdescfs": true, "procfs": true, "linprocfs": true, "linsysfs": true, "tmpfs": true,
	"nullfs": true, "unionfs": true, "autofs": true, "mqueuefs": true, "cd9660": true, "udf": true, "fusefs": true,
	"nfs": true, "smbfs": true, "p9fs": true,
}

// Mount-Pfade (und alles darunter), die nicht gemeldet werden: Geraete, Linux-Kompatibilitaet, TrueNAS-Systemdataset.
var skipMountPrefixes = []string{"/dev", "/proc", "/compat/linux/proc", "/compat/linux/sys", "/compat/linux/dev",
	"/var/db/system"}

// SkipMount sagt, ob ein Mount kein echtes lokales Dateisystem ist.
func SkipMount(m Mount) bool {
	if !m.Local || skipFSTypes[m.Type] || strings.HasPrefix(m.Type, "fusefs.") {
		return true
	}
	if strings.Contains(m.Mount, "/.zfs/snapshot/") { // automatisch eingehaengte ZFS-Snapshots
		return true
	}
	for _, p := range skipMountPrefixes {
		if m.Mount == p || strings.HasPrefix(m.Mount, p+"/") {
			return true
		}
	}
	return false
}

// FSFromStatfs baut die Dateisysteme aus der Mount-Liste und einer statfs-Funktion (nur lokale, ohne Pseudo-FS).
func FSFromStatfs(mounts []Mount, statfs func(mount string) (StatFS, error)) ([]m64proto.FS, []error) {
	last := map[string]int{} // letzter Eintrag je Pfad gilt (ueberdeckte Mounts sind nicht erreichbar)
	for i, m := range mounts {
		last[m.Mount] = i
	}
	var out []m64proto.FS
	var errs []error
	for i, m := range mounts {
		if last[m.Mount] != i || SkipMount(m) {
			continue
		}
		if len(out) >= 2*maxItems {
			break
		}
		st, err := statfs(m.Mount)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if st.Total == 0 {
			continue
		}
		used := uint64(0)
		if st.Total > st.Free {
			used = st.Total - st.Free
		}
		out = append(out, m64proto.FS{Mount: clip(m.Mount), Device: clip(m.Device), Type: clip(m.Type), Total: st.Total,
			Used: used, Avail: st.Avail, InodesTotal: st.InodesTotal, InodesFree: st.InodesFree, ReadOnly: m.ReadOnly})
	}
	return m64linux.DedupFS(out), errs
}

// statfsValues rechnet die Felder von struct statfs (FreeBSD) in Bytes um. bavail und ffree koennen negativ sein
// (root-Reserve angegriffen); Ueberlauf bei feindlichen Werten ergibt 0.
func statfsValues(bsize, blocks, bfree uint64, bavail int64, files uint64, ffree int64) StatFS {
	mul := func(a, b uint64) uint64 {
		if a != 0 && b > ^uint64(0)/a {
			return 0
		}
		return a * b
	}
	st := StatFS{Total: mul(blocks, bsize), Free: mul(bfree, bsize), InodesTotal: files}
	if bavail > 0 {
		st.Avail = mul(uint64(bavail), bsize)
	}
	if ffree > 0 {
		st.InodesFree = uint64(ffree)
	}
	if st.Total == 0 {
		st.Free, st.Avail = 0, 0
	}
	return st
}

// statfsError ist ein Fehler von statfs samt Pfad.
type statfsError struct {
	path string
	err  error
}

func (e *statfsError) Error() string { return "statfs " + e.path + ": " + e.err.Error() }
func (e *statfsError) Unwrap() error { return e.err }
