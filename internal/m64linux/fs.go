package m64linux

import (
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Mount ist eine Zeile aus /proc/mounts.
type Mount struct {
	Device   string
	Mount    string
	Type     string
	ReadOnly bool
}

// ParseMounts liest /proc/mounts (Escapes wie \040 werden aufgeloest).
func ParseMounts(b []byte) []Mount {
	var out []Mount
	for _, ln := range lines(b) {
		f := strings.Fields(ln)
		if len(f) < 4 {
			continue
		}
		m := Mount{Device: unescapeMount(f[0]), Mount: unescapeMount(f[1]), Type: f[2]}
		for _, o := range strings.Split(f[3], ",") {
			if o == "ro" {
				m.ReadOnly = true
			}
		}
		out = append(out, m)
		if len(out) >= 8*maxItems {
			break
		}
	}
	return out
}

// HostReadOnly uebernimmt "nur lesbar" je Mount-Punkt aus der Mount-Liste des Hosts (Namensraum von PID 1). Der
// letzte Eintrag je Mount-Punkt gilt (darueber gehaengte Dateisysteme); Mounts, die der Host nicht kennt, bleiben.
func HostReadOnly(own, host []Mount) {
	ro := map[string]bool{}
	for _, m := range host {
		ro[m.Mount] = m.ReadOnly
	}
	for i := range own {
		if v, ok := ro[own[i].Mount]; ok {
			own[i].ReadOnly = v
		}
	}
}

// unescapeMount loest die Oktal-Escapes aus /proc/mounts auf (\040 Leerzeichen, \011 Tab, \012, \134).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOct(s[i+1]) && isOct(s[i+2]) && isOct(s[i+3]) {
			sb.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func isOct(c byte) bool { return c >= '0' && c <= '7' }

// Pseudo- und Netz-Dateisysteme, die Monitor64 nicht meldet (Netz: statfs kann bei totem Server haengen).
var skipFSTypes = map[string]bool{
	"tmpfs": true, "devtmpfs": true, "devpts": true, "proc": true, "sysfs": true, "cgroup": true, "cgroup2": true,
	"securityfs": true, "pstore": true, "bpf": true, "autofs": true, "tracefs": true, "debugfs": true,
	"hugetlbfs": true, "mqueue": true, "configfs": true, "ramfs": true, "fusectl": true, "binfmt_misc": true,
	"rpc_pipefs": true, "nsfs": true, "overlay": true, "aufs": true, "squashfs": true, "efivarfs": true,
	"selinuxfs": true, "nfsd": true, "rootfs": true, "devfs": true, "none": true, "shm": true, "iso9660": true,
	"udf": true, "zram": true, "fuse.lxcfs": true, "fuse.gvfsd-fuse": true, "fuse.portal": true,
	"fuse.snapfuse": true, "fuse.xdg-document-portal": true, "lxcfs": true, "usbfs": true, "usbdevfs": true,
	// Netz
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true, "ncpfs": true, "afs": true, "9p": true,
	"ceph": true, "glusterfs": true, "fuse.glusterfs": true, "fuse.sshfs": true, "fuse.rclone": true,
	"fuse.s3fs": true, "davfs": true, "fuse.davfs": true, "lustre": true, "gpfs": true, "fuse.ceph-fuse": true,
}

// Mount-Pfade (und alles darunter), die nicht gemeldet werden.
var skipMountPrefixes = []string{
	"/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/var/lib/containers", "/var/lib/kubelet",
	"/var/lib/lxcfs", "/var/snap", "/etc/pve",
}

// SkipMount sagt, ob ein Mount kein echtes Dateisystem ist (Pseudo-FS, Netz, Docker-Overlay, /snap, /run ...).
func SkipMount(m Mount) bool {
	if skipFSTypes[m.Type] {
		return true
	}
	if m.Type == "fuse" && m.Device == "/dev/fuse" { // Proxmox pmxcfs
		return true
	}
	for _, p := range skipMountPrefixes {
		if m.Mount == p || strings.HasPrefix(m.Mount, p+"/") {
			return true
		}
	}
	return false
}

// DedupFS behaelt je Geraet nur einen Mount (Bind-Mounts, btrfs-Subvolumes): den kuerzesten Pfad.
func DedupFS(in []m64proto.FS) []m64proto.FS {
	idx := map[string]int{}
	var out []m64proto.FS
	for _, f := range in {
		key := f.Device
		if key == "" {
			key = "mount:" + f.Mount
		}
		if i, ok := idx[key]; ok {
			if len(f.Mount) < len(out[i].Mount) {
				out[i] = f
			}
			continue
		}
		idx[key] = len(out)
		out = append(out, f)
		if len(out) >= maxItems {
			break
		}
	}
	return out
}

// DFRow ist eine Zeile aus "df -PkT" (bzw. "df -Pk" bei BusyBox ohne -T; dann ist Type leer).
type DFRow struct {
	Device string
	Type   string
	Total  uint64 // Bytes
	Used   uint64
	Avail  uint64
	Mount  string
}

// ParseDF liest die Ausgabe von "df -PkT" oder "df -Pk" (Kopfzeile entscheidet, ob eine Typ-Spalte da ist).
func ParseDF(b []byte) []DFRow {
	ls := lines(b)
	if len(ls) == 0 {
		return nil
	}
	hasType := false
	start := 0
	if h := strings.Fields(ls[0]); len(h) > 0 && h[0] == "Filesystem" {
		hasType = len(h) > 1 && h[1] == "Type"
		start = 1
	}
	var out []DFRow
	for _, ln := range ls[start:] {
		f := strings.Fields(ln)
		n := 6
		if hasType {
			n = 7
		}
		if len(f) < n {
			continue
		}
		r := DFRow{Device: f[0]}
		i := 1
		if hasType {
			r.Type = f[1]
			i = 2
		}
		if !strings.HasSuffix(f[i+3], "%") && f[i+3] != "-" {
			continue
		}
		r.Total = u64(f[i]) * 1024
		r.Used = u64(f[i+1]) * 1024
		r.Avail = u64(f[i+2]) * 1024
		r.Mount = strings.Join(f[i+4:], " ")
		out = append(out, r)
		if len(out) >= 8*maxItems {
			break
		}
	}
	return out
}

// ParseDFInodes liest "df -Pi": Mount -> (Inodes gesamt, frei).
func ParseDFInodes(b []byte) map[string][2]uint64 {
	out := map[string][2]uint64{}
	for i, ln := range lines(b) {
		f := strings.Fields(ln)
		if i == 0 && len(f) > 0 && f[0] == "Filesystem" {
			continue
		}
		// Filesystem [Type] Inodes IUsed IFree IUse% Mounted on
		p := -1
		for j := 1; j < len(f); j++ {
			if strings.HasSuffix(f[j], "%") || (f[j] == "-" && j >= 4) {
				p = j
				break
			}
		}
		if p < 4 || p+1 >= len(f) {
			continue
		}
		out[strings.Join(f[p+1:], " ")] = [2]uint64{u64(f[p-3]), u64(f[p-1])}
		if len(out) >= 8*maxItems {
			break
		}
	}
	return out
}

// FSFromDF baut die Dateisysteme aus df-Zeilen; /proc/mounts liefert Typ (BusyBox ohne -T) und "ro".
func FSFromDF(rows []DFRow, mounts []Mount, inodes map[string][2]uint64) []m64proto.FS {
	byMount := map[string]Mount{}
	for _, m := range mounts {
		byMount[m.Mount] = m // spaeterer Mount ueberdeckt frueheren
	}
	var out []m64proto.FS
	for _, r := range rows {
		m, ok := byMount[r.Mount]
		if !ok {
			m = Mount{Device: r.Device, Mount: r.Mount}
		}
		if r.Type != "" {
			m.Type = r.Type
		}
		if m.Device == "" {
			m.Device = r.Device
		}
		if m.Type == "" && r.Total == 0 {
			continue // unbekannt und leer: Pseudo-FS
		}
		if SkipMount(m) {
			continue
		}
		f := m64proto.FS{Mount: r.Mount, Device: r.Device, Type: m.Type, Total: r.Total, Used: r.Used, Avail: r.Avail, ReadOnly: m.ReadOnly}
		if in, ok := inodes[r.Mount]; ok {
			f.InodesTotal, f.InodesFree = in[0], in[1]
		}
		out = append(out, f)
	}
	return DedupFS(out)
}

// StatFS sind die Groessen eines Dateisystems (Agent: statfs).
type StatFS struct {
	Total, Free, Avail      uint64 // Bytes; Free inkl. root-Reserve
	InodesTotal, InodesFree uint64
}

// FSFromStatfs baut die Dateisysteme aus /proc/mounts und einer statfs-Funktion.
func FSFromStatfs(mounts []Mount, statfs func(mount string) (StatFS, error)) ([]m64proto.FS, []error) {
	// letzte Zeile je Mount-Pfad gilt (ueberdeckte Mounts sind nicht erreichbar)
	last := map[string]int{}
	for i, m := range mounts {
		last[m.Mount] = i
	}
	var out []m64proto.FS
	var errs []error
	for i, m := range mounts {
		if last[m.Mount] != i || SkipMount(m) {
			continue
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
		out = append(out, m64proto.FS{Mount: m.Mount, Device: m.Device, Type: m.Type, Total: st.Total, Used: used,
			Avail: st.Avail, InodesTotal: st.InodesTotal, InodesFree: st.InodesFree, ReadOnly: m.ReadOnly})
	}
	return DedupFS(out), errs
}

// statfsError ist ein Fehler von statfs samt Pfad.
type statfsError struct {
	path string
	err  error
}

func (e *statfsError) Error() string { return "statfs " + e.path + ": " + e.err.Error() }
func (e *statfsError) Unwrap() error { return e.err }
