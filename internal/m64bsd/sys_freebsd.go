//go:build freebsd

package m64bsd

import (
	"bytes"

	"golang.org/x/sys/unix"
)

// defaultSysctl liest einen sysctl-Wert roh (ohne cgo).
func defaultSysctl(name string, args ...int) ([]byte, error) { return unix.SysctlRaw(name, args...) }

// maxMounts begrenzt die Mount-Liste (struct statfs hat rund 2,4 KB; TrueNAS kann viele Datasets haben).
const maxMounts = 2 * maxItems

// getMounts liest die eingehaengten Dateisysteme mit MNT_NOWAIT (keine Abfrage der Dateisysteme, haengt nicht bei
// totem NFS-Server; die Groessen holt statfsPath danach nur fuer lokale).
func getMounts() ([]Mount, error) {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}
	if n > maxMounts {
		n = maxMounts
	}
	buf := make([]unix.Statfs_t, n+4) // Platz fuer inzwischen dazugekommene
	n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}
	if n > len(buf) {
		n = len(buf)
	}
	out := make([]Mount, 0, n)
	for i := 0; i < n; i++ {
		s := &buf[i]
		out = append(out, Mount{Device: cstr(s.Mntfromname[:]), Mount: cstr(s.Mntonname[:]), Type: cstr(s.Fstypename[:]),
			ReadOnly: s.Flags&unix.MNT_RDONLY != 0, Local: s.Flags&unix.MNT_LOCAL != 0})
	}
	return out, nil
}

// statfsPath liest die Groessen eines Dateisystems.
func statfsPath(p string) (StatFS, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(p, &st); err != nil {
		return StatFS{}, &statfsError{p, err}
	}
	return statfsValues(st.Bsize, st.Blocks, st.Bfree, st.Bavail, st.Files, st.Ffree), nil
}

// cstr liest einen mit NUL beendeten Text.
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
