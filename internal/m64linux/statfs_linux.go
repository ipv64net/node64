//go:build linux

package m64linux

import "golang.org/x/sys/unix"

// statfsPath liest die Groessen eines Dateisystems.
func statfsPath(p string) (StatFS, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(p, &st); err != nil {
		return StatFS{}, &statfsError{p, err}
	}
	bs := uint64(st.Frsize)
	if bs == 0 {
		bs = uint64(st.Bsize)
	}
	return StatFS{
		Total:       st.Blocks * bs,
		Free:        st.Bfree * bs,
		Avail:       st.Bavail * bs,
		InodesTotal: st.Files,
		InodesFree:  st.Ffree,
	}, nil
}
