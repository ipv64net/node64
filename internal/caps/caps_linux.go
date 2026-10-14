// Package caps macht Datei-Capabilities des Binaries wirksam. Das Image gibt /node64 die Rechte nur als
// "erlaubt" (setcap ...=+p, ohne Effective-Bit): so startet das Binary auch, wenn der Container sie nicht hat
// (cap_drop, Podman), und Node64 schaltet beim Start selbst scharf, was der Container zulaesst.
package caps

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Raise setzt die wirksamen Rechte aller Threads auf die erlaubten. Rueckgabe: ob sich etwas geaendert hat.
func Raise() (bool, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false, err
	}
	if data[0].Effective == data[0].Permitted && data[1].Effective == data[1].Permitted {
		return false, nil
	}
	data[0].Effective, data[1].Effective = data[0].Permitted, data[1].Permitted
	// fuer alle Threads, sonst haette nur der aktuelle die Rechte (geht nur ohne cgo, wie im Image)
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return false, e
	}
	return true, nil
}
