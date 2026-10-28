package main

import (
	"syscall"
	"unsafe"
)

// Das Image gibt /sonar64 cap_net_raw nur als "erlaubt" (setcap cap_net_raw=+p, ohne Effective-Bit): so startet
// das Binary auch ohne das Recht (cap_drop, MikroTik), und schaltet es hier selbst scharf. Nur Standardbibliothek
// (wie internal/caps, aber ohne golang.org/x/sys).

const (
	linuxCapV3 = 0x20080522
	capNetRaw  = 13
)

type capHeader struct {
	version uint32
	pid     int32
}

type capData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

// raiseNetRaw macht cap_net_raw wirksam, wenn es erlaubt, aber nicht wirksam ist. Andere Rechte bleiben, wie sie
// sind. Rueckgabe: ob sich etwas geaendert hat.
func raiseNetRaw() (bool, error) {
	hdr := capHeader{version: linuxCapV3}
	var data [2]capData
	if _, _, e := syscall.RawSyscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return false, e
	}
	const bit = uint32(1) << capNetRaw
	if data[0].permitted&bit == 0 || data[0].effective&bit != 0 {
		return false, nil
	}
	data[0].effective |= bit
	// fuer alle Threads, sonst haette nur der aktuelle das Recht (geht nur ohne cgo, wie im Release)
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return false, e
	}
	return true, nil
}
