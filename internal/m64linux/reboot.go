package m64linux

import (
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// readReboot prueft "Neustart noetig": Debian/Ubuntu-Datei reboot-required (mit Paketliste), laufender Kernel ohne
// Modul-Ordner (Kernel-Update ohne Neustart, z. B. Arch) und ein neuerer installierter Kernel derselben Variante
// (Debian, Ubuntu, Proxmox, RHEL, Fedora, Raspberry Pi OS; #130). needs-restarting (RHEL) ergaenzt der Aufrufer.
func readReboot(src source) *m64proto.Reboot {
	r := &m64proto.Reboot{}
	for _, f := range []string{"/var/run/reboot-required", "/run/reboot-required"} {
		if !src.Exists(f) {
			continue
		}
		r.Required = true
		if b, err := src.ReadFile(f + ".pkgs"); err == nil {
			seen := map[string]bool{}
			for _, ln := range lines(b) {
				p := clip(ln)
				if p == "" || seen[p] {
					continue
				}
				seen[p] = true
				r.Packages = append(r.Packages, p)
				if len(r.Packages) >= 100 {
					break
				}
			}
		}
		break
	}
	rel := readStr(src, "/proc/sys/kernel/osrelease")
	if rel == "" || strings.ContainsAny(rel, "/ ") {
		return r
	}
	have, found := false, false
	newest := ""
	flavor := kernelFlavor(rel)
	for _, n := range src.ReadDir("/lib/modules") {
		if strings.ContainsAny(n, "/ ") || !src.Exists("/lib/modules/"+n+"/modules.dep") {
			continue
		}
		have = true
		if n == rel {
			found = true
		}
		if kernelFlavor(n) == flavor && kernelCmp(n, rel) > 0 && (newest == "" || kernelCmp(n, newest) > 0) {
			newest = n
		}
	}
	switch {
	case have && !found:
		r.Required = true
	case newest != "":
		r.Required, r.KernelRunning, r.KernelNewest = true, clip(rel), clip(newest)
	}
	return r
}

// kernelFlavor ist die Variante eines Kernels (Teil des Namens hinter Version und ABI-Nummer): "amd64",
// "cloud-amd64", "generic", "pve", "rpi-v8", "rpi-2712", bei RHEL/Fedora die Architektur (".x86_64", mit "+rt").
// Verglichen werden nur Kernel derselben Variante (Raspberry Pi OS hat rpi-v8 und rpi-2712 nebeneinander).
func kernelFlavor(k string) string {
	for _, arch := range []string{".x86_64", ".aarch64", ".ppc64le", ".s390x", ".i686", ".armv7hl"} {
		if i := strings.LastIndex(k, arch); i > 0 {
			return k[i:]
		}
	}
	parts := strings.Split(k, "-")
	i := 1
	for i < len(parts) && parts[i] != "" && strings.Trim(parts[i], "0123456789") == "" {
		i++ // ABI-Nummer (Debian "28", Ubuntu "49", Proxmox "4")
	}
	return strings.Join(parts[i:], "-")
}

// kernelCmp vergleicht zwei Kernel-Namen wie eine Versionssortierung: Ziffernfolgen als Zahlen, sonst Zeichen
// (-1 a aelter, 0 gleich, 1 a neuer).
func kernelCmp(a, b string) int {
	for a != "" && b != "" {
		da, db := isDigit(a[0]), isDigit(b[0])
		if da && db {
			na, ra := leadDigits(a)
			nb, rb := leadDigits(b)
			na, nb = strings.TrimLeft(na, "0"), strings.TrimLeft(nb, "0")
			switch {
			case len(na) != len(nb):
				return cmpInt(len(na), len(nb))
			case na != nb:
				return strings.Compare(na, nb)
			}
			a, b = ra, rb
			continue
		}
		if a[0] != b[0] {
			// Ziffer gegen Trennzeichen: die Ziffer gilt als neuer ("6.1.10" > "6.1-")
			switch {
			case da:
				return 1
			case db:
				return -1
			}
			return cmpInt(int(a[0]), int(b[0]))
		}
		a, b = a[1:], b[1:]
	}
	return cmpInt(len(a), len(b))
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func leadDigits(s string) (string, string) {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// ParseNeedsRestarting wertet den Exit-Code von "needs-restarting -r" aus (1 = Neustart noetig, 0 = nein).
func ParseNeedsRestarting(code int) (required, ok bool) {
	switch code {
	case 0:
		return false, true
	case 1:
		return true, true
	}
	return false, false
}
