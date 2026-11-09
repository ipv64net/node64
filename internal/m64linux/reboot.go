package m64linux

import (
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// readReboot prueft "Neustart noetig": Debian/Ubuntu-Datei reboot-required (mit Paketliste) und laufender Kernel
// ohne Modul-Ordner (Kernel-Update ohne Neustart, z. B. Arch). needs-restarting (RHEL) ergaenzt der Aufrufer.
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
	if !r.Required {
		if rel := readStr(src, "/proc/sys/kernel/osrelease"); rel != "" && !strings.ContainsAny(rel, "/ ") {
			have, found := false, false
			for _, n := range src.ReadDir("/lib/modules") {
				if !src.Exists("/lib/modules/" + n + "/modules.dep") {
					continue
				}
				have = true
				if n == rel {
					found = true
					break
				}
			}
			if have && !found {
				r.Required = true
			}
		}
	}
	return r
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
