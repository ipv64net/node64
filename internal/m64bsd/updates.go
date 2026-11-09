package m64bsd

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Paketverwalter (Updates.Manager).
const mgrPkg = "pkg"

// Nur das echte pkg (aus dem Paket ports-mgmt/pkg). /usr/sbin/pkg ist der Bootstrap-Starter und wuerde ohne
// installiertes pkg anbieten, es aus dem Netz zu holen.
var pkgPaths = []string{"/usr/local/sbin/pkg", "/usr/local/sbin/pkg-static"}

// pkgVersionArgs: installierte Pakete gegen den vorhandenen Katalog der Paketquellen (-R) vergleichen, ohne ihn
// zu erneuern (-U, kein Netz), nur aeltere ("<") auflisten.
var pkgVersionArgs = []string{"version", "-U", "-R", "-l", "<"}

// pkgAuditArgs: installierte Pakete gegen die vorhandene Schwachstellen-Datenbank (/var/db/pkg/vuln.xml) pruefen;
// ohne -F (kein Download).
var pkgAuditArgs = []string{"audit"}

// ParsePkgVersion zaehlt die Pakete mit neuerer Version in der Paketquelle aus "pkg version -U -R -l <"
// ("curl-8.9.1   <" bzw. mit -v "curl-8.9.1  <  needs updating (remote has 8.10.1)").
func ParsePkgVersion(b []byte) int {
	n := 0
	for _, ln := range lines(b) {
		if f := strings.Fields(ln); len(f) >= 2 && f[1] == "<" && strings.Contains(f[0], "-") {
			n++
		}
	}
	return n
}

var (
	pkgVulnRE    = regexp.MustCompile(`^(\S+) is vulnerable:?\s*$`)
	pkgAuditSum  = regexp.MustCompile(`(\d+) problem\(s\) in (\d+) installed package\(s\) found`)
	pkgAuditNoDB = regexp.MustCompile(`(?i)vuln\.?xml.*(does not exist|not found|cannot open|no such file)|pkg audit -F`)
)

// ParsePkgAudit wertet "pkg audit" aus: Zahl der verwundbaren installierten Pakete (Summenzeile "N problem(s) in M
// installed package(s) found", sonst die Zeilen "<paket> is vulnerable:"). noDB: keine Schwachstellen-Datenbank
// (noch nie "pkg audit -F" gelaufen). ok=false: Ausgabe nicht auswertbar.
func ParsePkgAudit(stdout, stderr []byte, code int) (vulnerable int, noDB, ok bool) {
	if pkgAuditNoDB.Match(stderr) || pkgAuditNoDB.Match(stdout) {
		return 0, true, false
	}
	pkgs := map[string]bool{}
	for _, ln := range lines(stdout) {
		if m := pkgAuditSum.FindStringSubmatch(ln); m != nil {
			if v, err := strconv.Atoi(m[2]); err == nil && v >= 0 && v < 1_000_000 {
				return v, false, true
			}
		}
		if m := pkgVulnRE.FindStringSubmatch(strings.TrimSpace(ln)); m != nil && len(pkgs) < 100000 {
			pkgs[m[1]] = true
		}
	}
	if len(pkgs) > 0 {
		return len(pkgs), false, true
	}
	if code == 0 { // keine Funde (aeltere pkg ohne Summenzeile)
		return 0, false, true
	}
	return 0, false, false
}

// versionRE: Versionstext von freebsd-version bzw. uname -r (z. B. 14.1-RELEASE-p5, 15.0-CURRENT).
var versionRE = regexp.MustCompile(`^[0-9][0-9A-Za-z.\-_]{0,63}$`)

// ParseFreeBSDVersion liest "freebsd-version -k -r" (zwei Zeilen: installierter Kernel, laufender Kernel) und
// liefert, ob ein Neustart noetig ist (installierter Kernel neuer als der laufende).
func ParseFreeBSDVersion(b []byte) (*m64proto.Reboot, bool) {
	var v []string
	for _, ln := range lines(b) {
		if t := strings.TrimSpace(ln); t != "" {
			v = append(v, t)
		}
	}
	if len(v) < 2 || !versionRE.MatchString(v[0]) || !versionRE.MatchString(v[1]) {
		return nil, false
	}
	r := &m64proto.Reboot{}
	if v[0] != v[1] {
		r.Required = true
		r.Packages = []string{"kernel " + v[0] + " (läuft: " + v[1] + ")"}
	}
	return r, true
}

// ParseSwapinfo liest "swapinfo -k" (Ersatz, wenn vm.swap_info ein unbekanntes Format hat): Summe der Geraete in
// Bytes.
func ParseSwapinfo(b []byte) (total, free uint64, err error) {
	found := false
	for _, ln := range lines(b) {
		f := strings.Fields(ln)
		if len(f) < 5 || f[0] == "Device" || f[0] == "Total" || !strings.HasSuffix(f[4], "%") {
			continue
		}
		t, err1 := strconv.ParseUint(f[1], 10, 64)
		u, err2 := strconv.ParseUint(f[2], 10, 64)
		if err1 != nil || err2 != nil || u > t || t > 1<<44 {
			continue
		}
		found = true
		total += t * 1024
		free += (t - u) * 1024
	}
	if !found && len(lines(b)) > 1 {
		return 0, 0, errFormat
	}
	return total, free, nil
}
