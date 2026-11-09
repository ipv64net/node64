package m64bsd

import (
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"
)

// Dateien, an denen die Plattform erkannt wird.
const (
	fileOPNsenseCore = "/usr/local/opnsense/version/core" // JSON (OPNsense >= 22.1)
	fileOPNsenseOld  = "/usr/local/opnsense/version/opnsense"
	filePlatform     = "/etc/platform" // pfSense: "pfSense"
	fileVersion      = "/etc/version"  // pfSense: "2.7.2-RELEASE"; TrueNAS CORE: "TrueNAS-13.0-U6.1"
	fileFreeBSDVer   = "/bin/freebsd-version"
)

var userlandRE = regexp.MustCompile(`(?m)^USERLAND_VERSION="([^"]{1,64})"`)

// DetectPlatform erkennt OPNsense, pfSense, TrueNAS CORE bzw. FreeBSD. read liest eine Datei (begrenzt), osrelease
// ist kern.osrelease (Rueckfall fuer die FreeBSD-Version).
func DetectPlatform(read func(path string) ([]byte, error), osrelease string) string {
	first := func(p string) string {
		b, err := read(p)
		if err != nil {
			return ""
		}
		if l := lines(b); len(l) > 0 {
			return clipN(l[0], 100)
		}
		return ""
	}
	if b, err := read(fileOPNsenseCore); err == nil {
		var v struct {
			Name    string `json:"product_name"`
			Version string `json:"product_version"`
		}
		if json.Unmarshal(b, &v) == nil && v.Name != "" {
			return clipN(strings.TrimSpace(v.Name+" "+v.Version), 100)
		}
	}
	if v := first(fileOPNsenseOld); v != "" {
		return clipN("OPNsense "+v, 100)
	}
	ver := first(fileVersion)
	if strings.HasPrefix(ver, "TrueNAS") || strings.HasPrefix(ver, "FreeNAS") {
		return ver
	}
	if p := first(filePlatform); p != "" && ver != "" {
		return clipN(p+" "+ver, 100)
	}
	if b, err := read(fileFreeBSDVer); err == nil {
		if m := userlandRE.FindSubmatch(b); m != nil && versionRE.Match(m[1]) {
			return "FreeBSD " + string(m[1])
		}
	}
	if osrelease != "" {
		return clipN("FreeBSD "+osrelease, 100)
	}
	return "FreeBSD"
}

// readSmall liest hoechstens 64 KB einer Datei.
func readSmall(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 64<<10))
}

// HostInfo liefert Plattform, Kernel und Startzeit fuer m64proto.Info (nur unter FreeBSD sinnvoll; anderswo leer).
func HostInfo() (platform, kernel string, boot int64) {
	return hostInfo(defaultSysctl, readSmall)
}

func hostInfo(sc SysctlFunc, read func(string) ([]byte, error)) (platform, kernel string, boot int64) {
	kernel = clipN(sysStr(sc, "kern.osrelease"), 100)
	if kernel == "" { // kein FreeBSD (bzw. sysctl gesperrt)
		return "", "", 0
	}
	return DetectPlatform(read, kernel), kernel, readBoottime(sc)
}
