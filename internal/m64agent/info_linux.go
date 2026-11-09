//go:build linux

package m64agent

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// hostInfo liest Distribution (/etc/os-release), Kernel und Startzeit (/proc/stat btime).
func hostInfo() (platform, kernel string, boot int64) {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if b, err := os.ReadFile(p); err == nil {
			platform = osReleaseName(string(b))
			break
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = cleanText(strings.TrimSpace(string(b)), 100)
	}
	if f, err := os.Open("/proc/stat"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
				boot, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
				break
			}
		}
	}
	return platform, kernel, boot
}

// osReleaseName liefert PRETTY_NAME (sonst NAME VERSION).
func osReleaseName(s string) string {
	vals := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		if uq, err := strconv.Unquote(v); err == nil {
			v = uq
		} else {
			v = strings.Trim(v, `"'`)
		}
		vals[k] = v
	}
	name := vals["PRETTY_NAME"]
	if name == "" {
		name = strings.TrimSpace(vals["NAME"] + " " + vals["VERSION"])
	}
	return cleanText(name, 100)
}
