package m64linux

import (
	"strings"
	"testing"
)

// kernelSrc: laufender Kernel und installierte Kernel (Ordner unter /lib/modules mit modules.dep).
func kernelSrc(running string, installed ...string) source {
	files := map[string][]byte{"/proc/sys/kernel/osrelease": []byte(running + "\n")}
	for _, k := range installed {
		files["/lib/modules/"+k+"/modules.dep"] = []byte("")
	}
	return newMapSource(files)
}

// #130: Debian 13, neuer Kernel installiert, ohne Neustart; /var/run/reboot-required fehlt (wie im Issue). Bisher:
// "Neustart noetig: nein", weil der laufende Kernel noch einen Modul-Ordner hat.
func TestKernelNewerInstalled(t *testing.T) {
	r := readReboot(kernelSrc("6.12.115+deb13.1-amd64", "6.12.115+deb13.1-amd64", "6.12.116+deb13-amd64"))
	if !r.Required || r.KernelRunning != "6.12.115+deb13.1-amd64" || r.KernelNewest != "6.12.116+deb13-amd64" {
		t.Fatalf("Debian 13: %+v", r)
	}
	for _, c := range []struct {
		name, running string
		installed     []string
		want          bool
		newest        string
	}{
		{"aktuell", "6.12.116+deb13-amd64", []string{"6.12.115+deb13.1-amd64", "6.12.116+deb13-amd64"}, false, ""},
		{"Debian 12", "6.1.0-27-amd64", []string{"6.1.0-27-amd64", "6.1.0-28-amd64"}, true, "6.1.0-28-amd64"},
		{"Ubuntu", "6.8.0-49-generic", []string{"6.8.0-49-generic", "6.8.0-50-generic", "6.8.0-9-generic"}, true, "6.8.0-50-generic"},
		{"Ubuntu, zweistellig", "6.8.0-9-generic", []string{"6.8.0-9-generic", "6.8.0-10-generic"}, true, "6.8.0-10-generic"},
		{"Proxmox", "6.8.12-4-pve", []string{"6.8.12-4-pve", "6.8.12-5-pve", "6.5.13-6-pve"}, true, "6.8.12-5-pve"},
		{"RHEL", "5.14.0-503.14.1.el9_5.x86_64", []string{"5.14.0-503.14.1.el9_5.x86_64", "5.14.0-503.15.1.el9_5.x86_64"}, true, "5.14.0-503.15.1.el9_5.x86_64"},
		{"Fedora", "6.11.7-300.fc41.x86_64", []string{"6.11.7-300.fc41.x86_64", "6.11.10-300.fc41.x86_64"}, true, "6.11.10-300.fc41.x86_64"},
		// Raspberry Pi OS: zwei Varianten nebeneinander (rpi-v8, rpi-2712) – nur die laufende zaehlt
		{"Pi, andere Variante", "6.6.51+rpt-rpi-v8", []string{"6.6.51+rpt-rpi-v8", "6.6.51+rpt-rpi-2712"}, false, ""},
		{"Pi, neuer", "6.6.51+rpt-rpi-v8", []string{"6.6.51+rpt-rpi-v8", "6.6.62+rpt-rpi-v8", "6.6.62+rpt-rpi-2712"}, true, "6.6.62+rpt-rpi-v8"},
		{"Debian, rt daneben", "6.1.0-28-amd64", []string{"6.1.0-28-amd64", "6.1.0-29-rt-amd64"}, false, ""},
		{"Debian, cloud", "6.1.0-28-cloud-amd64", []string{"6.1.0-28-cloud-amd64", "6.1.0-29-cloud-amd64"}, true, "6.1.0-29-cloud-amd64"},
		// aelterer Kernel installiert, laufender ist der neueste
		{"aelterer daneben", "6.8.12-5-pve", []string{"6.8.12-4-pve", "6.8.12-5-pve"}, false, ""},
		// laufender Kernel ohne Modul-Ordner (Arch nach Update): wie bisher
		{"Arch", "6.11.8-arch1-1", []string{"6.11.9-arch1-1"}, true, ""},
	} {
		r := readReboot(kernelSrc(c.running, c.installed...))
		if r.Required != c.want || r.KernelNewest != c.newest {
			t.Errorf("%s: %+v", c.name, r)
		}
	}
}

func TestKernelVersionCompare(t *testing.T) {
	for _, c := range [][2]string{
		{"6.12.115+deb13.1-amd64", "6.12.116+deb13-amd64"}, {"6.8.0-9-generic", "6.8.0-10-generic"},
		{"5.14.0-503.14.1.el9_5.x86_64", "5.14.0-503.15.1.el9_5.x86_64"}, {"5.14.0-427.el9_4.x86_64", "5.14.0-503.14.1.el9_5.x86_64"},
		{"6.6.51+rpt-rpi-v8", "6.6.62+rpt-rpi-v8"}, {"6.1.0-28-amd64", "6.10.0-1-amd64"},
	} {
		if kernelCmp(c[0], c[1]) >= 0 || kernelCmp(c[1], c[0]) <= 0 {
			t.Errorf("%s < %s nicht erkannt", c[0], c[1])
		}
	}
	for in, want := range map[string]string{
		"6.12.115+deb13.1-amd64": "amd64", "6.1.0-28-cloud-amd64": "cloud-amd64", "6.8.0-49-generic": "generic", "6.8.12-4-pve": "pve",
		"6.6.51+rpt-rpi-v8": "rpi-v8", "6.6.51+rpt-rpi-2712": "rpi-2712", "6.1.21-v8+": "v8+", "5.14.0-503.14.1.el9_5.x86_64": ".x86_64",
		"5.14.0-503.14.1.el9_5.x86_64+rt": ".x86_64+rt", "6.11.7-300.fc41.aarch64": ".aarch64",
	} {
		if got := kernelFlavor(in); got != want {
			t.Errorf("kernelFlavor(%q) = %q, erwartet %q", in, got, want)
		}
	}
	_ = strings.TrimSpace
}
