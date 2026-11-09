package m64linux

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
)

var testNow = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func parseScriptFile(t *testing.T, name string) *m64proto.Report {
	t.Helper()
	r, err := ParseScriptOutput(readTestdata(t, name), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if r.V != m64proto.Version || r.Time != testNow.UnixMilli() {
		t.Fatalf("Kopf %+v", r)
	}
	// muss sich als JSON ausgeben lassen (so geht es an die Node)
	if _, err := json.Marshal(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func netByName(r *m64proto.Report) map[string]m64proto.NetIf {
	m := map[string]m64proto.NetIf{}
	for _, n := range r.Net {
		m[n.Name] = n
	}
	return m
}

func hasNote(r *m64proto.Report, sec, sub string) bool {
	for _, n := range r.Notes {
		if n.Section == sec && strings.Contains(n.Note, sub) {
			return true
		}
	}
	return false
}

// Debian 12 (VM, Docker-Host), echt aufgezeichnet auf der Testbox mit dash.
func TestScriptDebian(t *testing.T) {
	r := parseScriptFile(t, "script_debian12_vm.txt")
	if len(r.Errors) != 0 {
		t.Fatalf("Fehler: %+v", r.Errors)
	}
	if r.CPU == nil || r.CPU.Cores != 12 || r.Mem == nil || r.Load == nil || r.Uptime < 50000 {
		t.Fatalf("Grundwerte %+v %+v %+v", r.CPU, r.Mem, r.Load)
	}
	if mountsOf(r.FS) != "/" || r.FS[0].Type != "ext4" || r.FS[0].InodesTotal != 3219456 {
		t.Fatalf("fs %+v", r.FS)
	}
	if len(r.Disks) != 1 || r.Disks[0].Name != "sda" || r.Disks[0].Model != "QEMU HARDDISK" || r.Disks[0].Rotational == nil || *r.Disks[0].Rotational {
		t.Fatalf("disk %+v", r.Disks)
	}
	n := netByName(r)
	if _, ok := n["lo"]; ok {
		t.Fatal("lo gemeldet")
	}
	if n["ens18"].Kind != "physical" || !n["ens18"].Up || n["ens18"].SpeedMbit != 0 || n["ens18"].MAC != "bc:24:11:42:6c:6f" {
		t.Fatalf("ens18 %+v", n["ens18"])
	}
	if n["docker0"].Kind != "virtual" || n["docker0"].Up || n["vethe24de3a"].Master != "br-d28b5f971274" || n["br-d28b5f971274"].Kind != "virtual" {
		t.Fatalf("docker %+v %+v", n["docker0"], n["vethe24de3a"])
	}
	if r.Systemd == nil || r.Systemd.State != "running" || len(r.Systemd.Failed) != 0 {
		t.Fatalf("systemd %+v", r.Systemd)
	}
	if r.Updates == nil || r.Updates.Manager != "apt" || r.Updates.Pending != 29 || r.Updates.Security != 23 || r.Updates.Checked != testNow.Unix() {
		t.Fatalf("updates %+v", r.Updates)
	}
	if r.Reboot == nil || r.Reboot.Required {
		t.Fatalf("reboot %+v", r.Reboot)
	}
	if len(r.SMART) != 1 || r.SMART[0].Error != "SMART nicht verfuegbar" {
		t.Fatalf("smart %+v", r.SMART)
	}
	if len(r.Bonds) != 0 || len(r.RAID) != 0 || len(r.ZFS) != 0 {
		t.Fatal("unerwartete Abschnitte")
	}
}

// Dasselbe Skript mit BusyBox ash und nur BusyBox-Programmen (echt aufgezeichnet).
func TestScriptBusyBox(t *testing.T) {
	r := parseScriptFile(t, "script_busybox135_debian.txt")
	if len(r.Errors) != 0 {
		t.Fatalf("Fehler: %+v", r.Errors)
	}
	if mountsOf(r.FS) != "/" || r.CPU == nil || len(r.Net) == 0 || len(r.Disks) != 1 {
		t.Fatalf("%+v", r)
	}
	// systemctl war nicht im PATH; kein Paketverwalter
	if r.Systemd != nil || !hasNote(r, "systemd", "kein systemd") || !hasNote(r, "updates", "kein Paketverwalter") {
		t.Fatalf("Notes %+v", r.Notes)
	}
}

func TestScriptProxmox(t *testing.T) {
	r := parseScriptFile(t, "script_proxmox8.txt")
	if len(r.Errors) != 0 {
		t.Fatalf("Fehler: %+v", r.Errors)
	}
	want := "/ /rpool /rpool/ROOT /rpool/data /rpool/data/subvol-101-disk-0 /tank /mnt/backup"
	if got := mountsOf(r.FS); got != want {
		t.Fatalf("fs %q", got)
	}
	n := netByName(r)
	kinds := map[string]string{"eno1": "physical", "eno2": "physical", "bond0": "bond", "vmbr0": "bridge", "vmbr0.20": "vlan",
		"tap100i0": "virtual", "fwbr100i0": "virtual", "fwpr100p0": "virtual", "fwln100i0": "virtual", "veth101i0": "virtual"}
	for name, k := range kinds {
		if n[name].Kind != k {
			t.Errorf("%s: Art %q, erwartet %q", name, n[name].Kind, k)
		}
	}
	if n["eno1"].Master != "bond0" || n["bond0"].Master != "vmbr0" || n["eno2"].Up || n["eno2"].RxCRC != 3 || !n["tap100i0"].Up {
		t.Fatalf("net %+v %+v %+v", n["eno1"], n["eno2"], n["tap100i0"])
	}
	if len(r.Bonds) != 1 || len(r.Bonds[0].Members) != 2 {
		t.Fatalf("bond %+v", r.Bonds)
	}
	if len(r.ZFS) != 2 || r.ZFS[1].Health != "DEGRADED" {
		t.Fatalf("zfs %+v", r.ZFS)
	}
	if r.Systemd.State != "degraded" || len(r.Systemd.Failed) != 1 {
		t.Fatalf("systemd %+v", r.Systemd)
	}
	if r.Updates.Pending != 4 || r.Updates.Security != 2 {
		t.Fatalf("updates %+v", r.Updates)
	}
	if len(r.SMART) != 3 || r.SMART[2].Error != SmartErrStandby || r.SMART[0].Serial != "S5GXNF0R123456A" {
		t.Fatalf("smart %+v", r.SMART)
	}
	if r.Disks[2].Serial != "S6PTNM0T123456K" || r.Disks[3].Serial != "WD-WCC4M1234567" || *r.Disks[3].Rotational != true {
		t.Fatalf("disk %+v", r.Disks)
	}
	if r.Reboot.Required {
		t.Fatal("kein Neustart erwartet")
	}
}

func TestScriptSynology(t *testing.T) {
	r := parseScriptFile(t, "script_synology_dsm7.txt")
	if len(r.Errors) != 0 {
		t.Fatalf("Fehler: %+v", r.Errors)
	}
	if got := mountsOf(r.FS); got != "/ /volume1 /volumeUSB1/usbshare" {
		t.Fatalf("fs %q", got)
	}
	if len(r.RAID) != 3 || r.RAID[0].Name != "md2" || r.RAID[0].State != "active" {
		t.Fatalf("raid %+v", r.RAID)
	}
	if len(r.Disks) != 2 || r.Disks[0].Name != "sata1" || r.Disks[0].Model != "WD40EFZX-68AWUN0" {
		t.Fatalf("disk %+v", r.Disks)
	}
	n := netByName(r)
	if n["docker9b1c2d3"].Kind != "virtual" || n["eth1"].Up || n["sit0"].Kind != "virtual" {
		t.Fatalf("net %+v", n)
	}
	if r.SMART != nil || !hasNote(r, "smart", "sudo -n smartctl nicht erlaubt") {
		t.Fatalf("smart %+v %+v", r.SMART, r.Notes)
	}
	if r.Updates != nil {
		t.Fatal("updates ohne Flag")
	}
}

func TestScriptUnraid(t *testing.T) {
	r := parseScriptFile(t, "script_unraid612.txt")
	if len(r.Errors) != 0 {
		t.Fatalf("Fehler: %+v", r.Errors)
	}
	want := "/boot /mnt/disk1 /mnt/disk2 /mnt/cache /mnt/user /etc/libvirt /mnt/disks/My Backup"
	if got := mountsOf(r.FS); got != want {
		t.Fatalf("fs %q", got)
	}
	for _, f := range r.FS {
		if f.Mount == "/mnt/disks/My Backup" && !f.ReadOnly {
			t.Fatal("ro aus /proc/mounts fehlt")
		}
	}
	var disks []string
	for _, d := range r.Disks {
		disks = append(disks, d.Name)
	}
	if strings.Join(disks, " ") != "sda sdb sdc sdd nvme0n1" {
		t.Fatalf("disk %v", disks)
	}
	if r.Systemd != nil || !hasNote(r, "systemd", "kein systemd") || !hasNote(r, "updates", "kein Paketverwalter") {
		t.Fatalf("notes %+v", r.Notes)
	}
	if len(r.Bonds) != 1 || r.Bonds[0].Members[0].Name != "eth0" {
		t.Fatalf("bond %+v", r.Bonds)
	}
	n := netByName(r)
	if n["br0"].Kind != "bridge" || n["virbr0"].Kind != "virtual" || n["eth0"].Master != "bond0" || n["eth0"].SpeedMbit != 2500 {
		t.Fatalf("net %+v", n)
	}
	sm := map[string]m64proto.SMART{}
	for _, s := range r.SMART {
		sm[s.Device] = s
	}
	if sm["/dev/sda"].Error != "SMART nicht verfuegbar" || sm["/dev/sdb"].Error != SmartErrStandby {
		t.Fatalf("smart %+v", r.SMART)
	}
	if c := sm["/dev/sdc"]; *c.Pending != 8 || *c.Uncorrectable != 8 || *c.Reallocated != 16 || !*c.Passed || c.WearPercentUsed != nil {
		t.Fatalf("sdc %+v", c)
	}
	if nv := sm["/dev/nvme0"]; *nv.Passed || *nv.CriticalWarning != 4 || *nv.MediaErrors != 3 || *nv.WearPercentUsed != 101 {
		t.Fatalf("nvme %+v", nv)
	}
	// AUXTIN0 mit -62 Grad ist kein Sensor
	for _, tp := range r.Temps {
		if strings.Contains(tp.Name, "AUXTIN0") {
			t.Fatalf("unplausibler Sensor %+v", tp)
		}
	}
	if len(r.Temps) != 4 {
		t.Fatalf("temp %+v", r.Temps)
	}
}

func TestScriptRaspberry(t *testing.T) {
	r := parseScriptFile(t, "script_raspios12.txt")
	if len(r.Errors) != 0 {
		t.Fatalf("Fehler: %+v", r.Errors)
	}
	if got := mountsOf(r.FS); got != "/ /boot/firmware /media/usb" {
		t.Fatalf("fs %q", got)
	}
	if r.Disks[0].Name != "mmcblk0" || r.Disks[0].Model != "SN64G" || r.Disks[0].Serial != "0x1234abcd" {
		t.Fatalf("disk %+v", r.Disks)
	}
	if n := netByName(r); n["wlan0"].Kind != "physical" || n["eth0"].SpeedMbit != 1000 {
		t.Fatalf("net %+v", n)
	}
	if r.Updates.Pending != 2 || r.Updates.Security != 1 {
		t.Fatalf("updates %+v", r.Updates)
	}
}

func TestScriptRebootDetection(t *testing.T) {
	out := "\n<<<m64:start>>>\n1\n\n<<<m64:file:/var/run/reboot-required.pkgs>>>\nlinux-image-6.1.0-54-amd64\nlibc6\nlibc6\n\n<<<m64:attr>>>\n" +
		"/var/run/reboot-required\t1\n\n<<<m64:end>>>\n"
	r, err := ParseScriptOutput([]byte(out), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Reboot.Required || len(r.Reboot.Packages) != 2 {
		t.Fatalf("%+v", r.Reboot)
	}
	// laufender Kernel ohne Modul-Ordner (Kernel aktualisiert, nicht neu gestartet)
	out = "\n<<<m64:start>>>\n1\n\n<<<m64:attr>>>\n/proc/sys/kernel/osrelease\t6.10.8-arch1-1\n/lib/modules/6.10.9-arch1-1/modules.dep\t1\n\n<<<m64:end>>>\n"
	r, _ = ParseScriptOutput([]byte(out), testNow)
	if !r.Reboot.Required {
		t.Fatalf("%+v", r.Reboot)
	}
	// RHEL: needs-restarting -r mit Exit-Code 1
	out = "\n<<<m64:start>>>\n1\n\n<<<m64:needs_restarting>>>\n1\n\n<<<m64:end>>>\n"
	r, _ = ParseScriptOutput([]byte(out), testNow)
	if !r.Reboot.Required {
		t.Fatalf("%+v", r.Reboot)
	}
}

func TestParseScriptOutputLimits(t *testing.T) {
	if _, err := ParseScriptOutput(make([]byte, m64proto.MaxReportBytes+1), testNow); err == nil {
		t.Fatal("Groessengrenze fehlt")
	}
	if _, err := ParseScriptOutput([]byte("bash: sh: command not found\n"), testNow); err == nil {
		t.Fatal("fremde Ausgabe angenommen")
	}
	// abgebrochen: kein end, kaputte Abschnitte, fremde Pfade
	out := "<<<m64:start>>>\n1\n<<<m64:file:relativ>>>\nx\n<<<m64:attr>>>\nkein-tab\n../etc\tx\n<<<m64:smart:/dev/sda;reboot>>>\n{}\n<<<m64:file:/proc/stat>>>\ncpu 1 2"
	r, err := ParseScriptOutput([]byte(out), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !hasNote(r, "script", "unvollstaendig") || len(r.SMART) != 0 {
		t.Fatalf("%+v", r)
	}
	// viele Abschnitte und lange Zeilen bleiben begrenzt
	var big bytes.Buffer
	big.WriteString("<<<m64:start>>>\n")
	for i := 0; big.Len() < m64proto.MaxReportBytes-100; i++ {
		big.WriteString("<<<m64:smart:/dev/sda>>>\n{}\n")
	}
	r, err = ParseScriptOutput(big.Bytes(), testNow)
	if err != nil || len(r.SMART) > maxSmartDevices {
		t.Fatalf("%v %d", err, len(r.SMART))
	}
}

func TestScriptContent(t *testing.T) {
	if strings.Contains(Script, "\r") {
		t.Fatal("Skript enthaelt CR")
	}
	if !strings.Contains(Script, "<<<m64:%s>>>") || !strings.Contains(Script, "m64_sec end") {
		t.Fatal("Abschnittsformat fehlt")
	}
	// nur lesend: keine schreibenden Befehle, Umleitungen nur nach /dev/null (Kommentare ausgenommen)
	badCmd := regexp.MustCompile(`(^|[\s;|&(])(rm|mv|cp|tee|dd|mkdir|touch|chmod|chown|ln|sed -i|apt-get update|apt update|makecache|zpool (scrub|clear))(\s|$)`)
	redir := regexp.MustCompile(`(^|[^0-9&<>])>\s*([^&\s|;)>]+)`)
	for i, ln := range strings.Split(Script, "\n") {
		if tl := strings.TrimSpace(ln); tl == "" || strings.HasPrefix(tl, "#") {
			continue
		}
		if m := badCmd.FindString(ln); m != "" {
			t.Errorf("Zeile %d: %q", i+1, m)
		}
		for _, m := range redir.FindAllStringSubmatch(ln, -1) {
			if m[2] != "/dev/null" {
				t.Errorf("Zeile %d: Umleitung nach %q", i+1, m[2])
			}
		}
	}
	if ScriptCommand(true, true) != "sh -s -- smart updates" || ScriptCommand(false, false) != "sh -s --" {
		t.Fatal(ScriptCommand(true, true))
	}
}

// TestScriptSyntax prueft das Skript mit allen vorhandenen Shells (sh -n).
func TestScriptSyntax(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("keine POSIX-Shell")
	}
	found := false
	for _, sh := range []string{"sh", "dash", "bash", "busybox"} {
		p, err := exec.LookPath(sh)
		if err != nil {
			continue
		}
		args := []string{"-n"}
		if sh == "busybox" {
			args = []string{"sh", "-n"}
		}
		cmd := exec.Command(p, args...)
		cmd.Stdin = strings.NewReader(Script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: %v: %s", sh, err, out)
		}
		found = true
	}
	if !found {
		t.Skip("keine Shell gefunden")
	}
}

// TestScriptRunLocal laesst das Skript auf dem Testrechner laufen (nur Linux) und wertet die Ausgabe aus.
func TestScriptRunLocal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("nur Linux")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("kein sh")
	}
	cmd := exec.Command(sh, "-s", "--")
	cmd.Stdin = strings.NewReader(Script)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v", err)
	}
	r, err := ParseScriptOutput(out, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r.CPU == nil || r.Mem == nil || r.Load == nil || hasNote(r, "script", "unvollstaendig") {
		t.Fatalf("%+v", r)
	}
}
