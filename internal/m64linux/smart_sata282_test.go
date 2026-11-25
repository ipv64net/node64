package m64linux

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Issue #282: SATA-Platte (WD Red Pro 16 TB) per SSH ohne Agent. Echte Ausgabe von smartctl 7.3 -j -a -n standby
// -d sat (alle Abschnitte, wie Debian 12/UGOS sie liefert) ergibt Zustand, Temperatur, Zaehler und alle Attribute.
func TestSmartWD161KFGX(t *testing.T) {
	s := ParseSmartctl("/dev/sda", readTestdata(t, "smart_ata_wd161kfgx.json"))
	if s.Error != "" || s.Passed == nil || !*s.Passed {
		t.Fatalf("Zustand %+v", s)
	}
	if s.Device != "/dev/sda" || s.Type != "ata" || s.Model != "WDC WD161KFGX-68AFPN0" || s.Serial != "2BJ9TESTX" ||
		s.Firmware != "83.00A83" || s.CapacityBytes != 16000900661248 {
		t.Fatalf("Kopf %+v", s)
	}
	if s.TempC == nil || *s.TempC != 37 || s.PowerOnHours == nil || *s.PowerOnHours != 23456 {
		t.Fatalf("Temperatur/Stunden %+v", s)
	}
	for name, v := range map[string]*uint64{"realloc": s.Reallocated, "pending": s.Pending, "uncorr": s.Uncorrectable, "crc": s.CRCErrors} {
		if v == nil || *v != 0 {
			t.Errorf("%s: %v", name, v)
		}
	}
	if s.WearPercentUsed != nil {
		t.Errorf("Festplatte ohne Verschleiss: %v", *s.WearPercentUsed)
	}
	if len(s.Attrs) != 18 || s.Attrs[13].ID != 194 || s.Attrs[13].Raw != "37 (Min/Max 20/45)" || len(s.Values) != 0 {
		t.Fatalf("Attribute %d %+v, Werte %+v", len(s.Attrs), s.Attrs, s.Values)
	}
}

// Issue #282: der ganze SSH-Weg ohne root - Geraeteliste aus "smartctl --scan-open", Aufruf ueber "sudo -n" mit
// vollem Pfad (smartctl in /usr/sbin), SATA neben NVMe. Exit-Code-Bits (hier 4: ein Log nicht lesbar) verwerfen
// die Ausgabe nicht; eine schlafende Platte (Exit 2) meldet "standby".
func TestScriptSmartSATAViaSudo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("nur Linux")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("kein sh")
	}
	dir := t.TempDir()
	wd := string(readTestdata(t, "smart_ata_wd161kfgx.json"))
	sdc := strings.Replace(strings.Replace(wd, `"exit_status": 0`, `"exit_status": 4, "messages": [{"string": "Read SMART Error Log failed: scsi error aborted command", "severity": "error"}]`, 1),
		"2BJ9TESTX", "2BJ9TESTZ", 1)
	files := map[string]string{
		"sda.json": wd,
		"sdb.json": `{"json_format_version": [1, 0], "smartctl": {"version": [7, 3], "messages": [{"string": "Device is in STANDBY mode, exit(2)", "severity": "information"}], "exit_status": 2},
"device": {"name": "/dev/sdb", "info_name": "/dev/sdb [SAT]", "type": "sat", "protocol": "ATA"}}`,
		"sdc.json":   sdc,
		"nvme0.json": string(section(t, "script_proxmox8.txt", "smart:/dev/nvme0")),
		"smartctl": "#!/bin/sh\n" +
			"[ \"$M64_TEST_SUDO\" = 1 ] || { echo 'ohne sudo' >&2; exit 1; }\n" +
			"case \"$*\" in\n-V) echo 'smartctl 7.3'; exit 0 ;;\n" +
			"--scan-open) printf '%s\\n' '/dev/sda -d sat # /dev/sda [SAT], ATA device' '/dev/sdb -d sat # /dev/sdb [SAT], ATA device' " +
			"'/dev/sdc -d sat # /dev/sdc [SAT], ATA device' '/dev/nvme0 -d nvme # /dev/nvme0, NVMe device'; exit 0 ;;\nesac\n" +
			"for a; do dev=$a; done\n" +
			"case \"$*\" in *'-j -a -n standby -d '*) ;; *) exit 1 ;; esac\n" +
			"case $dev in\n" +
			"/dev/sda) cat " + dir + "/sda.json; exit 0 ;;\n" +
			"/dev/sdb) cat " + dir + "/sdb.json; exit 2 ;;\n" +
			"/dev/sdc) cat " + dir + "/sdc.json; exit 4 ;;\n" +
			"/dev/nvme0) cat " + dir + "/nvme0.json; exit 0 ;;\nesac\nexit 1\n",
		// sudo -n wie mit NOPASSWD-Zeile in sudoers
		"sudo": "#!/bin/sh\n[ \"$1\" = -n ] || exit 1\nshift\nM64_TEST_SUDO=1\nexport M64_TEST_SUDO\nexec \"$@\"\n",
	}
	for name, body := range files {
		mode := os.FileMode(0o644)
		if !strings.HasSuffix(name, ".json") {
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	script := Script
	for _, r := range [][2]string{
		{"for m64_p in /usr/sbin/smartctl ", "for m64_p in " + dir + "/smartctl /usr/sbin/smartctl "},
		{`[ "$(id -u 2>/dev/null)" = 0 ] && m64_root=1`, ":"}, // immer als normaler Benutzer
		{`sudo -n "$m64_sc"`, dir + `/sudo -n "$m64_sc"`},
		{"! m64_have sudo;", "! m64_have " + dir + "/sudo;"},
	} {
		if strings.Count(script, r[0]) != 1 {
			t.Fatalf("Skript: %q nicht genau einmal gefunden", r[0])
		}
		script = strings.Replace(script, r[0], r[1], 1)
	}
	cmd := exec.Command(sh, "-s", "--", ScriptArgSmart)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v", err)
	}
	r, err := ParseScriptOutput(out, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range r.Notes {
		if n.Section == "smart" {
			t.Errorf("Hinweis %+v", n)
		}
	}
	if len(r.SMART) != 4 {
		t.Fatalf("SMART %+v", r.SMART)
	}
	by := map[string]int{}
	for i, s := range r.SMART {
		by[s.Device] = i
	}
	for _, dev := range []string{"/dev/sda", "/dev/sdc"} {
		s := r.SMART[by[dev]]
		if s.Error != "" || s.Passed == nil || !*s.Passed || s.TempC == nil || *s.TempC != 37 || len(s.Attrs) != 18 || s.Pending == nil {
			t.Errorf("%s: %+v", dev, s)
		}
	}
	if s := r.SMART[by["/dev/sdb"]]; s.Error != SmartErrStandby {
		t.Errorf("sdb: %+v", s)
	}
	if s := r.SMART[by["/dev/nvme0"]]; s.Error != "" || s.Type != "nvme" || s.TempC == nil || *s.TempC != 42 {
		t.Errorf("nvme0: %+v", s)
	}
}
