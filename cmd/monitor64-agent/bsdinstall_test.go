package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestBSDFlavor(t *testing.T) {
	for platform, want := range map[string]string{
		"OPNsense 25.1.5":         bsdOPNsense,
		"OPNsense 21.7.8":         bsdOPNsense,
		"pfSense 2.7.2-RELEASE":   bsdPfSense,
		"pfSense 24.11-RELEASE":   bsdPfSense,
		"TrueNAS-13.0-U6.1":       bsdTrueNAS,
		"FreeNAS-11.3-U5":         bsdTrueNAS,
		"FreeBSD 14.5-RELEASE-p3": bsdPlain,
		"FreeBSD":                 bsdPlain,
		"":                        bsdPlain,
	} {
		if got := bsdFlavor(platform, func(string) bool { return false }); got != want {
			t.Errorf("%q: %s statt %s", platform, got, want)
		}
	}
	// Versionsdateien unbekannt: Dateien, die es nur auf den Firewalls gibt
	only := func(paths ...string) func(string) bool {
		return func(p string) bool {
			for _, x := range paths {
				if x == p {
					return true
				}
			}
			return false
		}
	}
	if got := bsdFlavor("FreeBSD 15.0-CURRENT", only("/etc/pfSense-rc")); got != bsdPfSense {
		t.Errorf("pfSense-rc: %s", got)
	}
	if got := bsdFlavor("FreeBSD 14.3-RELEASE", only("/usr/local/etc/rc.freebsd", "/usr/local/opnsense")); got != bsdOPNsense {
		t.Errorf("rc.freebsd: %s", got)
	}
	if got := bsdFlavor("FreeBSD 14.3-RELEASE", only("/usr/local/opnsense")); got != bsdPlain {
		t.Errorf("nur Ordner: %s", got)
	}
}

func TestBSDRCFile(t *testing.T) {
	for _, f := range []string{bsdPlain, bsdOPNsense, bsdTrueNAS} {
		if file, other := bsdRCFile(f); file != "/usr/local/etc/rc.d/monitor64_agent" || other != file+".sh" {
			t.Errorf("%s: %s %s", f, file, other)
		}
	}
	// pfSense startet beim Hochfahren nur *.sh
	if file, other := bsdRCFile(bsdPfSense); file != "/usr/local/etc/rc.d/monitor64_agent.sh" || other != "/usr/local/etc/rc.d/monitor64_agent" {
		t.Errorf("pfSense: %s %s", file, other)
	}
	if bsdRCConf != "/etc/rc.conf.d/monitor64_agent" {
		t.Error(bsdRCConf)
	}
}

func TestSetRCVars(t *testing.T) {
	want := "monitor64_agent_enable=\"YES\"\nmonitor64_agent_port=\"6465\"\nmonitor64_agent_nolisten=\"NO\"\n"
	if got := setRCVars("", bsdRCVars(6465, false)); got != want {
		t.Fatalf("neu: %q", got)
	}
	// zweiter Lauf mit anderem Port und nur Push: eigene Zeilen ersetzt, fremde (auch auskommentierte) bleiben
	old := "# von Hand\r\nmonitor64_agent_args=\"--listen 192.168.1.1\"\r\n" + want + "#monitor64_agent_port=\"1\"\n\n\n"
	got := setRCVars(old, bsdRCVars(7000, true))
	if got != "# von Hand\nmonitor64_agent_args=\"--listen 192.168.1.1\"\n#monitor64_agent_port=\"1\"\n"+
		"monitor64_agent_enable=\"YES\"\nmonitor64_agent_port=\"7000\"\nmonitor64_agent_nolisten=\"YES\"\n" {
		t.Fatalf("ersetzt: %q", got)
	}
	if again := setRCVars(got, bsdRCVars(7000, true)); again != got {
		t.Fatalf("nicht stabil: %q", again)
	}
}

func TestBSDHints(t *testing.T) {
	join := func(flavor string, noListen bool) string {
		file, _ := bsdRCFile(flavor)
		return strings.Join(bsdHints(flavor, 6465, noListen, file), "\n")
	}
	for flavor, want := range map[string][]string{
		bsdPlain:    {"pf, ipfw", "TCP port 6465"},
		bsdOPNsense: {"Firewall > Rules", "TCP port 6465", "does not change rules", "OPNsense", "run the installer again"},
		bsdPfSense:  {"Firewall > Rules", "TCP port 6465", "/usr/local/etc/rc.d/monitor64_agent.sh", "ending in .sh"},
		bsdTrueNAS:  {"Post Init", "service monitor64_agent onestart", "run the installer again"},
	} {
		h := join(flavor, false)
		for _, w := range want {
			if !strings.Contains(h, w) {
				t.Errorf("%s: %q fehlt in:\n%s", flavor, w, h)
			}
		}
		// nur Push: kein offener Port, also kein Hinweis auf die Firewall
		if p := join(flavor, true); strings.Contains(p, "6465") || strings.Contains(p, "Firewall >") {
			t.Errorf("%s nur Push: %s", flavor, p)
		}
	}
	if h := join(bsdTrueNAS, false); strings.Contains(h, "Firewall") || strings.Contains(h, "ipfw") {
		t.Errorf("TrueNAS: %s", h)
	}
}

// Das rc.d-Skript muss zu install passen: Pfad des Programms, die gesetzten Variablen, daemon -f (sonst haengt der
// Start aus install/SSH), und genau je eine Zeile name=/rcvar= (OPNsense liest sie beim Hochfahren mit grep).
func TestRCScript(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("rc.d", "monitor64_agent"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "\r") || !strings.HasPrefix(s, "#!/bin/sh\n") {
		t.Fatal("Zeilenenden bzw. Kopfzeile")
	}
	for _, want := range []string{"# PROVIDE: monitor64_agent\n", "# REQUIRE: LOGIN NETWORKING\n", ". /etc/rc.subr\n",
		"load_rc_config $name\n", `monitor64_agent_bin="/usr/local/sbin/monitor64-agent"`, `command="/usr/sbin/daemon"`,
		`command_args="-f -r -R 5 -S -T monitor64-agent -P ${pidfile} ${monitor64_agent_bin} run --port ${monitor64_agent_port} --dir ${monitor64_agent_dir} ${monitor64_agent_args}"`,
		"checkyesno monitor64_agent_nolisten", `monitor64_agent_args="--no-listen ${monitor64_agent_args}"`,
		`: ${monitor64_agent_dir:="/usr/local/etc/monitor64-agent"}`, `run_rc_command "$1"`} {
		if !strings.Contains(s, want) {
			t.Errorf("rc.d-Skript ohne %q", want)
		}
	}
	for _, v := range bsdRCVars(6465, true) {
		if !strings.Contains(s, ": ${"+v[0]+":=") {
			t.Errorf("rc.d-Skript kennt %s nicht", v[0])
		}
	}
	for re, want := range map[string]string{`(?m)^name[ \t]*=.*$`: `name="monitor64_agent"`, `(?m)^rcvar[ \t]*=.*$`: `rcvar="monitor64_agent_enable"`} {
		if got := regexp.MustCompile(re).FindAllString(s, -1); len(got) != 1 || got[0] != want {
			t.Errorf("%s: %q", re, got)
		}
	}
}

// fakeTools legt einen Ordner mit nachgebauten Programmen an (uname, id, Download, Pruefsumme) und Verweisen auf die
// echten Hilfsprogramme, die install.sh braucht. PATH besteht nur aus diesem Ordner: curl, wget und sha256sum des
// Test-Systems sind damit nicht sichtbar.
func fakeTools(t *testing.T, scripts map[string]string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"sh", "mkdir", "chmod", "mktemp", "rm", "awk", "grep", "cp", "cat"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s fehlt: %v", tool, err)
		}
		if tool == "mkdir" { // der Test legt nichts unter /usr/local an (install.sh weicht dann nach /var/tmp aus)
			scripts[tool] = `case "$*" in */usr/local/*) exit 1 ;; esac; exec '` + p + `' "$@"`
			continue
		}
		if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return bin
}

// runInstallSh startet install.sh mit den nachgebauten Programmen. Die "heruntergeladene" Programmdatei ist ein Skript,
// das seine Argumente nach <dir>/args schreibt.
func runInstallSh(t *testing.T, osName, machine, file string, tools map[string]string, args ...string) (out, called string, err error) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("braucht eine POSIX-Shell")
	}
	sum, lerr := exec.LookPath("sha256sum")
	if lerr != nil {
		if sum, lerr = exec.LookPath("sha256"); lerr != nil { // FreeBSD < 14
			t.Skip("sha256sum fehlt")
		}
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "www")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	agent := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + filepath.Join(dir, "args") + "'\n"
	if err := os.WriteFile(filepath.Join(src, file), []byte(agent), 0o644); err != nil {
		t.Fatal(err)
	}
	sumOut, serr := exec.Command(sum, filepath.Join(src, file)).Output()
	if serr != nil {
		t.Fatal(serr)
	}
	hash := ""
	for _, f := range strings.Fields(string(sumOut)) { // "<hash>  datei" bzw. "SHA256 (datei) = <hash>"
		if len(f) == 64 {
			hash = f
		}
	}
	sums := hash + "  " + file + "\n" + strings.Repeat("0", 64) + "  monitor64-agent-other\n"
	if err := os.WriteFile(filepath.Join(src, "SHA256SUMS"), []byte(sums), 0o644); err != nil {
		t.Fatal(err)
	}
	scripts := map[string]string{
		"uname": `case "$1" in -s) echo ` + osName + ` ;; -m) echo ` + machine + ` ;; esac`,
		"id":    "echo 0",
	}
	// Download: letztes Argument ist die Adresse; die Datei kommt aus dem Ordner www
	get := `for a in "$@"; do url=$a; done; printf '%s\n' "$*" >> '` + filepath.Join(dir, "downloads") + `'; cp '` + src + `'/"${url##*/}" "$OUT"`
	for name, body := range tools {
		switch body {
		case "fetch": // fetch -v -T 10 -o DATEI URL
			body = `OUT=$5; ` + get
		case "curl": // curl ... -o DATEI URL
			body = `prev=; for a in "$@"; do [ "$prev" = -o ] && OUT=$a; prev=$a; done; ` + get
		case "sha256": // sha256 -q DATEI
			body = `[ "$1" = -q ] || exit 2; '` + sum + `' "$2" | awk '{ for (i = 1; i <= NF; i++) if (length($i) == 64) print $i }'`
		case "sha256sum":
			body = `printf '%s  %s\n' "$('` + sum + `' "$1" | awk '{ for (i = 1; i <= NF; i++) if (length($i) == 64) print $i }')" "$1"`
		}
		scripts[name] = body
	}
	bin := fakeTools(t, scripts)
	cmd := exec.Command(filepath.Join(bin, "sh"), append([]string{"install.sh"}, args...)...)
	cmd.Env = []string{"PATH=" + bin, "TMPDIR=" + dir}
	b, err := cmd.CombinedOutput()
	a, _ := os.ReadFile(filepath.Join(dir, "args"))
	dl, _ := os.ReadFile(filepath.Join(dir, "downloads"))
	return string(b) + string(dl), string(a), err
}

// install.sh unter FreeBSD: fetch und sha256 aus dem Grundsystem, Datei monitor64-agent-freebsd-<arch>, danach
// "monitor64-agent install" mit denselben Optionen wie unter Linux.
func TestInstallShFreeBSD(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETckeS39th4eGsSzZlxN5qpGWW+u7VErd1nfg8mRDnw node64@nas"
	bsd := map[string]string{"fetch": "fetch", "sha256": "sha256"}
	out, called, err := runInstallSh(t, "FreeBSD", "amd64", "monitor64-agent-freebsd-amd64", bsd,
		"--key", key, "--base", "https://node.example/agent")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if called != "install\n--key\n"+key+"\n" {
		t.Fatalf("Aufruf: %q\n%s", called, out)
	}
	for _, want := range []string{"downloading https://node.example/agent/monitor64-agent-freebsd-amd64", "checksum ok",
		"-v -T 10 -o ", "https://node.example/agent/SHA256SUMS"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q fehlt in:\n%s", want, out)
		}
	}
	// arm64 (uname -m meldet arm64, uname -p aarch64), Push mit zwei Nodes und eigenem Port
	out, called, err = runInstallSh(t, "FreeBSD", "arm64", "monitor64-agent-freebsd-arm64", bsd, "--key="+key, "--port", "7000",
		"--connect", "tok1234567890abcdef@node.example:6466", "--connect=tok1234567890abcdef@[2001:db8::1]:6466", "--no-listen")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if want := "install\n--key\n" + key + "\n--port\n7000\n--connect\ntok1234567890abcdef@node.example:6466\n--connect\ntok1234567890abcdef@[2001:db8::1]:6466\n--no-listen\n"; called != want {
		t.Fatalf("Aufruf: %q\n%s", called, out)
	}
	if !strings.Contains(out, "https://node64.de/agent/monitor64-agent-freebsd-arm64") {
		t.Errorf("Standard-Adresse: %s", out)
	}
	// falsche Pruefsumme: die Datei wird nicht gestartet
	out, called, err = runInstallSh(t, "FreeBSD", "amd64", "monitor64-agent-freebsd-amd64",
		map[string]string{"fetch": "fetch", "sha256": "echo " + strings.Repeat("1", 64)}, "--key", key)
	if err == nil || called != "" || !strings.Contains(out, "checksum mismatch") {
		t.Fatalf("falsche Pruefsumme: %v %q\n%s", err, called, out)
	}
	// nicht unterstuetzt: FreeBSD auf armv7, andere Systeme
	if out, called, err = runInstallSh(t, "FreeBSD", "armv7", "x", bsd, "--key", key); err == nil || called != "" || !strings.Contains(out, "unsupported architecture on FreeBSD") {
		t.Fatalf("armv7: %v %q\n%s", err, called, out)
	}
	if out, called, err = runInstallSh(t, "Darwin", "arm64", "x", bsd, "--key", key); err == nil || called != "" || !strings.Contains(out, "only Linux and FreeBSD") {
		t.Fatalf("Darwin: %v %q\n%s", err, called, out)
	}
}

// Unter Linux bleibt alles beim Alten: curl, sha256sum, Datei monitor64-agent-linux-<arch>.
func TestInstallShLinux(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETckeS39th4eGsSzZlxN5qpGWW+u7VErd1nfg8mRDnw node64@nas"
	for machine, arch := range map[string]string{"x86_64": "amd64", "aarch64": "arm64", "armv7l": "armv7"} {
		out, called, err := runInstallSh(t, "Linux", machine, "monitor64-agent-linux-"+arch,
			map[string]string{"curl": "curl", "sha256sum": "sha256sum"}, "--key", key)
		if err != nil || called != "install\n--key\n"+key+"\n" {
			t.Fatalf("%s: %v %q\n%s", machine, err, called, out)
		}
		if !strings.Contains(out, "--proto =https --proto-redir =https") || !strings.Contains(out, "https://node64.de/agent/monitor64-agent-linux-"+arch) {
			t.Errorf("%s: %s", machine, out)
		}
	}
}
