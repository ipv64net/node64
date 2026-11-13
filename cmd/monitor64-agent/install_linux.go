//go:build linux

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/m64agent"
	"github.com/ipv64net/node64/internal/m64proto"
)

// Ablage. Die Datei liegt in einem eigenen Ordner (nur der ist fuer update schreibbar), /usr/local/bin enthaelt
// einen Verweis darauf.
const (
	libDir   = "/usr/local/lib/monitor64-agent"
	libBin   = libDir + "/monitor64-agent"
	binLink  = "/usr/local/bin/monitor64-agent"
	unitName = "monitor64-agent.service"
	unitPath = "/etc/systemd/system/" + unitName
	stateDir = "/var/lib/monitor64-agent" // HOME der eigenen Skripte (StateDirectory)
)

// unitFile ist der systemd-Dienst. Root ist noetig (SMART, alle Dateisysteme); die Haertung beschraenkt Schreibzugriffe
// auf Einstellungen (keys), den eigenen Programmordner (update, <datei>.old) und /var/lib/monitor64-agent (HOME der
// eigenen Skripte). Paket-Caches nur fuer die Update-Pruefung; zypper braucht dazu noch /run (Sperrdatei
// /run/zypp.pid, siehe zypperPaths). /home und /root sind nur lesbar: eigene Skripte koennen Zugangsdateien wie
// /root/.my.cnf lesen (mit vollem Pfad, z. B. mysql --defaults-extra-file=/root/.my.cnf), aber nichts dort aendern.
// Restart=always startet den Agent nach einem Absturz neu; nach einem Update startet er sich selbst neu (exec).
// UnsetEnvironment=GODEBUG: manche Systeme setzen GODEBUG fuer alle Dienste (UGOS von Ugreen: tlskyber=0 in
// /etc/systemd/system.conf); einen dort inzwischen entfernten Schalter quittiert die Go-Laufzeit mit Abbruch beim Start.
const unitFile = `[Unit]
Description=Monitor64-Agent (Node64)
Documentation=https://node64.de/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=` + libBin + ` run --port %d%s
Restart=always
RestartSec=5
UnsetEnvironment=GODEBUG
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
StateDirectory=monitor64-agent
StateDirectoryMode=0700
ReadWritePaths=` + defaultDir + ` ` + libDir + `
ReadWritePaths=-/var/cache/dnf -/var/cache/libdnf5 -/var/cache/yum -/var/cache/zypp
%sProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
`

// zypperPaths: zypper legt bei jeder Abfrage /run/zypp.pid an (Sperre) und schreibt /var/log/zypper.log. Eine
// einzelne, noch nicht vorhandene Datei laesst sich nicht freigeben, deshalb /run - nur, wenn zypper da ist.
const zypperPaths = "ReadWritePaths=/run -/var/log/zypper.log\n"

// unitText baut den Dienst fuer den Port (zypper-Pfade nur, wenn zypper installiert ist).
func unitText(port int, zypper bool) string { return unitTextPush(port, zypper, false) }

// unitTextPush: wie unitText; noListen = nur Push (die Ziele stehen in <dir>/connect, nicht in der Befehlszeile:
// der Token soll nicht fuer alle Benutzer lesbar sein).
func unitTextPush(port int, zypper, noListen bool) string {
	extra, nl := "", ""
	if zypper {
		extra = zypperPaths
	}
	if noListen {
		nl = " --no-listen"
	}
	return fmt.Sprintf(unitFile, port, nl, extra)
}

func install(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	key := fs.String("key", "", `public key of the node ("ssh-ed25519 AAAA... comment")`)
	port := fs.Int("port", m64proto.DefaultPort, "TCP port")
	var pf pushFlags
	pf.register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := doInstall(*key, *port, pf); err != nil {
		fmt.Fprintln(os.Stderr, "monitor64-agent: ERROR:", err)
		return 1
	}
	return 0
}

func doInstall(key string, port int, pf pushFlags) error {
	key, err := checkInstallArgs(key, port)
	if err != nil {
		return err
	}
	connectPath := filepath.Join(defaultDir, m64agent.PushFile)
	if pf.noListen && len(pf.connect) == 0 {
		if t, _ := m64agent.ReadPushFile(connectPath); len(t) == 0 {
			return errors.New("--no-listen needs --connect token@node[:port]")
		}
	}
	if os.Geteuid() != 0 {
		return errors.New("please run as root")
	}
	systemd := haveSystemd()

	// Ordner und Schluessel
	for _, d := range []string{defaultDir, filepath.Join(defaultDir, "local.d"), libDir, stateDir} {
		mode := os.FileMode(0o700)
		if d == libDir {
			mode = 0o755
		}
		if err := os.MkdirAll(d, mode); err != nil {
			return err
		}
		_ = os.Chmod(d, mode)
	}
	keysPath := filepath.Join(defaultDir, "keys")
	added, err := addKey(keysPath, key)
	if err != nil {
		return err
	}
	if added {
		say("key added to %s", keysPath)
	} else {
		say("key already in %s", keysPath)
	}
	if err := writePushTargets(connectPath, pf.connect); err != nil {
		return err
	}

	// Programmdatei
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return err
	}
	if fi1, e1 := os.Stat(self); e1 == nil {
		if fi2, e2 := os.Stat(libBin); e2 != nil || !os.SameFile(fi1, fi2) {
			if err := copyFile(self, libBin, 0o755); err != nil {
				return fmt.Errorf("copy program: %w", err)
			}
		}
	}
	if cur, err := os.Readlink(binLink); err != nil || cur != libBin {
		_ = os.Remove(binLink)
		if err := os.Symlink(libBin, binLink); err != nil {
			return fmt.Errorf("link %s: %w", binLink, err)
		}
	}
	say("program installed: %s", libBin)
	selinuxLabel()

	// Hostschluessel (vor dem Start, damit der Fingerabdruck sicher feststeht)
	hk, err := m64agent.LoadOrCreateHostKey(filepath.Join(defaultDir, "hostkey"))
	if err != nil {
		return err
	}

	// Dienst
	if systemd {
		_, zerr := exec.LookPath("zypper")
		if err := os.WriteFile(unitPath, []byte(unitTextPush(port, zerr == nil, pf.noListen)), 0o644); err != nil {
			return err
		}
		for _, a := range [][]string{{"daemon-reload"}, {"enable", unitName}, {"restart", unitName}} {
			if out, err := exec.Command("systemctl", a...).CombinedOutput(); err != nil {
				return fmt.Errorf("systemctl %s: %v: %s", strings.Join(a, " "), err, bytes.TrimSpace(out))
			}
		}
		if err := serviceRuns(); err != nil {
			return err
		}
		if pf.noListen {
			say("service %s started (push only, not listening)", unitName)
		} else {
			say("service %s started (port %d/tcp)", unitName, port)
		}
	} else {
		say("WARNING: systemd not found - start the agent yourself: %s run --port %d", libBin, port)
	}
	fmt.Println()
	say("host key fingerprint (compare it in Node64):")
	fmt.Println("  " + m64agent.Fingerprint(hk.PublicKey()))
	return nil
}

// serviceRuns prueft kurz nach dem Start, ob der Dienst laeuft. systemd meldet den Start auch dann als gelungen,
// wenn das Programm sofort abbricht (Neustart-Schleife) – dann hier ein klarer Fehler mit den letzten Log-Zeilen.
func serviceRuns() error {
	time.Sleep(2 * time.Second)
	if exec.Command("systemctl", "is-active", "--quiet", unitName).Run() == nil {
		return nil
	}
	time.Sleep(2 * time.Second) // einmal nachfassen (langsame Systeme)
	if exec.Command("systemctl", "is-active", "--quiet", unitName).Run() == nil {
		return nil
	}
	log, _ := exec.Command("journalctl", "-u", unitName, "-n", "8", "--no-pager", "-o", "cat").CombinedOutput()
	return fmt.Errorf("service %s does not stay up - last log lines:\n%s\nmore: journalctl -u %s", unitName, bytes.TrimSpace(log), unitName)
}

// selinuxOn: SELinux ist auf diesem System eingeschaltet.
func selinuxOn() bool {
	_, err := os.Stat("/sys/fs/selinux/enforce")
	return err == nil
}

// selinuxLabel kennzeichnet den Programmordner als bin_t. Unter SELinux (Fedora, RHEL, Rocky ...) laeuft ein Dienst,
// dessen Programm das Etikett lib_t traegt (Standard unter /usr/local/lib), im engen Bereich init_t und darf seinen
// Ordner nicht beschreiben – das automatische Update scheitert mit "permission denied". Mit bin_t startet systemd
// ihn wie andere fremde Dienste (unconfined_service_t); neue Dateien im Ordner erben das Etikett. Ohne semanage
// bleibt chcon (haelt bis zu einer Neu-Etikettierung des Dateisystems). Alles nach bestem Bemuehen.
func selinuxLabel() {
	if !selinuxOn() {
		return
	}
	pat := libDir + "(/.*)?"
	if sm, err := exec.LookPath("semanage"); err == nil {
		if exec.Command(sm, "fcontext", "-a", "-t", "bin_t", pat).Run() != nil {
			_ = exec.Command(sm, "fcontext", "-m", "-t", "bin_t", pat).Run()
		}
		if rc, err := exec.LookPath("restorecon"); err == nil && exec.Command(rc, "-R", libDir).Run() == nil {
			say("SELinux: %s labelled bin_t (semanage fcontext)", libDir)
			return
		}
	}
	if cc, err := exec.LookPath("chcon"); err == nil && exec.Command(cc, "-R", "-t", "bin_t", libDir).Run() == nil {
		say("SELinux: %s labelled bin_t (chcon - lasts until the file system is relabelled; install policycoreutils-python-utils for semanage)", libDir)
		return
	}
	say("WARNING: SELinux is on but %s could not be labelled bin_t - automatic updates may be denied", libDir)
}

func haveSystemd() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	fi, err := os.Stat("/run/systemd/system")
	return err == nil && fi.IsDir()
}

func uninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "monitor64-agent: ERROR: please run as root")
		return 1
	}
	if haveSystemd() {
		_ = exec.Command("systemctl", "disable", "--now", unitName).Run()
	}
	_ = os.Remove(unitPath)
	if haveSystemd() {
		_ = exec.Command("systemctl", "daemon-reload").Run()
	}
	if cur, err := os.Readlink(binLink); err == nil && cur == libBin {
		_ = os.Remove(binLink)
	}
	_ = os.RemoveAll(libDir)
	_ = os.RemoveAll(stateDir)
	if p, err := exec.LookPath("semanage"); err == nil && selinuxOn() {
		_ = exec.Command(p, "fcontext", "-d", libDir+"(/.*)?").Run()
	}
	for _, f := range []string{"keys", "hostkey", m64agent.PushFile} {
		_ = os.Remove(filepath.Join(defaultDir, f))
	}
	local := filepath.Join(defaultDir, "local.d")
	if ents, err := os.ReadDir(local); err == nil && len(ents) > 0 {
		say("kept %s (contains your own scripts) - remove it yourself if no longer needed", local)
	} else {
		_ = os.Remove(local)
		_ = os.Remove(defaultDir)
	}
	say("removed")
	return 0
}
