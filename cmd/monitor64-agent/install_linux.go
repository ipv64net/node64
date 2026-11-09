//go:build linux

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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

func say(format string, a ...any) { fmt.Printf("monitor64-agent: "+format+"\n", a...) }

func doInstall(key string, port int, pf pushFlags) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New(`--key is missing (public key of the node)`)
	}
	if n, err := m64agent.ParseKeys([]byte(key)); err != nil || n != 1 {
		if err == nil {
			err = errors.New("exactly one key expected")
		}
		return fmt.Errorf("--key: %w", err)
	}
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
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

// writePushTargets nimmt die Ziele aus --connect in <dir>/connect auf (gleiche Adresse = neuer Token).
func writePushTargets(path string, add []m64agent.PushTarget) error {
	if len(add) == 0 {
		return nil
	}
	old, err := m64agent.ReadPushFile(path)
	if err != nil {
		say("WARNING: %v - file replaced", err)
		old = nil
	}
	all, err := m64agent.AddPushTargets(old, add)
	if err != nil {
		return fmt.Errorf("--connect: %w", err)
	}
	if err := m64agent.WritePushFile(path, all); err != nil {
		return err
	}
	for _, t := range add {
		say("connects to node %s (push, %s)", t.String(), path)
	}
	return nil
}

// addKey haengt den Schluessel an die Liste an, falls er fehlt.
func addKey(path, key string) (bool, error) {
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	// Vergleich ueber den Schluessel selbst (Kommentar und Optionen egal)
	newBlob := keyBlob(key)
	for _, line := range strings.Split(string(old), "\n") {
		if b := keyBlob(line); b != "" && b == newBlob {
			return false, nil
		}
	}
	data := strings.TrimRight(string(old), "\n")
	if data != "" {
		data += "\n"
	}
	data += key + "\n"
	if _, err := m64agent.ParseKeys([]byte(data)); err != nil {
		// Vorhandene Liste fehlerhaft: neuen Schluessel trotzdem aufnehmen, kaputte Zeilen bleiben (Agent ueberspringt sie).
		say("WARNING: %s contains invalid lines: %v", path, err)
	}
	return true, m64agent.WriteKeysFile(path, []byte(data))
}

// keyBlob liefert "art schluessel" einer authorized_keys-Zeile ("" wenn keiner erkannt).
func keyBlob(line string) string {
	f := strings.Fields(line)
	for i := 0; i+1 < len(f); i++ {
		if strings.HasPrefix(f[i], "ssh-") || strings.HasPrefix(f[i], "ecdsa-") || strings.HasPrefix(f[i], "sk-") {
			return f[i] + " " + f[i+1]
		}
	}
	return ""
}

// copyFile kopiert atomar (neue Datei daneben, dann umbenennen - klappt auch, wenn der Dienst die Datei gerade nutzt).
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".monitor64-agent.new-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
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
