//go:build freebsd

package main

import (
	"bytes"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/ipv64net/node64/internal/m64agent"
	"github.com/ipv64net/node64/internal/m64bsd"
	"github.com/ipv64net/node64/internal/m64proto"
)

// Ablage. Die Datei liegt wie unter Linux in einem eigenen Ordner: update schreibt neben die Programmdatei
// (<datei>.old, .update, .failed, .new-*), das soll nicht in /usr/local/sbin landen. Dort steht nur ein Verweis; ihn
// ruft das rc.d-Skript auf (eine von Hand nach /usr/local/sbin kopierte Datei laeuft damit weiter).
const (
	libDir  = "/usr/local/libexec/monitor64-agent"
	libBin  = libDir + "/monitor64-agent"
	binLink = "/usr/local/sbin/monitor64-agent"
)

// rcScript ist das rc.d-Skript (daemon(8) startet den Agent nach einem Absturz neu).
//
//go:embed rc.d/monitor64_agent
var rcScript []byte

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
	platform, _, _ := m64bsd.HostInfo()
	flavor := bsdFlavor(platform, func(p string) bool { _, err := os.Stat(p); return err == nil })
	rcFile, rcOther := bsdRCFile(flavor)
	say("system: %s", platform)

	// Ordner und Schluessel (Systemordner nur anlegen, ihre Rechte bleiben)
	for _, d := range []string{defaultDir, filepath.Join(defaultDir, "local.d")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		_ = os.Chmod(d, 0o700)
	}
	for _, d := range []string{libDir, filepath.Dir(binLink), bsdRCDir, filepath.Dir(bsdRCConf)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	_ = os.Chmod(libDir, 0o755)
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

	// Dienst: laufenden anhalten (auch unter dem anderen Dateinamen), Skript und Schalter schreiben, starten
	stopService(rcFile, rcOther)
	_ = os.Remove(rcOther)
	if err := writeFileMode(rcFile, rcScript, 0o555); err != nil {
		return err
	}
	old, err := os.ReadFile(bsdRCConf)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeFileMode(bsdRCConf, []byte(setRCVars(string(old), bsdRCVars(port, pf.noListen))), 0o644); err != nil {
		return err
	}
	if out, err := rcCommand(rcFile, "start"); err != nil {
		return fmt.Errorf("%s start: %v: %s", rcFile, err, out)
	}
	if err := waitRunning(rcFile); err != nil {
		return err
	}
	if pf.noListen {
		say("service %s started (push only, not listening)", filepath.Base(rcFile))
	} else {
		say("service %s started (port %d/tcp)", filepath.Base(rcFile), port)
	}
	for _, h := range bsdHints(flavor, port, pf.noListen, rcFile) {
		say("NOTE: %s", h)
	}
	fmt.Println()
	say("host key fingerprint (compare it in Node64):")
	fmt.Println("  " + m64agent.Fingerprint(hk.PublicKey()))
	return nil
}

// writeFileMode schreibt eine Datei neu (neben dem Ziel anlegen, dann umbenennen) und setzt die Rechte.
func writeFileMode(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".monitor64-agent.new-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// rcCommand ruft das rc.d-Skript mit sauberer Umgebung auf (wie service(8): der Dienst soll nicht die Umgebung der
// Anmeldung erben, aus der install gestartet wurde). WaitDelay: ein gestarteter Dienst, der die Ausgabe offen
// haelt (aelteres rc.d-Skript ohne daemon -f), darf install nicht aufhalten.
func rcCommand(rcFile, action string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command(rcFile, action)
	cmd.Env = []string{"HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"}
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.WaitDelay = 3 * time.Second
	err := cmd.Run()
	if errors.Is(err, exec.ErrWaitDelay) {
		err = nil
	}
	return string(bytes.TrimSpace(out.Bytes())), err
}

// stopService haelt den Dienst an, falls er laeuft (onestop: auch wenn er nicht eingeschaltet ist).
func stopService(rcFiles ...string) {
	for _, f := range rcFiles {
		if _, err := os.Stat(f); err == nil {
			_, _ = rcCommand(f, "onestop")
		}
	}
}

// waitRunning wartet kurz, bis der Dienst laeuft (daemon(8) legt die PID-Datei an).
func waitRunning(rcFile string) error {
	var out string
	var err error
	for i := 0; i < 15; i++ {
		if out, err = rcCommand(rcFile, "status"); err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("service did not start (%s) - see the system log, tag monitor64-agent", out)
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
	rcFile, rcOther := bsdRCFile(bsdPlain)
	stopService(rcFile, rcOther)
	for _, f := range []string{rcFile, rcOther, bsdRCConf} {
		_ = os.Remove(f)
	}
	if cur, err := os.Readlink(binLink); err == nil && cur == libBin {
		_ = os.Remove(binLink)
	}
	_ = os.RemoveAll(libDir)
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
