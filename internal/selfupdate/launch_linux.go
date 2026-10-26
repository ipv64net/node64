//go:build linux

package selfupdate

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Launch ist der Starter: ganz am Anfang von main aufrufen (nur fuer den normalen Betrieb). Gibt es unter
// <data>/bin eine geprueft abgelegte Version, die neuer ist als imageVersion, ersetzt sich der Prozess durch sie
// (exec, die Rechte des Image-Programms werden als "ambient" weitergereicht). Sonst kehrt Launch zurueck und das
// Image-Programm laeuft weiter. Fehler werden nur auf stderr gemeldet.
func Launch(dataDir, imageVersion string) {
	if os.Getenv(envChild) != "" || dataDir == "" {
		return
	}
	v, path := choose(dataDir, imageVersion)
	if path == "" {
		return
	}
	self, _ := os.Executable()
	env := append(withoutEnv(os.Environ(), envChild, envImage, envImageVersion),
		envChild+"="+v, envImage+"="+self, envImageVersion+"="+imageVersion)
	if err := execWithCaps(path, env); err != nil {
		fmt.Fprintf(os.Stderr, "node64: self-update %s could not be started (%v), running the image version %s\n", v, err, imageVersion)
	}
}

// Reexec startet das Image-Programm neu (nach einem Update oder zum Zuruecksetzen); der Starter waehlt dann die
// Version. Kehrt nur bei einem Fehler zurueck.
func Reexec() error {
	bin := os.Getenv(envImage)
	if bin == "" {
		bin, _ = os.Executable()
	}
	env := withoutEnv(os.Environ(), envChild, envImage, envImageVersion)
	runtime.LockOSThread()
	return unix.Exec(bin, os.Args, env)
}

// execWithCaps: erlaubte Capabilities des Image-Programms (Datei-Capabilities) vererbbar machen und als "ambient"
// setzen, damit das Programm aus <data>/bin (ohne Datei-Capabilities) Ports unter 1024 und ICMP behaelt; dann exec.
// Ist <data> mit noexec eingebunden, ueber memfd (Programm im Speicher).
func execWithCaps(path string, env []string) error {
	runtime.LockOSThread() // Capabilities und exec gelten fuer diesen Thread
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err == nil {
		data[0].Inheritable, data[1].Inheritable = data[0].Permitted, data[1].Permitted
		if unix.Capset(&hdr, &data[0]) == nil {
			for _, c := range []uintptr{unix.CAP_NET_BIND_SERVICE, unix.CAP_NET_RAW, unix.CAP_NET_ADMIN} {
				if data[0].Permitted&(1<<c) != 0 {
					_ = unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, c, 0, 0)
				}
			}
		}
	}
	err := unix.Exec(path, os.Args, env)
	if !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EPERM) {
		return err
	}
	// noexec: Programm in ein memfd kopieren und von dort starten
	b, rerr := os.ReadFile(path)
	if rerr != nil {
		return err
	}
	fd, merr := unix.MemfdCreate("node64", 0)
	if merr != nil {
		return fmt.Errorf("%v; memfd: %w", err, merr)
	}
	if _, werr := unix.Write(fd, b); werr != nil {
		return fmt.Errorf("%v; memfd write: %w", err, werr)
	}
	return unix.Exec(fmt.Sprintf("/proc/self/fd/%d", fd), os.Args, env)
}

func withoutEnv(env []string, keys ...string) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		drop := false
		for _, k := range keys {
			if strings.HasPrefix(e, k+"=") {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, e)
		}
	}
	return out
}
