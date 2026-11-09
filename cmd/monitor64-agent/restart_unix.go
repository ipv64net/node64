//go:build unix

package main

import (
	"os"
	"syscall"
)

// restartSelf ersetzt den laufenden Prozess durch die (neue) Programmdatei - gleiche Prozessnummer, gleiche
// Argumente; klappt auch ohne systemd. Kehrt nur bei einem Fehler zurueck.
func restartSelf(exe string) error {
	return syscall.Exec(exe, os.Args, os.Environ())
}
