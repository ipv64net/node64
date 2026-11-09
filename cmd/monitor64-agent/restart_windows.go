//go:build windows

package main

import (
	"os"
	"os/exec"
)

// exitRestart ist der Rueckgabewert, mit dem sich der Dienst fuer einen Neustart beendet.
const exitRestart = 3

// exitFn beendet den Prozess (Tests setzen einen Ersatz).
var exitFn = os.Exit

// restartSelf startet die (neue) Programmdatei. Als Dienst beendet sich der Prozess ohne Abmeldung beim
// Dienst-Manager; dessen Wiederherstellung ("Neu starten", von install gesetzt) startet den Dienst mit der Datei neu,
// die jetzt unter exe liegt. Im Vordergrund startet er die Datei mit denselben Argumenten und Ein-/Ausgaben und
// beendet sich. Kehrt nur bei einem Fehler zurueck.
func restartSelf(exe string) error {
	if asService.Load() {
		if logDone != nil {
			logDone()
		}
		exitFn(exitRestart)
		return nil
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	exitFn(0)
	return nil
}
