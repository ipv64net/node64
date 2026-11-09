//go:build windows

package m64agent

import (
	"errors"
	"os/exec"
)

// Eigene Skripte unter Windows folgen in Phase 2 (Pruefung der Dateirechte ueber ACLs).
var errLocalWindows = errors.New("local scripts are not supported on Windows yet")

func checkDir(string) error { return errLocalWindows }

func checkScript(string) error { return errLocalWindows }

func prepareCmd(*exec.Cmd) {}

func localEnv() []string { return nil }
