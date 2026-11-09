//go:build windows

package m64agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
)

// Eigene Skripte unter Windows folgen in Phase 2 (Pruefung der Dateirechte ueber ACLs).
var errLocalWindows = errors.New("local scripts are not supported on Windows yet")

func checkDir(string) error { return errLocalWindows }

func checkScript(string) (string, error) { return "", errLocalWindows }

func openScript(string) (*os.File, error) { return nil, errLocalWindows }

func scriptCmd(ctx context.Context, _ *os.File, real string) *exec.Cmd {
	return exec.CommandContext(ctx, real)
}

func prepareCmd(*exec.Cmd) {}

func localEnv() []string { return nil }
