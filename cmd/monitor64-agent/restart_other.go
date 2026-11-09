//go:build !unix

package main

import (
	"errors"
	"runtime"
)

// restartSelf: unter Windows startet der Dienst-Manager neu (Phase 2).
func restartSelf(string) error {
	return errors.New("restart not supported on " + runtime.GOOS)
}
