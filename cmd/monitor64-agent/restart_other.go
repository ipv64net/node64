//go:build !unix && !windows

package main

import (
	"errors"
	"runtime"
)

// restartSelf: auf anderen Systemen (weder Unix noch Windows) kein Neustart.
func restartSelf(string) error {
	return errors.New("restart not supported on " + runtime.GOOS)
}
