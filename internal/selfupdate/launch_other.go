//go:build !linux

package selfupdate

import "errors"

// Launch gibt es nur unter Linux (Container).
func Launch(dataDir, imageVersion string) {}

// Reexec gibt es nur unter Linux.
func Reexec() error { return errors.New("self-update restart is only supported on Linux") }
