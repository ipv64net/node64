//go:build !linux

package caps

// Raise gibt es nur unter Linux.
func Raise() (bool, error) { return false, nil }
