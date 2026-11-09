//go:build !linux

package m64linux

import "errors"

// statfsPath gibt es nur unter Linux; anderswo (Entwicklung unter Windows) liefern Tests Options.Statfs.
func statfsPath(p string) (StatFS, error) {
	return StatFS{}, &statfsError{p, errors.New("statfs nur unter Linux")}
}
