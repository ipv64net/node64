//go:build !freebsd

package m64bsd

import "errors"

// errNotFreeBSD: sysctl, getfsstat und statfs gibt es hier nur unter FreeBSD; Tests liefern Options.Sysctl,
// Options.Mounts und Options.Statfs.
var errNotFreeBSD = errors.New("nur unter FreeBSD")

func defaultSysctl(string, ...int) ([]byte, error) { return nil, errNotFreeBSD }

func getMounts() ([]Mount, error) { return nil, errNotFreeBSD }

func statfsPath(p string) (StatFS, error) { return StatFS{}, &statfsError{p, errNotFreeBSD} }
