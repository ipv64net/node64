//go:build !linux && !windows && !freebsd

package m64agent

// hostInfo: ausserhalb von Linux und Windows (FreeBSD folgt) keine Angaben.
func hostInfo() (platform, kernel string, boot int64) {
	return "", "", 0
}
