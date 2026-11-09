//go:build !linux

package m64agent

// hostInfo: ausserhalb von Linux folgt das mit dem Windows-Agent (Phase 2).
func hostInfo() (platform, kernel string, boot int64) {
	return "", "", 0
}
