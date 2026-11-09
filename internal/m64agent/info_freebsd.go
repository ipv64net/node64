//go:build freebsd

package m64agent

import "github.com/ipv64net/node64/internal/m64bsd"

// hostInfo liest Plattform (OPNsense, pfSense, TrueNAS CORE, FreeBSD), Kernel und Startzeit ueber sysctl.
func hostInfo() (platform, kernel string, boot int64) { return m64bsd.HostInfo() }
