//go:build linux

package groups

import (
	"net/netip"
	"syscall"
)

// Neighbors liest die Nachbartabelle des Hosts (IPv4 und IPv6) per Netlink.
func Neighbors() (map[netip.Addr]string, error) {
	b, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	return parseNeighDump(b), nil
}
