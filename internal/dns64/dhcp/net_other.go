//go:build !linux

package dhcp

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

func listen(context.Context, string, int) (*net.UDPConn, error) {
	return nil, errors.New("dhcp: only on linux")
}

// ARPProbe gibt es nur unter Linux.
func ARPProbe(string, netip.Addr, netip.Addr) bool { return false }
