//go:build !linux

package ipam64

import (
	"errors"
	"net/netip"
)

// neighbors: die Nachbartabelle gibt es nur unter Linux.
func neighbors() (map[netip.Addr]Neighbor, error) { return nil, errors.ErrUnsupported }
