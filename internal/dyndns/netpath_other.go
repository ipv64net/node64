//go:build !linux

package dyndns

import (
	"context"
	"errors"
	"net/netip"
)

// traceUDP gibt es nur unter Linux (Container); anderswo bleibt die Analyse leer.
func traceUDP(context.Context, netip.Addr, int) ([]netip.Addr, error) {
	return nil, errors.New("not supported on this platform")
}
