//go:build !linux

package sonar

import "net/netip"

// newDgramTracer: Traceroute ohne Rechte gibt es nur unter Linux (Fehlerwarteschlange); sonst nur der Raw-Socket.
func newDgramTracer(dst netip.Addr, useICMP bool, port int, short [4]byte) (tracer, error) {
	return nil, errTraceUnsupported
}
