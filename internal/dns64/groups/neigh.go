package groups

import (
	"encoding/binary"
	"net"
	"net/netip"
)

// Netlink-Konstanten (linux/neighbour.h, linux/rtnetlink.h); hier ohne syscall, damit der Parser ueberall testbar ist.
const (
	nlmsgHdrLen     = 16
	ndMsgLen        = 12
	rtmNewNeigh     = 28
	nlmsgDone       = 3
	ndaDst          = 1
	ndaLLAddr       = 2
	nudIncomplete   = 0x01
	nudFailed       = 0x20
	nudNoARP        = 0x40
	afInet, afInet6 = 2, 10
)

// parseNeighDump liest eine Netlink-Antwort auf RTM_GETNEIGH (Bytes in Host-Reihenfolge) und liefert IP -> MAC.
// Unvollstaendige, gescheiterte und NOARP-Eintraege (z. B. Loopback, Multicast) fallen weg.
func parseNeighDump(b []byte) map[netip.Addr]string {
	out := map[netip.Addr]string{}
	for len(b) >= nlmsgHdrLen {
		l := int(binary.NativeEndian.Uint32(b[0:4]))
		typ := binary.NativeEndian.Uint16(b[4:6])
		if l < nlmsgHdrLen || l > len(b) {
			break
		}
		msg := b[nlmsgHdrLen:l]
		b = b[min(align4(l), len(b)):]
		if typ == nlmsgDone {
			break
		}
		if typ != rtmNewNeigh || len(msg) < ndMsgLen {
			continue
		}
		family := msg[0]
		state := binary.NativeEndian.Uint16(msg[8:10])
		if family != afInet && family != afInet6 || state&(nudIncomplete|nudFailed|nudNoARP) != 0 {
			continue
		}
		var ip netip.Addr
		var mac net.HardwareAddr
		attrs := msg[ndMsgLen:]
		for len(attrs) >= 4 {
			al := int(binary.NativeEndian.Uint16(attrs[0:2]))
			at := binary.NativeEndian.Uint16(attrs[2:4])
			if al < 4 || al > len(attrs) {
				break
			}
			val := attrs[4:al]
			switch at {
			case ndaDst:
				if a, ok := netip.AddrFromSlice(val); ok {
					ip = a.Unmap()
				}
			case ndaLLAddr:
				if len(val) == 6 {
					mac = net.HardwareAddr(append([]byte(nil), val...))
				}
			}
			attrs = attrs[min(align4(al), len(attrs)):]
		}
		if ip.IsValid() && mac != nil && !allZero(mac) {
			out[ip] = mac.String()
		}
	}
	return out
}

func align4(n int) int { return (n + 3) &^ 3 }

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
