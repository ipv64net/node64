package ipam64

import (
	"encoding/binary"
	"net"
	"net/netip"
	"time"
)

// Nachbartabelle (ARP und NDP) per Netlink, Parser aus dem Entwurf von UlrichSchwarz, erweitert um IPv6.

// Netlink-Konstanten (linux/neighbour.h, linux/rtnetlink.h); ohne syscall, damit der Parser ueberall testbar ist.
const (
	nlmsgHdrLen  = 16
	ndMsgLen     = 12
	rtmNewNeigh  = 28
	nlmsgDone    = 3
	ndaDst       = 1
	ndaLLAddr    = 2
	ndaCacheInfo = 3
	nudReachable = 0x02
	nudStale     = 0x04
	nudDelay     = 0x08
	nudProbe     = 0x10
	userHZ       = 100 // Zeiten in nda_cacheinfo: Ticks zu 1/100 s
)

// parseNeigh liest eine Netlink-Antwort auf RTM_GETNEIGH (IPv4 und IPv6) und liefert je IP die MAC und das Alter
// der letzten Bestaetigung. Nur Eintraege mit gueltiger MAC (erreichbar, veraltet, in Pruefung); feste Eintraege,
// gescheiterte und unvollstaendige fallen weg, ebenso IPv6 Link-Local (fe80::/10, steht in keinem Praefix).
func parseNeigh(b []byte) map[netip.Addr]Neighbor {
	out := map[netip.Addr]Neighbor{}
	for len(b) >= nlmsgHdrLen {
		l := int(binary.NativeEndian.Uint32(b[0:4]))
		typ := binary.NativeEndian.Uint16(b[4:6])
		if l < nlmsgHdrLen || l > len(b) {
			break
		}
		msg := b[nlmsgHdrLen:l]
		b = b[min((l+3)&^3, len(b)):]
		if typ == nlmsgDone {
			break
		}
		if typ != rtmNewNeigh || len(msg) < ndMsgLen {
			continue
		}
		if state := binary.NativeEndian.Uint16(msg[8:10]); state&(nudReachable|nudStale|nudDelay|nudProbe) == 0 {
			continue
		}
		var ip netip.Addr
		var n Neighbor
		age := false
		for a := msg[ndMsgLen:]; len(a) >= 4; {
			al := int(binary.NativeEndian.Uint16(a[0:2]))
			at := binary.NativeEndian.Uint16(a[2:4])
			if al < 4 || al > len(a) {
				break
			}
			v := a[4:al]
			switch {
			case at == ndaDst && len(v) == 4:
				ip = netip.AddrFrom4([4]byte(v))
			case at == ndaDst && len(v) == 16:
				ip = netip.AddrFrom16([16]byte(v)).Unmap()
			case at == ndaLLAddr && len(v) == 6:
				n.MAC = net.HardwareAddr(v).String()
			case at == ndaCacheInfo && len(v) >= 4:
				n.Age, age = time.Duration(binary.NativeEndian.Uint32(v[0:4]))*time.Second/userHZ, true
			}
			a = a[min((al+3)&^3, len(a)):]
		}
		if ip.IsValid() && !ip.IsLinkLocalUnicast() && !ip.IsMulticast() && n.MAC != "" && n.MAC != "00:00:00:00:00:00" && age {
			out[ip] = n
		}
	}
	return out
}
