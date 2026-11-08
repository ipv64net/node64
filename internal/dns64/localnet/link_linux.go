//go:build linux

package localnet

import (
	"bytes"
	"encoding/binary"
	"syscall"
)

// linkKinds liest den Linux-Link-Typ jeder Schnittstelle (veth, macvlan, ipvlan ...) per Netlink (RTM_GETLINK,
// IFLA_LINKINFO/IFLA_INFO_KIND). ifindex/iflink allein unterscheiden ein veth-Paar nicht von macvlan/ipvlan.
// Fehler: nil (dann bleibt die bisherige Erkennung).
func linkKinds() map[string]string {
	b, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		return nil
	}
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for i := range msgs {
		if msgs[i].Header.Type != syscall.RTM_NEWLINK {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&msgs[i])
		if err != nil {
			continue
		}
		var name, kind string
		for _, a := range attrs {
			switch a.Attr.Type & nlaTypeMask {
			case syscall.IFLA_IFNAME:
				name = string(bytes.TrimRight(a.Value, "\x00"))
			case syscall.IFLA_LINKINFO:
				kind = infoKind(a.Value)
			}
		}
		if name != "" {
			out[name] = kind
		}
	}
	return out
}

const nlaTypeMask = 0x3fff // ohne NLA_F_NESTED / NLA_F_NET_BYTEORDER

// infoKind: IFLA_INFO_KIND (Typ 1) aus den verschachtelten Attributen von IFLA_LINKINFO ("" = keiner/kaputt).
func infoKind(b []byte) string {
	for len(b) >= 4 {
		n := int(binary.NativeEndian.Uint16(b[:2]))
		if n < 4 || n > len(b) {
			return ""
		}
		if binary.NativeEndian.Uint16(b[2:4])&nlaTypeMask == 1 {
			return string(bytes.TrimRight(b[4:n], "\x00"))
		}
		step := (n + 3) &^ 3 // NLA_ALIGNTO = 4
		if step >= len(b) {
			return ""
		}
		b = b[step:]
	}
	return ""
}
