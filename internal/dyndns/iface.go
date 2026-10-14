package dyndns

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// ifAddr ist eine globale IPv6-Adresse eines Interfaces (nur sichtbar mit network_mode: host).
type ifAddr struct {
	Iface      string
	Addr       netip.Addr
	Temporary  bool // Privacy-Adresse (wechselt regelmaessig, nicht fuer AAAA-Records)
	Deprecated bool
}

// Flags aus /proc/net/if_inet6 (linux/if_addr.h)
const (
	ifaTemporary  = 0x01
	ifaDeprecated = 0x20
	ifaTentative  = 0x40
)

// localIPv6 liest die globalen IPv6-Adressen des Hosts bzw. Containers (nur Linux, sonst leer).
func localIPv6() []ifAddr {
	f, err := os.Open("/proc/net/if_inet6")
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseIfInet6(f)
}

// parseIfInet6: "20010db8000000000000000000000001 02 40 00 80 eth0" (Adresse, Index, Laenge, Scope, Flags, Name)
func parseIfInet6(r io.Reader) []ifAddr {
	var out []ifAddr
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 || len(f[0]) != 32 || f[3] != "00" { // nur Scope global
			continue
		}
		var b [16]byte
		ok := true
		for i := 0; i < 16; i++ {
			v, err := strconv.ParseUint(f[0][2*i:2*i+2], 16, 8)
			if err != nil {
				ok = false
				break
			}
			b[i] = byte(v)
		}
		flags, err := strconv.ParseUint(f[4], 16, 32)
		if !ok || err != nil || flags&ifaTentative != 0 {
			continue
		}
		a := netip.AddrFrom16(b)
		if !publicAddr(a) {
			continue
		}
		out = append(out, ifAddr{Iface: f[5], Addr: a, Temporary: flags&ifaTemporary != 0, Deprecated: flags&ifaDeprecated != 0})
	}
	return out
}
