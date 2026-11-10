// Package ra kuendigt den DNS-Server per IPv6 Router Advertisement an (RFC 4861, RDNSS/DNSSL nach RFC 8106) und
// liest die RAs der Router im Netz (Plan docs/PLAN-NODE64-DNS64-DHCP.md, D7). Node64 ist dabei kein Router:
// Router-Lifetime 0 (kein Default-Router), keine Praefixe - Adressen und Route kommen weiter vom Router. Die Flags
// M/O uebernimmt der Sender vom Router des Netzes (Linux merkt sich die Flags des letzten RA).
package ra

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	typeRS    = 133
	typeRA    = 134
	optSLLA   = 1  // Link-Layer-Adresse der Quelle
	optPrefix = 3  // Praefix-Information
	optRDNSS  = 25 // DNS-Server
	optDNSSL  = 31 // Suchdomains

	flagManaged = 0x80 // M: Adressen per DHCPv6
	flagOther   = 0x40 // O: weitere Angaben per DHCPv6
	flagOnLink  = 0x80 // L (Praefix)
	flagAuto    = 0x40 // A (Praefix): SLAAC
)

// Prefix ist ein Praefix aus dem RA eines Routers.
type Prefix struct {
	Prefix netip.Prefix `json:"prefix"`
	SLAAC  bool         `json:"slaac"`   // Geraete bilden sich daraus selbst eine Adresse
	OnLink bool         `json:"on_link"` // im Netz direkt erreichbar
	Valid  uint32       `json:"valid_lifetime"`
}

// Router ist ein anderer Router im Netz (aus seinem letzten RA).
type Router struct {
	Iface    string       `json:"interface"`
	Source   netip.Addr   `json:"source"`
	Lifetime int          `json:"router_lifetime"` // Sekunden; 0 = kein Default-Router
	Managed  bool         `json:"managed"`
	Other    bool         `json:"other"`
	Prefixes []Prefix     `json:"prefixes"`
	DNS      []netip.Addr `json:"dns"`
	Domains  []string     `json:"domains"`
	LastSeen time.Time    `json:"last_seen"`
}

// Addresses: Geraete bekommen von diesem Router eine Adresse (SLAAC-Praefix oder DHCPv6).
func (r Router) Addresses() bool {
	if r.Managed {
		return true
	}
	for _, p := range r.Prefixes {
		if p.SLAAC && p.Valid > 0 {
			return true
		}
	}
	return false
}

// Ad ist der Inhalt eines eigenen RA.
type Ad struct {
	Managed, Other bool
	DNS            []netip.Addr
	Withdraw       []netip.Addr // frueher angekuendigt, jetzt nicht mehr (Lifetime 0)
	Domains        []string
	Lifetime       time.Duration // fuer DNS und Domains; 0 = zuruecknehmen
	MAC            net.HardwareAddr
}

// Marshal baut das RA (ICMPv6 ohne Pruefsumme; die setzt der Kernel).
func (a Ad) Marshal() []byte {
	b := make([]byte, 16)
	b[0] = typeRA
	if a.Managed {
		b[5] |= flagManaged
	}
	if a.Other {
		b[5] |= flagOther
	}
	// Hop-Limit, Router-Lifetime, Reachable und Retrans bleiben 0 (nicht angegeben, kein Default-Router)
	if len(a.MAC) == 6 {
		b = append(b, optSLLA, 1)
		b = append(b, a.MAC...)
	}
	life := uint32(a.Lifetime / time.Second)
	b = appendRDNSS(b, a.DNS, life)
	b = appendRDNSS(b, a.Withdraw, 0)
	if len(a.Domains) > 0 {
		var names []byte
		for _, d := range a.Domains {
			for _, l := range strings.Split(strings.Trim(d, "."), ".") {
				if l == "" || len(l) > 63 {
					continue
				}
				names = append(names, byte(len(l)))
				names = append(names, l...)
			}
			names = append(names, 0)
		}
		n := 8 + len(names)
		n += (8 - n%8) % 8
		o := make([]byte, n)
		o[0], o[1] = optDNSSL, byte(n/8)
		binary.BigEndian.PutUint32(o[4:], life)
		copy(o[8:], names)
		b = append(b, o...)
	}
	return b
}

func appendRDNSS(b []byte, list []netip.Addr, life uint32) []byte {
	if len(list) == 0 {
		return b
	}
	o := make([]byte, 8, 8+16*len(list))
	o[0], o[1] = optRDNSS, byte(1+2*len(list))
	binary.BigEndian.PutUint32(o[4:], life)
	for _, a := range list {
		v := a.As16()
		o = append(o, v[:]...)
	}
	return append(b, o...)
}

// solicit baut eine Router Solicitation.
func solicit(mac net.HardwareAddr) []byte {
	b := make([]byte, 8)
	b[0] = typeRS
	if len(mac) == 6 {
		b = append(b, optSLLA, 1)
		b = append(b, mac...)
	}
	return b
}

// Parse liest ein RA (ICMPv6-Nachricht ab dem Typ); false bei anderem Typ oder kaputter Nachricht.
func Parse(b []byte) (Router, bool) {
	var r Router
	if len(b) < 16 || b[0] != typeRA || b[1] != 0 {
		return r, false
	}
	r.Managed, r.Other = b[5]&flagManaged != 0, b[5]&flagOther != 0
	r.Lifetime = int(binary.BigEndian.Uint16(b[6:]))
	for o := b[16:]; len(o) >= 2; {
		n := int(o[1]) * 8
		if n == 0 || n > len(o) {
			return r, false
		}
		v := o[:n]
		switch o[0] {
		case optPrefix:
			if n == 32 && v[2] <= 128 {
				addr := netip.AddrFrom16([16]byte(v[16:32]))
				if p, err := addr.Prefix(int(v[2])); err == nil {
					r.Prefixes = append(r.Prefixes, Prefix{Prefix: p, OnLink: v[3]&flagOnLink != 0, SLAAC: v[3]&flagAuto != 0, Valid: binary.BigEndian.Uint32(v[4:])})
				}
			}
		case optRDNSS:
			if binary.BigEndian.Uint32(v[4:]) > 0 { // Lifetime 0 = zurueckgenommen
				for i := 8; i+16 <= n; i += 16 {
					r.DNS = append(r.DNS, netip.AddrFrom16([16]byte(v[i:i+16])))
				}
			}
		case optDNSSL:
			if binary.BigEndian.Uint32(v[4:]) > 0 {
				r.Domains = append(r.Domains, parseNames(v[8:])...)
			}
		}
		o = o[n:]
	}
	return r, true
}

// parseNames liest Domains im DNS-Format (ohne Kompression, mit Fuellnullen am Ende).
func parseNames(b []byte) []string {
	var out, labels []string
	for i := 0; i < len(b); {
		l := int(b[i])
		i++
		if l == 0 {
			if len(labels) > 0 {
				out = append(out, strings.Join(labels, "."))
			}
			labels = nil
			continue
		}
		if l > 63 || i+l > len(b) {
			break
		}
		labels = append(labels, string(b[i:i+l]))
		i += l
	}
	return out
}
