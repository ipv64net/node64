package dns64

import (
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

// Geteilter DNS fuer CDN64 online: Namen, die ueber srv07/srv08 laufen, beantwortet DNS64 im Heimnetz mit der
// Adresse der Node. Sonst ginge jeder Aufruf von zu Hause ueber das Internet und zurueck (und mit nur IPv6 im
// Heimnetz ueber IPv4 gar nicht).

// SetSplit setzt die Namen, die im Heimnetz die Node meinen (nil = keine).
func (m *Module) SetSplit(f func(name string) bool) { m.splitFn = f }

// split: A/AAAA eines solchen Namens fuer Clients im selben Netz wie die Node, mit den Adressen der Node auf
// dieser Schnittstelle. Clients aus anderen Netzen und eine Node im Docker-Bridge-Netz (deren Adressen im
// Heimnetz niemand erreicht) bekommen die normale Antwort.
func (m *Module) split(name string, qtype uint16, client netip.Addr) ([]dns.RR, bool) {
	if m.splitFn == nil || (qtype != dns.TypeA && qtype != dns.TypeAAAA) || !m.splitFn(name) {
		return nil, false
	}
	addrs := linkAddrs(client)
	if len(addrs) == 0 {
		return nil, false
	}
	out := []dns.RR{}
	for _, a := range addrs {
		switch {
		case qtype == dns.TypeA && a.Is4():
			out = append(out, &dns.A{Hdr: hdr(name, dns.TypeA, 60), A: a.AsSlice()})
		case qtype == dns.TypeAAAA && a.Is6():
			out = append(out, &dns.AAAA{Hdr: hdr(name, dns.TypeAAAA, 60), AAAA: a.AsSlice()})
		}
	}
	return out, true
}

// linkAddrs: Adressen der Node auf der Schnittstelle, deren Netz den Client enthaelt (ohne Link-Local).
var linkAddrs = func(client netip.Addr) []netip.Addr {
	client = client.Unmap()
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		list, err := ifc.Addrs()
		if err != nil {
			continue
		}
		hit := false
		var mine []netip.Addr
		for _, a := range list {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			p, err := netip.ParsePrefix(n.String())
			if err != nil {
				continue
			}
			ad := p.Addr().Unmap()
			if p.Masked().Contains(client) {
				hit = true
			}
			if !ad.IsLinkLocalUnicast() {
				mine = append(mine, ad)
			}
		}
		if hit {
			return mine
		}
	}
	return nil
}
