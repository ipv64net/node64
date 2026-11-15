package ipam64

import (
	"context"
	"net/netip"
)

// Freie Adressen: frei ist eine Adresse, die in keiner Quelle belegt ist, nicht Netz- oder Broadcast-Adresse ist und
// weder im DHCP-Adressbereich (auch dem des umgebenden DHCP-Netzes) noch in einem reservierten Adressbereich liegt
// (auch einem des Eltern-Praefixes, der hineinreicht). Gibt es im Praefix selbst Adressbereiche fuer feste Adressen
// (nicht in einem Kind-Praefix), wird nur dort gesucht (bzw. im gewaehlten Bereich).

const maxFreeSearch = 1 << 16 // so viele Adressen hoechstens durchsuchen (IPv6, grosse Netze)

// FreeBlock ist eine Luecke zwischen belegten Adressen (Liste der Adressen eines Praefixes).
type FreeBlock struct {
	First, Last netip.Addr
	Count       int64
	Pool        bool // ganz im DHCP-Adressbereich
}

// Available liefert bis zu n freie Adressen in einem Praefix (rangeUID: nur in diesem Adressbereich).
func (m *Module) Available(ctx context.Context, cidr, rangeUID string, n int) ([]netip.Addr, error) {
	snap, err := m.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	net := snap.Net(cidr)
	if net == nil {
		return nil, ErrNotFound
	}
	return snap.free(net, rangeUID, n)
}

func (s *Snapshot) free(n *Net, rangeUID string, limit int) ([]netip.Addr, error) {
	if n.Container() {
		return nil, nil
	}
	type span struct{ a, b netip.Addr }
	var fixed, reserved []span
	first, last := n.Prefix.Masked().Addr(), lastAddr(n.Prefix)
	for _, r := range s.Ranges {
		a, err1 := netip.ParseAddr(r.Start)
		b, err2 := netip.ParseAddr(r.End)
		if err1 != nil || err2 != nil || a.Is4() != n.IsV4() {
			continue
		}
		switch {
		case rangeUID != "" && r.UID == rangeUID:
			if n.Prefix.Contains(a) {
				fixed = []span{{a, b}}
			}
		case rangeUID == "" && r.Kind == RangeFixed && s.NetOf(a) == n: // Bereiche eines Kind-Praefixes gehoeren dorthin
			fixed = append(fixed, span{a, b})
		case r.Kind == RangeReserved && !b.Less(first) && !last.Less(a): // auch aus dem Eltern-Praefix hineinreichend
			reserved = append(reserved, span{a, b})
		}
	}
	if rangeUID != "" && len(fixed) == 0 {
		return nil, ErrNotFound
	}
	if len(fixed) == 0 {
		first := n.Prefix.Masked().Addr()
		if (n.IsV4() && n.Prefix.Bits() <= 30) || (!n.IsV4() && n.Prefix.Bits() <= 126) {
			first = first.Next()
		}
		fixed = []span{{first, lastAddr(n.Prefix)}}
	}
	blocked := func(ip netip.Addr) bool {
		if n.IsV4() && n.Prefix.Bits() <= 30 && (ip == n.Prefix.Masked().Addr() || ip == lastAddr(n.Prefix)) {
			return true
		}
		if !n.IsV4() && n.Prefix.Bits() <= 126 && ip == n.Prefix.Masked().Addr() { // Subnet-Router-Anycast (RFC 4291)
			return true
		}
		if n.inPool(ip) || s.Entry(ip) != nil {
			return true
		}
		for _, r := range reserved {
			if !ip.Less(r.a) && !r.b.Less(ip) {
				return true
			}
		}
		// Adresse in einem Kind-Praefix gehoert dort hin
		return s.NetOf(ip) != n
	}
	var out []netip.Addr
	steps := 0
	for _, sp := range fixed {
		for ip := sp.a; ip.IsValid() && !sp.b.Less(ip) && len(out) < limit && steps < maxFreeSearch; ip = ip.Next() {
			steps++
			if !blocked(ip) {
				out = append(out, ip)
			}
		}
	}
	return out, nil
}

// FreeBlocks liefert die Luecken zwischen den belegten Adressen eines IPv4-Praefixes (fuer die Liste; leer bei IPv6
// und Praefixen groesser /16).
func (s *Snapshot) FreeBlocks(n *Net) []FreeBlock {
	if !n.IsV4() || n.Prefix.Bits() < 16 || n.Container() {
		return nil
	}
	var out []FreeBlock
	first := n.Prefix.Masked().Addr()
	last := lastAddr(n.Prefix)
	if n.Prefix.Bits() <= 30 {
		first, last = first.Next(), last.Prev()
	}
	add := func(a, b netip.Addr) {
		if b.Less(a) {
			return
		}
		out = append(out, FreeBlock{First: a, Last: b, Count: int64(u32(b)-u32(a)) + 1, Pool: n.inPool(a) && n.inPool(b)})
	}
	cur := first
	for _, e := range s.entries[n.Prefix] {
		if e.ip.Less(cur) {
			continue
		}
		add(cur, e.ip.Prev())
		cur = e.ip.Next()
	}
	add(cur, last)
	return out
}
