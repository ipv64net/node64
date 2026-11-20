package ipam64

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
)

// Freie Adressen: frei ist eine Adresse, die in keiner Quelle belegt ist, nicht Netz- oder Broadcast-Adresse und nicht
// Router-Adresse eines DHCP-Netzes ist und
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
	routers := s.routers(n)
	blocked := func(ip netip.Addr) bool {
		if n.IsV4() && n.Prefix.Bits() <= 30 && (ip == n.Prefix.Masked().Addr() || ip == lastAddr(n.Prefix)) {
			return true
		}
		if !n.IsV4() && n.Prefix.Bits() <= 126 && ip == n.Prefix.Masked().Addr() { // Subnet-Router-Anycast (RFC 4291)
			return true
		}
		if n.inPool(ip) || s.Entry(ip) != nil || slices.Contains(routers, ip) {
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

// routers liefert die Router-Adressen der DHCP-Netze, die in einem Praefix liegen (nie frei).
func (s *Snapshot) routers(n *Net) []netip.Addr {
	var out []netip.Addr
	for _, k := range s.Nets {
		if r, err := netip.ParseAddr(k.Router); err == nil && n.Prefix.Contains(r) {
			out = append(out, r)
		}
	}
	return out
}

// FreeBlocks liefert die Luecken zwischen den belegten Adressen eines IPv4-Praefixes (fuer die Liste; leer bei IPv6
// und Praefixen groesser /16). Wie bei free zaehlen Kind-Praefixe, reservierte Adressbereiche und Router-Adressen nicht
// als frei; eine Luecke wird an den Grenzen des DHCP-Adressbereichs geteilt (Pool: ganz darin).
func (s *Snapshot) FreeBlocks(n *Net) []FreeBlock {
	if !n.IsV4() || n.Prefix.Bits() < 16 || n.Container() {
		return nil
	}
	first, last := uint64(u32(n.Prefix.Masked().Addr())), uint64(u32(lastAddr(n.Prefix)))
	if n.Prefix.Bits() <= 30 {
		first, last = first+1, last-1
	}
	type span struct{ a, b uint64 }
	var taken []span // belegt bzw. gesperrt
	for _, e := range s.entries[n.Prefix] {
		taken = append(taken, span{uint64(u32(e.ip)), uint64(u32(e.ip))})
	}
	for _, k := range s.Nets {
		if k.Parent == n.CIDR {
			taken = append(taken, span{uint64(u32(k.Prefix.Masked().Addr())), uint64(u32(lastAddr(k.Prefix)))})
		}
	}
	for _, r := range s.Ranges {
		a, err1 := netip.ParseAddr(r.Start)
		b, err2 := netip.ParseAddr(r.End)
		if r.Kind == RangeReserved && err1 == nil && err2 == nil && a.Is4() && b.Is4() {
			taken = append(taken, span{uint64(u32(a)), uint64(u32(b))})
		}
	}
	for _, r := range s.routers(n) {
		taken = append(taken, span{uint64(u32(r)), uint64(u32(r))})
	}
	slices.SortFunc(taken, func(x, y span) int { return cmp.Compare(x.a, y.a) })
	var ps, pe uint64 = 1, 0 // DHCP-Adressbereich (leer: ps > pe)
	if n.start.Is4() && n.end.Is4() {
		ps, pe = uint64(u32(n.start)), uint64(u32(n.end))
	}
	var out []FreeBlock
	add := func(a, b uint64, pool bool) {
		if b < a {
			return
		}
		out = append(out, FreeBlock{First: addr4(a), Last: addr4(b), Count: int64(b-a) + 1, Pool: pool})
	}
	gap := func(a, b uint64) { // an den Grenzen des Pools teilen
		if pe < ps || b < ps || pe < a {
			add(a, b, false)
			return
		}
		if a < ps {
			add(a, ps-1, false)
		}
		add(max(a, ps), min(b, pe), true)
		if pe < b {
			add(pe+1, b, false)
		}
	}
	cur := first
	for _, t := range taken {
		if cur > last {
			break
		}
		if t.b < cur {
			continue
		}
		if t.a > cur {
			gap(cur, min(t.a-1, last))
		}
		cur = t.b + 1
	}
	if cur <= last {
		gap(cur, last)
	}
	return out
}

func addr4(v uint64) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
