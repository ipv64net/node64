// Package shield: gemeinsamer Schutz-Code fuer Node64 (CDN64) und die CDN64-Server (cdn64-edge), z. B. die
// ipv64-Blocklisten als schnell durchsuchbare Sperrliste.
package shield

import (
	"bufio"
	"io"
	"net/netip"
	"slices"
	"strings"
)

type v4Range struct{ lo, hi uint32 }

// Set ist eine zusammengefasste Sperrliste (nur lesend nach dem Bau), z. B. die ipv64-Blocklisten.
type Set struct {
	v4    []v4Range      // sortiert, zusammengefasst
	v6    []netip.Prefix // sortiert
	allow []netip.Prefix // Ausnahmen
	total int            // Eintraege vor dem Zusammenfassen
}

func v4u(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// Has: Adresse steht in der Liste und nicht in den Ausnahmen (nil-Set sperrt nichts).
func (s *Set) Has(a netip.Addr) bool {
	if s == nil || !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, p := range s.allow {
		if p.Contains(a) {
			return false
		}
	}
	if a.Is4() {
		x := v4u(a)
		i, _ := slices.BinarySearchFunc(s.v4, x, func(r v4Range, x uint32) int {
			switch {
			case r.hi < x:
				return -1
			case r.lo > x:
				return 1
			}
			return 0
		})
		return i < len(s.v4) && s.v4[i].lo <= x && x <= s.v4[i].hi
	}
	// IPv6: wenige Netze; das letzte Netz mit Startadresse <= a pruefen (enthaltene sind beim Bau entfernt)
	i, _ := slices.BinarySearchFunc(s.v6, a, func(p netip.Prefix, a netip.Addr) int { return p.Addr().Compare(a) })
	if i < len(s.v6) && s.v6[i].Contains(a) {
		return true
	}
	return i > 0 && s.v6[i-1].Contains(a)
}

// NormPrefix bringt ein Netz in die Form, in der Adressen geprueft werden (die kommen entmappt an): IPv4-gemappte
// Netze (::ffff:a.b.c.d/n, n >= 96) werden zu IPv4-Netzen, Zonen fallen weg, Host-Bits werden genullt. false bei
// ungueltigen Netzen und gemappten kuerzer als /96 (die passen auf keine IPv4-Adresse sinnvoll).
func NormPrefix(p netip.Prefix) (netip.Prefix, bool) {
	if !p.IsValid() {
		return netip.Prefix{}, false
	}
	a, bits := p.Addr().WithZone(""), p.Bits()
	if a.Is4In6() {
		if bits < 96 {
			return netip.Prefix{}, false
		}
		a, bits = a.Unmap(), bits-96
	}
	return netip.PrefixFrom(a, bits).Masked(), true
}

// BuildSet fasst die Netze aller Listen zusammen (IPv4 als sortierte Bereiche, IPv6 ohne enthaltene Netze).
func BuildSet(lists [][]netip.Prefix, allow []netip.Prefix) *Set {
	s := &Set{}
	for _, p := range allow {
		if p, ok := NormPrefix(p); ok {
			s.allow = append(s.allow, p)
		}
	}
	var v4 []v4Range
	var v6 []netip.Prefix
	for _, l := range lists {
		s.total += len(l)
		for _, p := range l {
			p, ok := NormPrefix(p)
			if !ok {
				continue
			}
			if p.Addr().Is4() {
				lo := v4u(p.Addr())
				hi := lo | (uint32(1)<<(32-p.Bits()) - 1)
				if p.Bits() == 0 {
					hi = ^uint32(0)
				}
				v4 = append(v4, v4Range{lo, hi})
			} else {
				v6 = append(v6, p)
			}
		}
	}
	slices.SortFunc(v4, func(a, b v4Range) int {
		if a.lo != b.lo {
			if a.lo < b.lo {
				return -1
			}
			return 1
		}
		return 0
	})
	for _, r := range v4 {
		if n := len(s.v4); n > 0 && r.lo <= s.v4[n-1].hi+1 && s.v4[n-1].hi != ^uint32(0) {
			if r.hi > s.v4[n-1].hi {
				s.v4[n-1].hi = r.hi
			}
			continue
		}
		s.v4 = append(s.v4, r)
	}
	slices.SortFunc(v6, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	for _, p := range v6 { // enthaltene Netze weglassen
		if n := len(s.v6); n > 0 && s.v6[n-1].Contains(p.Addr()) && s.v6[n-1].Bits() <= p.Bits() {
			continue
		}
		s.v6 = append(s.v6, p)
	}
	return s
}

// ParseList liest eine Liste (ein Netz bzw. eine IP je Zeile, # und ; leiten Kommentare ein).
func ParseList(r io.Reader) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if f := strings.Fields(line); len(f) > 0 {
			line = f[0]
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			a, err2 := netip.ParseAddr(line)
			if err2 != nil {
				continue
			}
			p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		}
		if p, ok := NormPrefix(p); ok {
			out = append(out, p)
		}
	}
	return out, sc.Err()
}

// Total: Eintraege vor dem Zusammenfassen (0 = leer).
func (s *Set) Total() int {
	if s == nil {
		return 0
	}
	return s.total
}
