package firewall

import (
	"net/netip"
	"slices"
)

// Bereichs-Logik (plattformunabhaengig): Netze aus den Listen werden zu sortierten, zusammengefassten Bereichen je
// Familie; eigene, private und reservierte Netze werden herausgeschnitten (auch aus groesseren Netzen der Liste).
// So stehen im Set nur Intervalle, die sich nicht ueberlappen und nicht beruehren - wie es nftables fuer Sets mit
// "flags interval" ohne auto-merge erwartet.

// Range ist ein Adressbereich From..To (beide eingeschlossen, gleiche Familie, IPv4 ohne ::ffff:-Form).
type Range struct {
	From, To netip.Addr
}

// String: "a-b" bzw. "a" bei einer einzelnen Adresse (Log und Tests).
func (r Range) String() string {
	if r.From == r.To {
		return r.From.String()
	}
	return r.From.String() + "-" + r.To.String()
}

// prefixRange: erste und letzte Adresse eines Netzes.
func prefixRange(p netip.Prefix) Range {
	p = p.Masked()
	from := p.Addr()
	b := from.AsSlice()
	host := from.BitLen() - p.Bits()
	for i := len(b) - 1; i >= 0 && host > 0; i-- {
		n := min(host, 8)
		b[i] |= byte(1<<n - 1)
		host -= n
	}
	to, _ := netip.AddrFromSlice(b)
	return Range{From: from, To: to}
}

// mustPrefixes fuer feste Tabellen.
func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, x := range s {
		out[i] = netip.MustParsePrefix(x)
	}
	return out
}

// Reserved: Netze, die nie gesperrt werden (privat, Loopback, Link-Local, CGNAT, Dokumentation, Multicast,
// reserviert). Bei IPv6 gilt nur 2000::/3 (global unicast) als sperrbar, ohne die Dokumentationsnetze; damit fallen
// auch ULA, Link-Local, NAT64 (64:ff9b::/96) und ::ffff:0:0/96 heraus.
var Reserved = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
	"192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4",
	"::/3", "4000::/2", "8000::/1", "2001:db8::/32", "3fff::/20",
)

// Kleinste erlaubte Netzgroesse aus einer Liste: groessere Netze (z. B. 0.0.0.0/0 aus einer kaputten Liste) wuerden
// halbe Kontinente sperren und werden verworfen.
const (
	minBits4 = 8
	minBits6 = 16
)

// compareAddr fuer Sortierung (gleiche Familie).
func cmpRange(a, b Range) int {
	if c := a.From.Compare(b.From); c != 0 {
		return c
	}
	return a.To.Compare(b.To)
}

// merge sortiert und fasst ueberlappende und angrenzende Bereiche zusammen (eine Familie).
func merge(rs []Range) []Range {
	if len(rs) == 0 {
		return nil
	}
	slices.SortFunc(rs, cmpRange)
	out := rs[:1]
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		next := last.To.Next() // ungueltig = letzte Adresse der Familie, deckt alles Folgende ab
		if !next.IsValid() || r.From.Compare(next) <= 0 {
			if r.To.Compare(last.To) > 0 {
				last.To = r.To
			}
			continue
		}
		out = append(out, r)
	}
	return slices.Clip(out)
}

// subtract schneidet die Bereiche ex aus rs heraus (beide sortiert und zusammengefasst, eine Familie).
func subtract(rs, ex []Range) []Range {
	var out []Range
	j := 0
	for _, r := range rs {
		cur := r
		for j < len(ex) && ex[j].To.Compare(cur.From) < 0 {
			j++
		}
		keep := true
		for k := j; k < len(ex) && ex[k].From.Compare(cur.To) <= 0; k++ {
			e := ex[k]
			if e.From.Compare(cur.From) > 0 {
				out = append(out, Range{From: cur.From, To: e.From.Prev()})
			}
			if e.To.Compare(cur.To) >= 0 {
				keep = false
				break
			}
			cur.From = e.To.Next()
		}
		if keep {
			out = append(out, cur)
		}
	}
	return out
}

// toRanges teilt Netze nach Familie in zusammengefasste Bereiche.
func toRanges(ps []netip.Prefix) (v4, v6 []Range) {
	for _, p := range ps {
		if !p.IsValid() {
			continue
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), max(p.Bits()-96, 0))
		}
		if p.Addr().Is4() {
			v4 = append(v4, prefixRange(p))
		} else {
			v6 = append(v6, prefixRange(p))
		}
	}
	return merge(v4), merge(v6)
}

// Build baut aus den Netzen aller Listen die Bereiche fuer die beiden Sets: zusammengefasst, ohne zu grosse Netze
// (skipped zaehlt sie) und ohne die Netze in exclude (Reserved, Ausnahmen, eigene Adressen).
func Build(lists [][]netip.Prefix, exclude []netip.Prefix) (v4, v6 []Range, skipped int) {
	var all []netip.Prefix
	for _, l := range lists {
		for _, p := range l {
			a := p.Addr().Unmap()
			bits := p.Bits()
			if p.Addr().Is4In6() {
				bits -= 96
			}
			if (a.Is4() && bits < minBits4) || (a.Is6() && bits < minBits6) {
				skipped++
				continue
			}
			all = append(all, p)
		}
	}
	v4, v6 = toRanges(all)
	ex4, ex6 := toRanges(exclude)
	return subtract(v4, ex4), subtract(v6, ex6), skipped
}

// Diff liefert die Bereiche, die in next neu sind (added) bzw. aus prev wegfallen (removed); beide Listen sortiert
// wie von Build. Gleiche Bereiche zaehlen nicht.
func Diff(prev, next []Range) (added, removed []Range) {
	i, j := 0, 0
	for i < len(prev) || j < len(next) {
		switch {
		case i == len(prev):
			added = append(added, next[j])
			j++
		case j == len(next):
			removed = append(removed, prev[i])
			i++
		default:
			switch c := cmpRange(prev[i], next[j]); {
			case c == 0:
				i++
				j++
			case c < 0:
				removed = append(removed, prev[i])
				i++
			default:
				added = append(added, next[j])
				j++
			}
		}
	}
	return added, removed
}

// Addresses zaehlt die Adressen der IPv4-Bereiche (fuer Anzeige; IPv6 waere zu gross).
func Addresses(v4 []Range) uint64 {
	var n uint64
	for _, r := range v4 {
		f, t := r.From.As4(), r.To.As4()
		lo := uint64(f[0])<<24 | uint64(f[1])<<16 | uint64(f[2])<<8 | uint64(f[3])
		hi := uint64(t[0])<<24 | uint64(t[1])<<16 | uint64(t[2])<<8 | uint64(t[3])
		n += hi - lo + 1
	}
	return n
}
