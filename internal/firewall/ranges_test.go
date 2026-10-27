package firewall

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func rs(t *testing.T, s ...string) []Range {
	t.Helper()
	var out []Range
	for _, x := range s {
		a, b, ok := strings.Cut(x, "-")
		if !ok {
			b = a
		}
		out = append(out, Range{From: netip.MustParseAddr(a), To: netip.MustParseAddr(b)})
	}
	return out
}

func eqRanges(t *testing.T, got, want []Range) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestPrefixRange(t *testing.T) {
	for _, c := range []struct{ p, from, to string }{
		{"1.2.3.0/24", "1.2.3.0", "1.2.3.255"},
		{"1.2.3.4/32", "1.2.3.4", "1.2.3.4"},
		{"10.0.0.0/7", "10.0.0.0", "11.255.255.255"},
		{"1.2.3.77/20", "1.2.0.0", "1.2.15.255"},
		{"2001:db8::/33", "2001:db8::", "2001:db8:7fff:ffff:ffff:ffff:ffff:ffff"},
		{"::/0", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	} {
		r := prefixRange(netip.MustParsePrefix(c.p))
		if r.From.String() != c.from || r.To.String() != c.to {
			t.Errorf("%s: %v", c.p, r)
		}
	}
}

func TestMerge(t *testing.T) {
	got := merge(rs(t, "1.0.0.5-1.0.0.9", "1.0.0.1-1.0.0.3", "1.0.0.4", "2.0.0.0-2.0.0.10", "2.0.0.3-2.0.0.4", "3.0.0.0"))
	eqRanges(t, got, rs(t, "1.0.0.1-1.0.0.9", "2.0.0.0-2.0.0.10", "3.0.0.0"))
	// letzte Adresse der Familie
	got = merge(rs(t, "255.255.255.0-255.255.255.255", "255.255.255.255", "1.1.1.1"))
	eqRanges(t, got, rs(t, "1.1.1.1", "255.255.255.0-255.255.255.255"))
	if merge(nil) != nil {
		t.Fatal("empty")
	}
}

func TestSubtract(t *testing.T) {
	got := subtract(rs(t, "1.0.0.0-1.0.0.255", "5.0.0.0-5.0.0.9", "7.0.0.0"),
		rs(t, "1.0.0.10-1.0.0.20", "1.0.0.30", "1.0.0.250-4.0.0.0", "5.0.0.0-5.0.0.2", "5.0.0.9", "7.0.0.0"))
	eqRanges(t, got, rs(t, "1.0.0.0-1.0.0.9", "1.0.0.21-1.0.0.29", "1.0.0.31-1.0.0.249", "5.0.0.3-5.0.0.8"))
	// Ausnahme bis zur letzten Adresse, ab der ersten Adresse
	got = subtract(rs(t, "::-::ff", "f000::-f000::1"), rs(t, "::-::f", "8000::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
	eqRanges(t, got, rs(t, "::10-::ff"))
	eqRanges(t, subtract(rs(t, "1.1.1.1"), nil), rs(t, "1.1.1.1"))
}

func TestBuildFiltersReservedAllowAndLarge(t *testing.T) {
	list := []netip.Prefix{
		netip.MustParsePrefix("1.2.3.4/32"),
		netip.MustParsePrefix("1.2.3.5/32"),
		netip.MustParsePrefix("10.1.2.3/32"),        // privat
		netip.MustParsePrefix("192.168.0.0/16"),     // privat
		netip.MustParsePrefix("100.0.0.0/8"),        // enthaelt CGNAT 100.64/10
		netip.MustParsePrefix("0.0.0.0/0"),          // zu gross
		netip.MustParsePrefix("8.8.0.0/16"),         // teilweise Ausnahme
		netip.MustParsePrefix("2a01:4f8::1/128"),    // global
		netip.MustParsePrefix("fd00::1/128"),        // ULA
		netip.MustParsePrefix("fe80::1/128"),        // Link-Local
		netip.MustParsePrefix("2001:db8::1/128"),    // Dokumentation
		netip.MustParsePrefix("::/0"),               // zu gross
		netip.MustParsePrefix("::ffff:9.9.9.9/128"), // IPv4 in IPv6-Form
	}
	allow := []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24"), netip.MustParsePrefix("1.2.3.5/32")}
	ex := slices.Concat(Reserved, allow)
	v4, v6, skipped := Build([][]netip.Prefix{list}, ex)
	if skipped != 2 {
		t.Fatalf("skipped %d", skipped)
	}
	eqRanges(t, v4, rs(t, "1.2.3.4", "8.8.0.0-8.8.7.255", "8.8.9.0-8.8.255.255", "9.9.9.9",
		"100.0.0.0-100.63.255.255", "100.128.0.0-100.255.255.255"))
	eqRanges(t, v6, rs(t, "2a01:4f8::1"))
}

func TestBuildMergesLists(t *testing.T) {
	a := []netip.Prefix{netip.MustParsePrefix("1.2.3.0/25")}
	b := []netip.Prefix{netip.MustParsePrefix("1.2.3.128/25"), netip.MustParsePrefix("1.2.3.4/32")}
	v4, v6, _ := Build([][]netip.Prefix{a, b}, Reserved)
	eqRanges(t, v4, rs(t, "1.2.3.0-1.2.3.255"))
	if len(v6) != 0 {
		t.Fatal(v6)
	}
	if n := Addresses(v4); n != 256 {
		t.Fatalf("addresses %d", n)
	}
}

func TestDiff(t *testing.T) {
	prev := rs(t, "1.0.0.1", "2.0.0.0-2.0.0.9", "3.0.0.1")
	next := rs(t, "1.0.0.1", "2.0.0.0-2.0.0.10", "4.0.0.1")
	add, rem := Diff(prev, next)
	eqRanges(t, add, rs(t, "2.0.0.0-2.0.0.10", "4.0.0.1"))
	eqRanges(t, rem, rs(t, "2.0.0.0-2.0.0.9", "3.0.0.1"))
	add, rem = Diff(next, next)
	if len(add)+len(rem) != 0 {
		t.Fatal("same lists differ")
	}
	add, rem = Diff(nil, next)
	if len(add) != 3 || len(rem) != 0 {
		t.Fatal(add, rem)
	}
}

func TestParseAllowAndLists(t *testing.T) {
	p, err := ParseAllow("192.168.1.0/24, 203.0.113.7;2a01:4f8::/32 ::ffff:1.2.3.4")
	if err != nil || len(p) != 4 || p[1].String() != "203.0.113.7/32" || p[3].String() != "1.2.3.4/32" {
		t.Fatal(p, err)
	}
	if _, err := ParseAllow("1.2.3.4/33"); err == nil {
		t.Fatal("bad cidr accepted")
	}
	if _, err := ParseAllow("example.com"); err == nil {
		t.Fatal("name accepted")
	}
	// fruehere Teillisten der v64 Blocklist gelten als v64 (doppelt nur einmal)
	l, err := ParseLists("v64, V64_SSH,v64,spamhaus_drop")
	if err != nil || !slices.Equal(l, []string{"v64", "spamhaus_drop"}) {
		t.Fatal(l, err)
	}
	if l, _ := ParseLists(""); !slices.Equal(l, []string{"v64"}) {
		t.Fatal(l)
	}
	if _, err := ParseLists("v64,../x"); err == nil {
		t.Fatal("bad id accepted")
	}
}
