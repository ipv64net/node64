package shield

import (
	"net/netip"
	"strings"
	"testing"
)

func TestBlockSet(t *testing.T) {
	list, err := ParseList(strings.NewReader(`# Kommentar
1.2.3.0/24
1.2.4.0/24 ; angrenzend
5.6.7.8
10.0.0.5/8
2001:db8:1::/48
2001:db8:1:5::/64   # enthalten
2a00:1450::1
kein-netz
`))
	if err != nil {
		t.Fatal(err)
	}
	s := BuildSet([][]netip.Prefix{list}, []netip.Prefix{netip.MustParsePrefix("1.2.4.9/32")})
	if len(s.v4) != 3 { // 1.2.3.0-1.2.4.255 zusammen, 5.6.7.8, 10/8
		t.Fatalf("v4 ranges: %+v", s.v4)
	}
	for ip, want := range map[string]bool{
		"1.2.3.1": true, "1.2.4.200": true, "1.2.5.1": false, "5.6.7.8": true, "5.6.7.9": false, "10.200.1.1": true,
		"1.2.4.9":         false, // Ausnahme
		"2001:db8:1:5::7": true, "2001:db8:1:ffff::1": true, "2001:db8:2::1": false, "2a00:1450::1": true, "2a00:1450::2": false,
		"::ffff:5.6.7.8": true, // IPv4 ueber Dual-Stack
	} {
		if got := s.Has(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: %v, want %v", ip, got, want)
		}
	}
	var nilSet *Set
	if nilSet.Has(netip.MustParseAddr("5.6.7.8")) {
		t.Fatal("nil set blocks nothing")
	}
}

// IPv4-gemappte Netze gelten fuer IPv4 (Adressen kommen entmappt an); gemappte kuerzer als /96 und Zonen fallen weg.
func TestNormPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"::ffff:203.0.113.0/120": "203.0.113.0/24", "::ffff:0.0.0.0/96": "0.0.0.0/0", "::ffff:1.2.3.4/80": "",
		"2001:db8::7/64": "2001:db8::/64", "192.0.2.9/24": "192.0.2.0/24",
	} {
		got, ok := NormPrefix(netip.MustParsePrefix(in))
		if (want == "") == ok || ok && got.String() != want {
			t.Errorf("%s: %v %v, want %q", in, got, ok, want)
		}
	}
	list, _ := ParseList(strings.NewReader("::ffff:203.0.113.0/120 # Netz\n::ffff:198.51.100.7\n"))
	s := BuildSet([][]netip.Prefix{list, {netip.MustParsePrefix("::ffff:192.0.2.0/120")}}, []netip.Prefix{netip.MustParsePrefix("::ffff:203.0.113.9/128")})
	for ip, want := range map[string]bool{"203.0.113.5": true, "198.51.100.7": true, "192.0.2.1": true, "203.0.113.9": false, "198.51.100.8": false} {
		if got := s.Has(netip.MustParseAddr(ip)); got != want {
			t.Errorf("mapped %s: %v, want %v", ip, got, want)
		}
	}
}
