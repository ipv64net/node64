package dnsserver

import (
	"testing"

	"github.com/miekg/dns"
)

// Angehaengte Suchdomain: oeffentliche Domain + lokale Endung; Dienst-Suchen und lokale Namen nicht.
func TestSearchBase(t *testing.T) {
	for in, want := range map[string]string{
		"adsbexchange.com.home.local":     "adsbexchange.com",
		"pfsense.ipv64.de.home.local":     "pfsense.ipv64.de",
		"example.co.uk.fritz.box":         "example.co.uk",
		"nas.home.local":                  "",
		"drucker.buero.home.local":        "",
		"_ldap._tcp.dc._msdcs.home.local": "",
		"home.local":                      "",
		"com.home.local":                  "",
	} {
		if got := searchBase(in); got != want {
			t.Errorf("searchBase(%q) = %q, want %q", in, got, want)
		}
	}
}

// Echte TLDs mit DNSSEC-/Delegations-Typen gehen an die Upstreams, Geraetenamen und Adressfragen bleiben lokal.
func TestTLDQuery(t *testing.T) {
	for _, c := range []struct {
		name  string
		qtype uint16
		want  bool
	}{
		{"com", dns.TypeDS, true}, {"de", dns.TypeDNSKEY, true}, {"com", dns.TypeNS, true}, {"org", dns.TypeSOA, true},
		{"com", dns.TypeA, false}, {"media", dns.TypeAAAA, false}, {"nas", dns.TypeDS, false}, {"fritz", dns.TypeSOA, false},
		{"example.com", dns.TypeDS, false}, {"", dns.TypeNS, false},
	} {
		if got := tldQuery(c.name, c.qtype); got != c.want {
			t.Errorf("tldQuery(%q, %s) = %v, want %v", c.name, dns.TypeToString[c.qtype], got, c.want)
		}
	}
}
