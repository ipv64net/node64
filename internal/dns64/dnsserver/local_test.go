package dnsserver

import "testing"

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
