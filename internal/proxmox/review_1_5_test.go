package proxmox

import "testing"

// Link-Local mit Zone: wird angenommen und in der URL als %25 geschrieben (vorher abgelehnt, obwohl Monitor64 0.1.4
// es fuer Proxmox VE und PBS verspricht); die Zone bleibt in ihrer Schreibweise.
func TestNormalizeAddressZone(t *testing.T) {
	for in, want := range map[string]string{
		"fe80::1%eth0":                  "https://[fe80::1%25eth0]:8006",
		"https://[fe80::1%eth0]:8006":   "https://[fe80::1%25eth0]:8006",
		"https://[fe80::1%25Eth0]:8443": "https://[fe80::1%25Eth0]:8443",
		"https://[FE80::1%25eth0]":      "https://[fe80::1%25eth0]:8006",
		"pve.example.lan":               "https://pve.example.lan:8006",
		"[2001:db8::5]":                 "https://[2001:db8::5]:8006",
	} {
		got, ok := NormalizeAddressFor(KindPVE, in)
		if !ok || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, ok, want)
		}
	}
}
