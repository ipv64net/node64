package monitor64

import (
	"context"
	"net/netip"
	"testing"
)

// Adresse eines Hosts: Hostname, IPv4 und IPv6 in allen ueblichen Schreibweisen; was daraus fuer die Zugaenge wird.
func TestCleanAddressIPv6(t *testing.T) {
	for _, tc := range []struct {
		in, want   string
		agent, pve string
		trap       string
	}{
		{"nas", "nas", "nas:6556", "https://nas:8006", ""},
		{"nas:2222", "nas:2222", "nas:2222", "https://nas:2222", ""},
		{"10.0.0.5", "10.0.0.5", "10.0.0.5:6556", "https://10.0.0.5:8006", "10.0.0.5"},
		{"2001:db8::1", "2001:db8::1", "[2001:db8::1]:6556", "https://[2001:db8::1]:8006", "2001:db8::1"},
		{" [2001:db8::1] ", "2001:db8::1", "[2001:db8::1]:6556", "https://[2001:db8::1]:8006", "2001:db8::1"},
		{"[2001:db8::1]:2222", "[2001:db8::1]:2222", "[2001:db8::1]:2222", "https://[2001:db8::1]:2222", "2001:db8::1"},
		{"::1", "::1", "[::1]:6556", "https://[::1]:8006", "::1"},
		{"fe80::1%eth0", "fe80::1%eth0", "[fe80::1%eth0]:6556", "https://[fe80::1%eth0]:8006", "fe80::1"},
		{"[fe80::1%eth0]:22", "[fe80::1%eth0]:22", "[fe80::1%eth0]:22", "https://[fe80::1%eth0]:22", "fe80::1"},
		{"::ffff:192.168.1.5", "::ffff:192.168.1.5", "[::ffff:192.168.1.5]:6556", "https://[::ffff:192.168.1.5]:8006", "192.168.1.5"},
	} {
		got, ok := cleanAddress(tc.in)
		if !ok || got != tc.want {
			t.Errorf("cleanAddress(%q) = %q, %v, erwartet %q", tc.in, got, ok, tc.want)
			continue
		}
		if a := accessAddr(got, 0, 6556); a != tc.agent {
			t.Errorf("%q: Agent %q, erwartet %q", tc.in, a, tc.agent)
		}
		if u := "https://" + hostPort(got, 8006); u != tc.pve {
			t.Errorf("%q: PVE %q, erwartet %q", tc.in, u, tc.pve)
		}
		if tc.trap != "" {
			if as := resolveAddrs(context.Background(), got); len(as) != 1 || as[0] != netip.MustParseAddr(tc.trap) {
				t.Errorf("%q: Trap-Absender %v, erwartet %s", tc.in, as, tc.trap)
			}
		}
	}
	for _, bad := range []string{"", "[2001:db8::1", "2001:db8::1]:22", "[nas]:22", "[2001:db8::1]:0", "[2001:db8::1]:x", "[2001:db8::1]22",
		"nas:99999", "nas:ssh", ":22", "a:b:c", "2001:db8::zz", "nas%eth0", "10.0.0.5 ; rm", "[10.0.0.5]:22"} {
		if got, ok := cleanAddress(bad); ok {
			t.Errorf("cleanAddress(%q) angenommen als %q", bad, got)
		}
	}
}
