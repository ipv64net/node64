package groups

import (
	"net/netip"
	"testing"
)

// MAC aus den DHCP-Vergaben, wenn die Nachbartabelle das Geraet nicht kennt (z. B. hinter einem Relay).
func TestLeaseMAC(t *testing.T) {
	r := NewResolver(nil)
	r.read = func() (map[netip.Addr]string, error) { return map[netip.Addr]string{}, nil }
	r.Set([]Group{{ID: 7, Name: "Kinder", Members: []Member{{Kind: KindMAC, Value: "aa:bb:cc:dd:ee:01"}}}})
	ip := netip.MustParseAddr("10.20.0.100")
	if m := r.For(ip); m.ID != 0 {
		t.Fatalf("without lease: %+v", m)
	}
	r.SetLeases(map[netip.Addr]string{ip: "aa:bb:cc:dd:ee:01"})
	if m := r.For(ip); m.ID != 7 || m.MAC != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("with lease: %+v", m)
	}
	if ips := r.IPs("aa:bb:cc:dd:ee:01"); len(ips) != 1 || ips[0] != ip {
		t.Fatalf("ips %v", ips)
	}
}
