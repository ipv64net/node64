package ipam64

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// Forum 5228: Adressen, die nur in der Nachbartabelle stehen (DHCP macht die FRITZ!Box), bekommen den Namen, den
// DNS64 beim Router erfragt; eigene Namen gehen vor.
func TestRouterNames(t *testing.T) {
	m, f, _ := modTest(t)
	ctx := context.Background()
	mustPrefix(t, m, Prefix{Prefix: "192.168.1.0/24"})
	if _, err := m.SaveAddress(ctx, Address{Address: "192.168.1.20", Name: "drucker", Status: StatusReserved}, "t"); err != nil {
		t.Fatal(err)
	}
	var asked []string
	m.SetDNS64(DNS64{Running: func() bool { return true }, Names: func(_ context.Context, ips []string) map[string]string {
		asked = append(asked, ips...)
		return map[string]string{"192.168.1.30": "laptop.fritz.box", "192.168.1.20": "falsch.fritz.box"}
	}})
	f.tab = map[netip.Addr]Neighbor{
		ip("192.168.1.20"): {MAC: "02:64:03:00:00:14", Age: time.Second},
		ip("192.168.1.30"): {MAC: "02:64:03:00:00:1e", Age: time.Second},
	}
	if err := m.poll(ctx); err != nil {
		t.Fatal(err)
	}
	s, err := m.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if e := s.Entry(ip("192.168.1.30")); e == nil || e.Name != "laptop.fritz.box" {
		t.Fatalf("router name: %+v", e)
	}
	if e := s.Entry(ip("192.168.1.20")); e == nil || e.Name != "drucker" {
		t.Fatalf("own name must win: %+v", e)
	}
	for _, a := range asked {
		if a == "192.168.1.20" {
			t.Fatal("asked the router for an address that already has a name")
		}
	}
}
