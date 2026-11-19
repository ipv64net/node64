package dns64

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/ipv64net/node64/internal/dns64/groups"
)

// #223: IPv6-Adresse ohne Namen bekommt den Namen der IPv4-Adresse desselben Geraets (gleiche MAC).
func TestNamesByMAC(t *testing.T) {
	m := &Module{grp: groups.NewResolver(slog.New(slog.NewTextHandler(io.Discard, nil)))}
	v4, v6, other := "192.168.178.74", "fd00:dead:beef:babe::1299", "fd00:dead:beef:babe::77"
	m.grp.SetLeases(map[netip.Addr]string{
		netip.MustParseAddr(v4):    "1c:1b:0d:97:98:a3",
		netip.MustParseAddr(v6):    "1c:1b:0d:97:98:a3",
		netip.MustParseAddr(other): "aa:bb:cc:dd:ee:ff",
	})
	out := map[string]string{v4: "Nr8-Gaming-PC.fritz.box"}
	m.namesByMAC(context.Background(), nil, []string{v4, v6, other}, out)
	if out[v6] != "Nr8-Gaming-PC.fritz.box" || out[other] != "" {
		t.Fatalf("names: %v", out)
	}
}
