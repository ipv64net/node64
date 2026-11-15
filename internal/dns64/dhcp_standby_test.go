package dns64

import (
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Code-Review 1.7: Die Reserve fragt die Haupt-Node (TCP 53) nie im DHCP-Paketpfad. Bei abgelaufenem Stand liefert
// dhcpStandby sofort den letzten Stand und prueft einmal im Hintergrund (auch bei vielen Paketen gleichzeitig).
func TestDHCPStandbyNotInPacketPath(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	const subnet = "192.168.50.0/24"
	m.SetDHCPPeers(func(context.Context, string) []DHCPPeer {
		return []DHCPPeer{{NodeID: "a", Name: "Node A", Online: false}}
	})
	n := clDHCPNode{Role: dhcpPrimary, Mode: dhcpOn, Nets: []clDHCPNodeNet{{subnet, "192.168.50.2"}}}
	if err := m.ClusterApply(ctx, ItemDHCPScopes, "n:a", json.RawMessage(jsonString(n)), false); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	old := dhcpDialPrimary
	dhcpDialPrimary = func(string) bool { calls.Add(1); time.Sleep(800 * time.Millisecond); return false }
	t.Cleanup(func() { dhcpDialPrimary = old })
	m.dh.soonMu.Lock()
	m.dh.standby = map[string]standbyState{subnet: {quiet: true, at: time.Now().Add(-time.Minute)}}
	m.dh.soonMu.Unlock()

	p := netip.MustParsePrefix(subnet)
	start := time.Now()
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !m.dhcpStandby(p) {
				t.Error("stale state not used")
			}
		}()
	}
	wg.Wait()
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("packet path blocked %v", d)
	}
	deadline := time.Now().Add(3 * time.Second)
	for m.dhcpStandby(p) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if m.dhcpStandby(p) {
		t.Fatal("primary gone: reserve must answer after the background probe")
	}
	if c := calls.Load(); c != 1 {
		t.Fatalf("probes %d", c)
	}
}
