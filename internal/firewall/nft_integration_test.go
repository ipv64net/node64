//go:build linux && nftintegration

package firewall

// Integrationstest gegen echtes nftables. Nur in einem Wegwerf-Container mit eigenem Netz-Namensraum starten
// (docker run --cap-add NET_ADMIN, NICHT --network host), mit nft, ping und ip im Container:
//
//	GOOS=linux go test -c -tags nftintegration -o fwtest ./internal/firewall
//	docker run --rm --cap-add NET_ADMIN -v $PWD:/t debian:12 sh -c 'apt-get update -qq && apt-get install -y -qq nftables iputils-ping iproute2 >/dev/null && /t/fwtest -test.v'

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
)

func nftList(t *testing.T) (string, bool) {
	t.Helper()
	out, err := exec.Command("nft", "list", "table", "inet", Table).CombinedOutput()
	return string(out), err == nil
}

func pingFrom(addr string) bool {
	return exec.Command("ping", "-c", "1", "-W", "1", "-I", addr, addr).Run() == nil
}

func TestNFTIntegration(t *testing.T) {
	ls := newListServer(t)
	ls.set("ipv64_blocklist_v64.txt", "9.9.9.9\n1.2.3.0/24\n10.0.0.1\n2a01:4f8::/32\n")
	h := newTestHelper(t, ls, nil, func(c *Config) { c.HostAddrs = func() []netip.Addr { return nil } })
	if err := h.Probe(); err != nil {
		t.Fatal("probe:", err)
	}
	t.Cleanup(func() { _ = h.be.Remove() })
	if err := exec.Command("ip", "addr", "replace", "9.9.9.9/32", "dev", "lo").Run(); err != nil {
		t.Fatal("ip addr add:", err)
	}
	if !pingFrom("9.9.9.9") {
		t.Fatal("ping before table failed")
	}

	ctx := context.Background()
	if !h.Refresh(ctx) {
		t.Fatalf("refresh: %+v", h.Status())
	}
	out, ok := nftList(t)
	t.Log("\n" + out)
	for _, want := range []string{"table inet node64", "set blocklist_v4", "type ipv4_addr", "flags interval", "set blocklist_v6", "type ipv6_addr",
		"1.2.3.0/24", "9.9.9.9", "2a01:4f8::/32", "chain input", "type filter hook input priority filter - 10; policy accept;",
		"chain forward", "type filter hook forward priority filter - 10; policy accept;", "ip saddr @blocklist_v4", "ip6 saddr @blocklist_v6", "drop"} {
		if !ok || !strings.Contains(out, want) {
			t.Errorf("nft output lacks %q", want)
		}
	}
	if strings.Contains(out, "10.0.0.1") {
		t.Error("private address in set")
	}
	if pingFrom("9.9.9.9") {
		t.Error("ping from blocked address still works")
	}

	// Aenderung: 9.9.9.9 faellt weg, neue Netze kommen dazu
	ls.set("ipv64_blocklist_v64.txt", "1.2.3.0/24\n5.5.5.5\n5.5.5.6\n2a01:4f8::/32\n")
	if !h.Refresh(ctx) {
		t.Fatalf("refresh 2: %+v", h.Status())
	}
	out, _ = nftList(t)
	if !strings.Contains(out, "5.5.5.5-5.5.5.6") || strings.Contains(out, "9.9.9.9") {
		t.Errorf("update not applied:\n%s", out)
	}
	if !pingFrom("9.9.9.9") {
		t.Error("ping after removal from list failed")
	}

	// grosse Liste (Stuecke, Sendepuffer): 60 000 Einzeladressen und 20 000 IPv6-Netze in einer Transaktion
	var b strings.Builder
	for i := range 60000 {
		fmt.Fprintf(&b, "%d.%d.%d.1\n", 20+i/65536, (i/256)%256, i%256)
	}
	for i := range 20000 {
		fmt.Fprintf(&b, "2a02:100:%x::/48\n", 2*i) // nicht angrenzend, sonst fasst Build sie zusammen
	}
	ls.set("ipv64_blocklist_v64.txt", b.String())
	if !h.Refresh(ctx) {
		t.Fatalf("refresh big: %+v", h.Status())
	}
	if st := h.Status(); st.V4 != 60000 || st.V6 != 20000 {
		t.Fatalf("big: %d / %d", st.V4, st.V6)
	}
	out, _ = nftList(t)
	if !strings.Contains(out, "20.0.0.1") || !strings.Contains(out, "20.0.234.1") {
		t.Error("big list not in nft")
	}

	// Tabelle von aussen geloescht (nft flush ruleset): naechster Abruf legt sie wieder an
	if err := exec.Command("nft", "delete", "table", "inet", Table).Run(); err != nil {
		t.Fatal(err)
	}
	ls.set("ipv64_blocklist_v64.txt", "9.9.9.9\n")
	if !h.Refresh(ctx) {
		t.Fatalf("refresh after delete: %+v", h.Status())
	}
	if out, ok := nftList(t); !ok || !strings.Contains(out, "9.9.9.9") {
		t.Errorf("table not recreated:\n%s", out)
	}

	// Beenden: Tabelle weg
	h.stop()
	if out, ok := nftList(t); ok {
		t.Errorf("table still there after stop:\n%s", out)
	}
	if err := h.be.Remove(); err != nil {
		t.Errorf("remove without table: %v", err)
	}
}
