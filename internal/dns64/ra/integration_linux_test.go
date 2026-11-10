//go:build linux

package ra

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Echte Sockets im Test-Container (nie im Heimnetz), Aufbau wie beim DHCP-Test: veth0 (Node) und veth1 im
// Namensraum cli. Dort spielt radvd den Router (Praefix mit SLAAC, O-Flag, eigener DNS-Server), rdisc6 das Geraet.
// Nur mit DHCP_IT=1 und den Paketen radvd und ndisc6.
func TestIntegrationRA(t *testing.T) {
	if os.Getenv("DHCP_IT") != "1" {
		t.Skip("DHCP_IT=1 fehlt")
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "radvd.conf")
	if err := os.WriteFile(conf, []byte(`interface veth1 {
	AdvSendAdvert on; MinRtrAdvInterval 3; MaxRtrAdvInterval 4; AdvOtherConfigFlag on;
	prefix 2001:db8:99::/64 { AdvOnLink on; AdvAutonomous on; };
	RDNSS fd99::53 { };
	DNSSL fritz.box { };
};
`), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = exec.Command("ip", "netns", "exec", "cli", "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1").Run()
	radvd := exec.Command("ip", "netns", "exec", "cli", "radvd", "-n", "-C", conf, "-p", filepath.Join(dir, "radvd.pid"), "-m", "stderr")
	if err := radvd.Start(); err != nil {
		t.Fatalf("radvd: %v", err)
	}
	t.Cleanup(func() { _ = radvd.Process.Kill(); _ = radvd.Wait() })
	time.Sleep(time.Second)

	// Anzeige bei ausgeschaltetem Sender: Router fragen
	routers, err := Probe(context.Background(), "veth0", 3*time.Second)
	if err != nil || len(routers) != 1 {
		t.Fatalf("probe: %v %+v", err, routers)
	}
	r := routers[0]
	if r.Lifetime == 0 || !r.Other || r.Managed || !r.Addresses() || len(r.Prefixes) != 1 || r.Prefixes[0].Prefix != netip.MustParsePrefix("2001:db8:99::/64") ||
		len(r.DNS) != 1 || r.DNS[0] != netip.MustParseAddr("fd99::53") || len(r.Domains) != 1 || r.Domains[0] != "fritz.box" || !r.Source.IsLinkLocalUnicast() {
		t.Fatalf("router %+v", r)
	}

	// Sender: kuendigt fd99::1 an, uebernimmt das O-Flag des Routers, ist selbst kein Default-Router
	s := &Sender{Ifaces: []string{"veth0"}, Domains: []string{"home.lan"}, DNS: func(string) []netip.Addr { return []netip.Addr{netip.MustParseAddr("fd99::1")} }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	time.Sleep(5 * time.Second) // RS, 2 s auf den Router warten, erstes RA; danach >3 s bis zur naechsten RS-Antwort
	if st := s.Status(); len(st) != 1 || st[0].ErrKind != "" || len(st[0].DNS) != 1 || st[0].LastSent.IsZero() {
		t.Fatalf("status %+v (err %q)", st, s.Err())
	}
	if rs := s.Routers(); len(rs) != 1 || !rs[0].Other {
		t.Fatalf("sender routers %+v", rs)
	}
	out, err := exec.Command("ip", "netns", "exec", "cli", "rdisc6", "-m", "-w", "2000", "veth1").CombinedOutput()
	if err != nil {
		t.Fatalf("rdisc6: %v\n%s", err, out)
	}
	o := string(out)
	if !strings.Contains(o, "fd99::1") || !strings.Contains(o, "home.lan") { // radvd laeuft im selben Namensraum: rdisc6 sieht nur die Node
		t.Fatalf("rdisc6 misses an RA:\n%s", o)
	}
	zero := false
	for _, l := range strings.Split(o, "\n") {
		if strings.Contains(l, "Router lifetime") && strings.Contains(l, " 0 (0x0") {
			zero = true
		}
		if strings.Contains(l, "Stateful other conf") && strings.HasSuffix(strings.TrimSpace(l), "No") {
			t.Fatalf("O flag not mirrored:\n%s", o)
		}
	}
	if !zero {
		t.Fatalf("own RA with router lifetime > 0:\n%s", o)
	}
	if s.Sent() < 2 {
		t.Fatalf("sent %d", s.Sent())
	}
	cancel()
	<-done
	if st := s.Status(); len(st[0].DNS) != 0 {
		t.Fatalf("not withdrawn: %+v", st)
	}
}
