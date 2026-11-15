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

// Code-Review 1.7: radvd auf demselben Host (hier im Namensraum der Node auf veth0, gleiche Link-Local-Adresse). Sein
// naechstes RA kommt erst nach 16 s; der Sender darf trotzdem nie ein eigenes RA (Router-Lifetime 0) senden - das
// naehme dem Geraet die Default-Route. Erkannt am Beitritt von radvd zu ff02::2; Forwarding allein (Kernel tritt
// bei) zaehlt nicht. Nur mit DHCP_IT=1 und radvd.
func TestIntegrationRASelfRouter(t *testing.T) {
	if os.Getenv("DHCP_IT") != "1" {
		t.Skip("DHCP_IT=1 fehlt")
	}
	_ = exec.Command("ip", "netns", "exec", "cli", "sysctl", "-qw", "net.ipv6.conf.all.forwarding=0").Run()
	_ = exec.Command("ip", "netns", "exec", "cli", "sysctl", "-qw", "net.ipv6.conf.veth1.accept_ra=2").Run()
	if err := exec.Command("sysctl", "-qw", "net.ipv6.conf.all.forwarding=1").Run(); err != nil {
		t.Fatalf("forwarding: %v", err)
	}
	t.Cleanup(func() { _ = exec.Command("sysctl", "-qw", "net.ipv6.conf.all.forwarding=0").Run() })
	dns := func(string) []netip.Addr { return []netip.Addr{netip.MustParseAddr("fd99::1")} }
	run := func(s *Sender, d time.Duration) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); s.Run(ctx) }()
		time.Sleep(d)
		cancel()
		<-done
	}

	// nur Forwarding (Kernel in ff02::2): Sender kuendigt an
	s := &Sender{Ifaces: []string{"veth0"}, DNS: dns}
	run(s, 3*time.Second)
	if s.Sent() < 1 {
		t.Fatalf("forwarding only: sent %d, status %+v", s.Sent(), s.Status())
	}

	dir := t.TempDir()
	conf := filepath.Join(dir, "radvd.conf")
	if err := os.WriteFile(conf, []byte(`interface veth0 {
	AdvSendAdvert on; MinRtrAdvInterval 30; MaxRtrAdvInterval 60; AdvDefaultLifetime 180;
	prefix 2001:db8:77::/64 { AdvOnLink on; AdvAutonomous on; };
};
`), 0o644); err != nil {
		t.Fatal(err)
	}
	radvd := exec.Command("radvd", "-n", "-C", conf, "-p", filepath.Join(dir, "radvd.pid"), "-m", "stderr")
	if err := radvd.Start(); err != nil {
		t.Fatalf("radvd: %v", err)
	}
	t.Cleanup(func() { _ = radvd.Process.Kill(); _ = radvd.Wait() })
	route := func() string {
		out, _ := exec.Command("ip", "netns", "exec", "cli", "ip", "-6", "route", "show", "default").CombinedOutput()
		return strings.TrimSpace(string(out))
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(route(), "fe80::") && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	if !strings.Contains(route(), "fe80::") {
		t.Fatalf("no default route from radvd: %q", route())
	}

	s = &Sender{Ifaces: []string{"veth0"}, DNS: dns}
	run(s, 5*time.Second) // RS, nach 2 s das erste RA - radvd sendet erst nach 16 s wieder
	if s.Sent() != 0 {
		t.Fatalf("own RA beside radvd: sent %d", s.Sent())
	}
	if st := s.Status(); st[0].ErrKind != "self_router" {
		t.Fatalf("status %+v", st)
	}
	if r := route(); !strings.Contains(r, "fe80::") {
		t.Fatalf("default route lost: %q", r)
	}
}
