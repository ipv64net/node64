//go:build linux

package dhcp

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Echte Sockets in einem Test-Container (nie im Heimnetz): veth0 (10.99.0.1/24, Server) und veth1 im Namensraum
// cli (Client busybox udhcpc, fremder Server dnsmasq). Nur mit DHCP_IT=1, z. B.:
//
//	docker run --rm --privileged -v $PWD:/src -w /src golang:1.27-alpine sh -c 'apk add -q iproute2 dnsmasq &&
//	  ip netns add cli && ip link add veth0 type veth peer name veth1 && ip link set veth1 netns cli &&
//	  ip addr add 10.99.0.1/24 dev veth0 && ip link set veth0 up && ip netns exec cli ip link set veth1 up &&
//	  DHCP_IT=1 go test -run Integration -v ./internal/dns64/dhcp/'
func itScope() Scope {
	return Scope{ID: 1, Iface: "veth0", Subnet: netip.MustParsePrefix("10.99.0.0/24"), Start: netip.MustParseAddr("10.99.0.100"),
		End: netip.MustParseAddr("10.99.0.110"), Router: netip.MustParseAddr("10.99.0.1"), Domain: "it.lan", Lease: time.Hour, Authoritative: true}
}

func itRun(t *testing.T, cfg Config) (*Server, *memStore) {
	t.Helper()
	st := &memStore{leases: map[string]Lease{}}
	s := New(cfg, st, nil)
	s.Probe = ARPProbe
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(200 * time.Millisecond)
	if v := s.Snapshot(); v.Scopes[0].Error != "" {
		t.Fatalf("scope error: %s", v.Scopes[0].Error)
	}
	return s, st
}

// cli fuehrt ein Programm im Namensraum des Clients aus.
func cli(args ...string) *exec.Cmd {
	return exec.Command("ip", append([]string{"netns", "exec", "cli"}, args...)...)
}

func udhcpc(t *testing.T) string {
	t.Helper()
	out, _ := cli("udhcpc", "-i", "veth1", "-n", "-q", "-f", "-t", "3", "-T", "1", "-s", "/bin/true", "-x", "hostname:it-client").CombinedOutput()
	return string(out)
}

func itOn(t *testing.T) {
	if os.Getenv("DHCP_IT") != "1" {
		t.Skip("DHCP_IT=1 fehlt")
	}
}

func TestIntegrationLease(t *testing.T) {
	itOn(t)
	s, st := itRun(t, Config{Scopes: []Scope{itScope()}})
	out := udhcpc(t)
	if !strings.Contains(out, "lease of 10.99.0.100 obtained") {
		t.Fatalf("udhcpc: %s", out)
	}
	leases := st.all()
	if len(leases) != 1 {
		t.Fatalf("leases %+v", leases)
	}
	for _, l := range leases {
		if l.IP != netip.MustParseAddr("10.99.0.100") || l.State != StateBound || l.Hostname != "it-client" {
			t.Fatalf("lease %+v", l)
		}
	}
	// derselbe Client bekommt dieselbe Adresse wieder
	if out := udhcpc(t); !strings.Contains(out, "lease of 10.99.0.100 obtained") {
		t.Fatalf("again: %s", out)
	}
	if n := len(s.Snapshot().Events); n < 4 {
		t.Fatalf("events %d", n)
	}
}

func TestIntegrationObserve(t *testing.T) {
	itOn(t)
	s, st := itRun(t, Config{Scopes: []Scope{itScope()}, Observe: true})
	if out := udhcpc(t); strings.Contains(out, "obtained") {
		t.Fatalf("observe answered: %s", out)
	}
	v := s.Snapshot()
	if len(st.all()) != 0 || len(v.Events) == 0 || v.Events[0].Result != "observe" {
		t.Fatalf("observe: leases %d events %+v", len(st.all()), v.Events)
	}
}

// Fremder Server: dnsmasq auf veth1 (10.99.0.2) antwortet auf das Pruef-DISCOVER; die ARP-Pruefung findet seine
// Adresse.
func TestIntegrationForeignAndARP(t *testing.T) {
	itOn(t)
	if out, err := cli("ip", "addr", "add", "10.99.0.2/24", "dev", "veth1").CombinedOutput(); err != nil {
		t.Fatalf("ip addr: %v %s", err, out)
	}
	defer cli("ip", "addr", "del", "10.99.0.2/24", "dev", "veth1").Run()
	if !ARPProbe("veth0", netip.MustParseAddr("10.99.0.1"), netip.MustParseAddr("10.99.0.2")) {
		t.Error("arp: 10.99.0.2 not found")
	}
	if ARPProbe("veth0", netip.MustParseAddr("10.99.0.1"), netip.MustParseAddr("10.99.0.105")) {
		t.Error("arp: 10.99.0.105 answered")
	}
	if _, err := exec.LookPath("dnsmasq"); err != nil {
		t.Skip("dnsmasq fehlt (apk add dnsmasq)")
	}
	srv := cli("dnsmasq", "-k", "--port=0", "--interface=veth1", "--bind-interfaces", "--dhcp-range=10.99.0.200,10.99.0.210,1h", "--dhcp-leasefile=/tmp/dnsmasq.leases")
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Process.Kill(); _ = srv.Wait() }()
	time.Sleep(300 * time.Millisecond)
	s, _ := itRun(t, Config{Scopes: []Scope{itScope()}})
	s.checkForeign(context.Background())
	v := s.Snapshot()
	if len(v.Foreign) != 1 || v.Foreign[0].Server != netip.MustParseAddr("10.99.0.2") {
		t.Fatalf("foreign %+v", v.Foreign)
	}
}
