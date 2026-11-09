//go:build linux

package dhcp

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
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

// syncStore speichert Vergaben gemeinsam und gibt sie an den anderen laufenden Server weiter (wie der Cluster).
type syncStore struct {
	mem  *memStore
	peer func() *Server
}

func (s syncStore) SaveLease(l Lease) error {
	_ = s.mem.SaveLease(l)
	if p := s.peer(); p != nil {
		p.Import(l)
	}
	return nil
}

func (s syncStore) DeleteLease(scope int64, mac string) error {
	_ = s.mem.DeleteLease(scope, mac)
	if p := s.peer(); p != nil {
		p.Forget(scope, mac)
	}
	return nil
}

// Failover simuliert (Bridge im Test-Container, nie im Heimnetz): Haupt-Node auf fp (10.98.0.1), Reserve auf fr
// (10.98.0.2), Geraet im Namensraum cf. Die Reserve schweigt, solange die Haupt-Node "im Cluster erreichbar" ist; faellt
// sie aus, bekommt das Geraet von der Reserve seine bisherige Adresse; kommt sie zurueck, schweigt die Reserve wieder
// und die Haupt-Node kennt die Vergaben der Reserve.
func TestIntegrationFailover(t *testing.T) {
	itOn(t)
	sh := func(args ...string) {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	sh("ip", "netns", "add", "cf")
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", "cf").Run()
		_ = exec.Command("ip", "link", "del", "brf").Run()
	})
	sh("ip", "link", "add", "brf", "type", "bridge")
	sh("ip", "link", "set", "brf", "up")
	for _, x := range []string{"fp", "fr", "fc"} {
		sh("ip", "link", "add", x, "type", "veth", "peer", "name", x+"b")
		sh("ip", "link", "set", x+"b", "master", "brf")
		sh("ip", "link", "set", x+"b", "up")
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", x+"b").Run() })
	}
	sh("ip", "link", "set", "fc", "netns", "cf")
	sh("ip", "netns", "exec", "cf", "ip", "link", "set", "fc", "up")
	sh("ip", "addr", "add", "10.98.0.1/24", "dev", "fp")
	sh("ip", "addr", "add", "10.98.0.2/24", "dev", "fr")
	sh("ip", "link", "set", "fp", "up")
	sh("ip", "link", "set", "fr", "up")
	time.Sleep(time.Second) // Bridge bereit

	scope := func(iface string) Scope {
		return Scope{ID: 1, Iface: iface, Subnet: netip.MustParsePrefix("10.98.0.0/24"), Start: netip.MustParseAddr("10.98.0.100"),
			End: netip.MustParseAddr("10.98.0.110"), Router: netip.MustParseAddr("10.98.0.1"), Lease: time.Hour, Authoritative: true}
	}
	shared := &memStore{leases: map[string]Lease{}}
	var primary, reserve atomic.Pointer[Server]
	var primaryOnline atomic.Bool
	start := func(s *Server) func() {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); s.Run(ctx) }()
		time.Sleep(300 * time.Millisecond)
		return func() { cancel(); <-done }
	}
	leases := func() []Lease {
		var out []Lease
		for _, l := range shared.all() {
			out = append(out, l)
		}
		return out
	}
	newPrimary := func() func() {
		s := New(Config{Scopes: []Scope{scope("fp")}, Leases: leases()}, syncStore{shared, reserve.Load}, nil)
		primary.Store(s)
		primaryOnline.Store(true)
		return start(s)
	}
	stopPrimary := newPrimary()
	r := New(Config{Scopes: []Scope{scope("fr")}}, syncStore{shared, primary.Load}, nil)
	r.Standby = func(netip.Prefix) bool { return primaryOnline.Load() } // Haupt-Node im Cluster erreichbar
	reserve.Store(r)
	stopReserve := start(r)
	defer stopReserve()

	client := func(extra ...string) string {
		args := append([]string{"netns", "exec", "cf", "udhcpc", "-i", "fc", "-n", "-q", "-f", "-t", "3", "-T", "1", "-s", "/bin/true"}, extra...)
		out, _ := exec.Command("ip", args...).CombinedOutput()
		return string(out)
	}
	// 1. Haupt-Node vergibt, Reserve schweigt
	out := client()
	if !strings.Contains(out, "obtained from 10.98.0.1") {
		t.Fatalf("primary lease: %s", out)
	}
	ip := strings.Fields(out[strings.Index(out, "lease of ")+len("lease of "):])[0]
	quiet := func() bool { // Reserve hat nichts angeboten oder vergeben, seit die Haupt-Node lebt
		for _, e := range r.Snapshot().Events {
			if e.Result == "offer" || e.Result == "ack" {
				return false
			}
			if e.Result == "standby" {
				return true
			}
		}
		return false
	}
	if !quiet() {
		t.Fatalf("reserve not in standby: %+v", r.Snapshot().Events)
	}
	// 2. Haupt-Node faellt aus: Reserve gibt dem Geraet seine Adresse (bekannt aus dem Abgleich)
	stopPrimary()
	primary.Store(nil)
	primaryOnline.Store(false)
	out = client("-r", ip)
	if !strings.Contains(out, "lease of "+ip+" obtained from 10.98.0.2") {
		t.Fatalf("failover: %s", out)
	}
	// 3. Haupt-Node zurueck: Reserve schweigt wieder, die Haupt-Node vergibt dieselbe Adresse
	stopPrimary = newPrimary()
	defer stopPrimary()
	out = client("-r", ip)
	if !strings.Contains(out, "lease of "+ip+" obtained from 10.98.0.1") {
		t.Fatalf("failback: %s", out)
	}
	if !quiet() {
		t.Fatalf("reserve answered after failback: %+v", r.Snapshot().Events)
	}
}
