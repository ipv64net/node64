package sonar

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestICMPPingLoopback(t *testing.T) {
	for _, mode := range []string{"ping", "raw"} {
		t.Run(mode, func(t *testing.T) {
			p := testProber(t)
			if !icmpMode(t, p, mode, 0) {
				return
			}
			res := p.Ping(context.Background(), Target{ID: "a_lo", Addr: "127.0.0.1", Family: 4, Method: MethodICMP, Count: 3}, time.Now())
			if res.Error != "" || res.Sent != 3 || res.Recv != 3 || res.AvgMs <= 0 {
				t.Fatalf("ICMP %s: %+v", mode, res)
			}
		})
	}
}

func TestICMPDenied(t *testing.T) {
	p := testProber(t)
	p.ping, p.raw = [2]bool{}, [2]bool{}
	if p.ICMPAllowed() {
		t.Fatal("ICMPAllowed ohne Sockets")
	}
	res := p.Ping(context.Background(), Target{ID: "a", Addr: "127.0.0.1", Family: 4, Method: MethodICMP, Count: 1}, time.Now())
	if res.Error != probeErrICMPDenied || res.Sent != 0 {
		t.Fatalf("ohne ICMP: %+v", res)
	}
}

// icmpMode stellt den Prober auf nur Ping-Socket bzw. nur Raw-Socket fuer Familie fi um (oder ueberspringt).
func icmpMode(t *testing.T, p *prober, mode string, fi int) bool {
	t.Helper()
	switch mode {
	case "ping":
		if !p.ping[fi] {
			t.Skip("kein Ping-Socket (net.ipv4.ping_group_range)")
			return false
		}
		p.raw[fi] = false
	case "raw":
		if !icmpCanListen([]string{"ip4:icmp", "ip6:ipv6-icmp"}[fi], []string{"0.0.0.0", "::"}[fi]) {
			t.Skip("kein Raw-Socket (cap_net_raw)")
			return false
		}
		p.ping[fi], p.raw[fi] = false, true
	case "udp":
		if runtime.GOOS != "linux" {
			t.Skip("UDP-Traceroute nur unter Linux")
			return false
		}
		p.ping[fi], p.raw[fi] = false, false
	}
	return true
}

func TestTraceEchoConstantChecksum(t *testing.T) {
	first := traceEcho(false, 4711, 1)
	for k := 2; k <= traceMaxTTL*traceMaxAttempts; k++ {
		b := traceEcho(false, 4711, k)
		if b[0] != 8 || b[2] != first[2] || b[3] != first[3] {
			t.Fatalf("Pruefsumme aendert sich bei k=%d: %x vs %x", k, b[2:4], first[2:4])
		}
		if int(binary.BigEndian.Uint16(b[6:8])) != k {
			t.Fatalf("Sequenz falsch bei k=%d", k)
		}
	}
	if b := traceEcho(true, 1, 1); b[0] != 128 {
		t.Fatalf("IPv6-Typ %d", b[0])
	}
}

func TestTraceQuoted(t *testing.T) {
	dst := netAddrPort("9.9.9.9", 0).Addr()
	q := make([]byte, 28)
	q[0], q[9] = 0x45, icmpProto4
	copy(q[16:20], []byte{9, 9, 9, 9})
	q[20] = 8
	binary.BigEndian.PutUint16(q[24:], 4711)
	binary.BigEndian.PutUint16(q[26:], 3)
	if !traceQuoted(false, q, dst, 4711, 3) {
		t.Fatal("passendes Zitat abgelehnt")
	}
	if traceQuoted(false, q, dst, 4711, 4) || traceQuoted(false, q, dst, 1, 3) ||
		traceQuoted(false, q, netAddrPort("8.8.8.8", 0).Addr(), 4711, 3) || traceQuoted(false, q[:10], dst, 4711, 3) {
		t.Fatal("fremdes Zitat angenommen")
	}
	if !traceQuoted(false, q[:20], dst, 4711, 3) {
		t.Fatal("Zitat nur mit IP-Kopf abgelehnt")
	}
	for i := range 64 {
		_ = traceQuoted(i%2 == 0, make([]byte, i), dst, 0, 0) // kurze Eingaben ohne Panik
	}
}

func TestTraceLoopback(t *testing.T) {
	for _, mode := range []string{"ping", "raw", "udp"} {
		t.Run(mode, func(t *testing.T) {
			p := testProber(t)
			if !icmpMode(t, p, mode, 0) {
				return
			}
			if mode == "udp" {
				_, p.udpPort = startResponder(t, "127.0.0.1:0", "a_lo")
			}
			res := p.Trace(context.Background(), Target{ID: "a_lo", Addr: "127.0.0.1", Family: 4, Method: MethodTrace, Count: 2, MaxTTL: 5}, time.Now())
			if res.Error != "" || len(res.Hops) != 1 || res.Hops[0].Addr != "127.0.0.1" || res.Hops[0].TTL != 1 ||
				res.Sent != 1 || res.Recv != 1 || res.AvgMs <= 0 {
				t.Fatalf("Trace %s: %+v", mode, res)
			}
		})
	}
}

func TestTraceLoopbackClosedPort(t *testing.T) {
	p := testProber(t)
	if !icmpMode(t, p, "udp", 0) {
		return
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip(err)
	}
	p.udpPort = c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	res := p.Trace(context.Background(), Target{ID: "n1", Addr: "127.0.0.1", Family: 4, Method: MethodTrace, Count: 1}, time.Now())
	if res.Error != "" || len(res.Hops) != 1 || res.Hops[0].Addr != "127.0.0.1" || res.Recv != 1 {
		t.Fatalf("Port unerreichbar vom Ziel muss die Traceroute beenden: %+v", res)
	}
}

// TestTraceNet misst echt ins Internet (nur mit SONAR64_NETTEST=1, z. B. auf der Box).
func TestTraceNet(t *testing.T) {
	if os.Getenv("SONAR64_NETTEST") != "1" {
		t.Skip("SONAR64_NETTEST=1 fuer echte Messungen")
	}
	addr := os.Getenv("SONAR64_NETTEST_ADDR")
	if addr == "" {
		addr = "9.9.9.9"
	}
	for _, mode := range []string{"ping", "raw", "udp"} {
		t.Run(mode, func(t *testing.T) {
			p := newProber(ProbeConfig{NodeID: "ntest", Gap: 50 * time.Millisecond})
			if !icmpMode(t, p, mode, 0) {
				return
			}
			tg := Target{ID: "x", Addr: addr, Family: 4, Method: MethodTrace, Count: 2, MaxTTL: 20}
			res := p.Trace(context.Background(), tg, time.Now())
			t.Logf("%s: sent %d recv %d err %q avg %.3f", mode, res.Sent, res.Recv, res.Error, res.AvgMs)
			for _, h := range res.Hops {
				t.Logf("  %2d %-40s %.3f", h.TTL, h.Addr, h.RTTMs)
			}
			if res.Error != "" || res.Recv < 2 {
				t.Fatalf("zu wenige Hops: %+v", res)
			}
			if mode != "udp" {
				tg.Method, tg.Count = MethodICMP, 3
				pr := p.Ping(context.Background(), tg, time.Now())
				t.Logf("ping: %+v", pr)
				if pr.Recv == 0 {
					t.Fatalf("kein Echo: %+v", pr)
				}
			}
		})
	}
}
