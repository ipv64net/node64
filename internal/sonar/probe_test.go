package sonar

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// testProber ist ein Prober fuer Loopback-Tests (kurze Abstaende, Loopback erlaubt).
func testProber(t *testing.T) *prober {
	t.Helper()
	p := newProber(ProbeConfig{NodeID: "ntestsender1", Timeout: 300 * time.Millisecond, Gap: 20 * time.Millisecond})
	p.allowLoopback = true
	return p
}

func TestProbePublic(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8": true, "1.1.1.1": true, "2a00:1450:4001::1": true, "2606:4700::1111": true,
		"10.1.2.3": false, "172.16.0.1": false, "192.168.178.1": false, "100.64.0.1": false, "127.0.0.1": false,
		"169.254.1.1": false, "0.1.2.3": false, "224.0.0.1": false, "255.255.255.255": false, "198.18.0.1": false,
		"192.0.2.1": false, "203.0.113.5": false, "240.0.0.1": false,
		"::1": false, "::": false, "fe80::1": false, "fc00::1": false, "fd12::1": false, "ff02::1": false,
		"2001:db8::1": false, "2002:c000:201::1": false, "2001::1": false, "64:ff9b::808:808": false,
		"::ffff:8.8.8.8": false, "::ffff:10.0.0.1": false, "3fff::1": false, "3ffe::1": false,
	}
	for s, want := range cases {
		if got := probePublic(netip.MustParseAddr(s)); got != want {
			t.Errorf("probePublic(%s) = %v, want %v", s, got, want)
		}
	}
	if probePublic(netip.MustParseAddr("fe80::1%eth0")) || probePublic(netip.Addr{}) {
		t.Error("zone or invalid address accepted")
	}
}

func TestPingChecks(t *testing.T) {
	p := newProber(ProbeConfig{NodeID: "nx"})
	ctx := context.Background()
	round := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		t    Target
		want string
	}{
		{Target{ID: "a", Addr: "10.0.0.1", Family: 4, Method: MethodICMP, Count: 1}, probeErrDenied},
		{Target{ID: "a", Addr: "127.0.0.1", Family: 4, Method: MethodUDP, Count: 1}, probeErrDenied},
		{Target{ID: "a", Addr: "192.168.1.1", Family: 4, Method: MethodUDP, Count: 1}, probeErrDenied},
		{Target{ID: "a", Addr: "fd00::1", Family: 6, Method: MethodUDP, Count: 1}, probeErrDenied},
		{Target{ID: "a", Addr: "8.8.8.8", Family: 6, Method: MethodICMP, Count: 1}, probeErrInvalid},
		{Target{ID: "a", Addr: "2a00::1", Family: 4, Method: MethodICMP, Count: 1}, probeErrInvalid},
		{Target{ID: "a", Addr: "::ffff:8.8.8.8", Family: 4, Method: MethodICMP, Count: 1}, probeErrInvalid},
		{Target{ID: "a", Addr: "8.8.8.8", Family: 5, Method: MethodICMP, Count: 1}, probeErrInvalid},
		{Target{ID: "a", Addr: "dns.google", Family: 4, Method: MethodICMP, Count: 1}, probeErrInvalid},
		{Target{ID: "a", Addr: "8.8.8.8", Family: 4, Method: MethodICMP, Count: 0}, probeErrInvalid},
		{Target{ID: "a", Addr: "8.8.8.8", Family: 4, Method: MethodICMP, Count: 6}, probeErrInvalid},
		{Target{ID: "a", Addr: "8.8.8.8", Family: 4, Method: "tcp", Count: 1}, probeErrInvalid},
		{Target{ID: "a", Addr: "8.8.8.8", Family: 4, Method: MethodTrace, Count: 1}, probeErrInvalid},
	}
	for _, c := range cases {
		r := p.Ping(ctx, c.t, round)
		if r.Error != c.want || r.Sent != 0 {
			t.Errorf("Ping(%+v) = err %q sent %d, want %q", c.t, r.Error, r.Sent, c.want)
		}
		if r.Target != c.t.ID || !r.Round.Equal(round) || r.At.IsZero() || r.At.Location() != time.UTC {
			t.Errorf("Ping(%+v): Kopf falsch: %+v", c.t, r)
		}
	}
}

func TestTraceChecks(t *testing.T) {
	p := newProber(ProbeConfig{NodeID: "nx"})
	ctx := context.Background()
	cases := []struct {
		t    Target
		want string
	}{
		{Target{ID: "a", Addr: "10.0.0.1", Family: 4, Method: MethodTrace, Count: 1}, probeErrDenied},
		{Target{ID: "a", Addr: "8.8.8.8", Family: 4, Method: MethodTrace, Count: 0}, probeErrInvalid},
		{Target{ID: "a", Addr: "8.8.8.8", Family: 4, Method: MethodTrace, Count: 4}, probeErrInvalid},
		{Target{ID: "a", Addr: "8.8.8.8", Family: 4, Method: MethodTrace, Count: 1, MaxTTL: 31}, probeErrInvalid},
		{Target{ID: "a", Addr: "8.8.8.8", Family: 4, Method: MethodTrace, Count: 1, MaxTTL: -1}, probeErrInvalid},
	}
	for _, c := range cases {
		r := p.Trace(ctx, c.t, time.Now())
		if r.Error != c.want || r.Sent != 0 || r.Method != MethodTrace {
			t.Errorf("Trace(%+v) = err %q sent %d, want %q", c.t, r.Error, r.Sent, c.want)
		}
	}
}

func TestProberDefaults(t *testing.T) {
	p := newProber(ProbeConfig{})
	if p.cfg.Timeout != time.Second || p.cfg.Gap != 500*time.Millisecond || p.udpPort != Port {
		t.Fatalf("Standardwerte falsch: %+v port %d", p.cfg, p.udpPort)
	}
	p = newProber(ProbeConfig{Timeout: time.Hour, Gap: time.Nanosecond})
	if p.cfg.Timeout != probeMaxTimeout || p.cfg.Gap != probeMinGap {
		t.Fatalf("Grenzen nicht angewandt: %+v", p.cfg)
	}
}

func TestProbeStats(t *testing.T) {
	ms := time.Millisecond
	var r Result
	probeStats(&r, []time.Duration{10 * ms, -1, 14 * ms, 12 * ms, -1}, 5)
	if r.Sent != 5 || r.Recv != 3 || r.MinMs != 10 || r.MaxMs != 14 || r.AvgMs != 12 || r.JitterMs != 3 {
		t.Fatalf("Statistik falsch: %+v", r)
	}
	r = Result{}
	probeStats(&r, []time.Duration{-1, -1}, 2)
	if r.Sent != 2 || r.Recv != 0 || r.MinMs != 0 || r.JitterMs != 0 {
		t.Fatalf("Verlust falsch: %+v", r)
	}
	r = Result{}
	probeStats(&r, []time.Duration{1234567 * time.Nanosecond}, 1)
	if r.MinMs != 1.235 || r.AvgMs != 1.235 || r.JitterMs != 0 {
		t.Fatalf("Rundung falsch: %+v", r)
	}
}

func TestProbeCanceled(t *testing.T) {
	p := testProber(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := p.Ping(ctx, Target{ID: "a", Addr: "127.0.0.1", Family: 4, Method: MethodUDP, Count: 3}, time.Now())
	if r.Error != probeErrCanceled || r.Sent != 0 {
		t.Fatalf("abgebrochene Messung: %+v", r)
	}
}
