package sonar

import (
	"context"
	"math"
	"net/netip"
	"testing"
	"time"
)

func TestIsPublicAddr(t *testing.T) {
	cases := map[string]bool{
		"1.1.1.1": true, "8.8.8.8": true, "195.201.0.1": true, "2a01:4f8::1": true, "2606:4700::1111": true,
		"0.1.2.3": false, "10.1.2.3": false, "100.64.0.1": false, "127.0.0.1": false, "169.254.1.1": false,
		"172.16.0.1": false, "172.31.255.255": false, "192.0.0.8": false, "192.0.2.1": false, "192.168.1.1": false,
		"198.18.0.1": false, "198.51.100.1": false, "203.0.113.9": false, "224.0.0.1": false, "239.1.1.1": false,
		"240.0.0.1": false, "255.255.255.255": false,
		"::": false, "::1": false, "::ffff:10.0.0.1": false, "::ffff:1.1.1.1": false, "64:ff9b::a00:1": false,
		"fe80::1": false, "fc00::1": false, "fd12::1": false, "ff02::1": false, "2001:db8::1": false,
		"2002:a00:1::1": false, "2001::1": false, "3fff::1": false, "100::1": false, "fe80::1%eth0": false,
	}
	for s, want := range cases {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if got := isPublicAddr(a); got != want {
			t.Errorf("isPublicAddr(%s) = %v, want %v", s, got, want)
		}
	}
}

func TestTargetAddrFamily(t *testing.T) {
	if _, ok := targetAddr(Target{Addr: "1.1.1.1", Family: 6}); ok {
		t.Error("v4 address with fam 6 accepted")
	}
	if _, ok := targetAddr(Target{Addr: "2a01:4f8::1", Family: 4}); ok {
		t.Error("v6 address with fam 4 accepted")
	}
	if _, ok := targetAddr(Target{Addr: "example.com", Family: 4}); ok {
		t.Error("host name accepted")
	}
	if _, ok := targetAddr(Target{Addr: "1.1.1.1", Family: 4}); !ok {
		t.Error("public v4 rejected")
	}
}

func TestLimitsFor(t *testing.T) {
	if l := limitsFor(false, BudgetLow); l.targets != 8 || l.pps != 2 || l.day != 20000 {
		t.Errorf("low %+v", l)
	}
	if l := limitsFor(false, BudgetNormal); l.targets != 15 || l.day != 40000 {
		t.Errorf("normal %+v", l)
	}
	if l := limitsFor(false, BudgetHigh); l.targets != 20 || l.day != 60000 {
		t.Errorf("high %+v", l)
	}
	if l := limitsFor(false, "egal"); l.targets != 8 {
		t.Errorf("unknown %+v", l)
	}
	if l := limitsFor(true, BudgetLow); l.targets != 2000 || l.pps != 50 {
		t.Errorf("anchor %+v", l)
	}
}

func TestInQuiet(t *testing.T) {
	if inQuiet([2]int{0, 0}, 3) {
		t.Error("{0,0} must mean none")
	}
	q := [2]int{23, 6}
	for h, want := range map[int]bool{22: false, 23: true, 0: true, 5: true, 6: false, 12: false} {
		if inQuiet(q, h) != want {
			t.Errorf("23-6 hour %d", h)
		}
	}
	q = [2]int{1, 5}
	for h, want := range map[int]bool{0: false, 1: true, 4: true, 5: false} {
		if inQuiet(q, h) != want {
			t.Errorf("1-5 hour %d", h)
		}
	}
}

func TestBucketRate(t *testing.T) {
	now := time.Unix(1000, 0)
	b := newBucket(MaxPPS, func() time.Time { return now })
	if d := b.reserve(5); d != 0 {
		t.Fatalf("burst of 5 should pass, wait %v", d)
	}
	d := b.reserve(2)
	if d < 900*time.Millisecond || d > 1100*time.Millisecond {
		t.Fatalf("expected ~1 s wait for 2 packets at 2/s, got %v", d)
	}
	now = now.Add(time.Second)
	if d := b.reserve(2); d != 0 {
		t.Fatalf("after 1 s 2 packets allowed, wait %v", d)
	}
	// grosse Messung (Trace 90 Pakete) zieht ins Minus, danach lange Pause
	now = now.Add(10 * time.Second)
	if d := b.reserve(90); d != 0 {
		t.Fatalf("trace should start at full bucket, wait %v", d)
	}
	if d := b.reserve(1); d < 40*time.Second {
		t.Fatalf("after 90 packets the next must wait ~43 s, got %v", d)
	}
	// ueber 100 s im Mittel nie mehr als 2/s
	b = newBucket(MaxPPS, func() time.Time { return now })
	sent := 0
	start := now
	for now.Sub(start) < 100*time.Second {
		if b.reserve(1) == 0 {
			sent++
		} else {
			now = now.Add(50 * time.Millisecond)
		}
	}
	if sent > 2*100+MaxCount {
		t.Fatalf("sent %d packets in 100 s", sent)
	}
}

func TestBucketWaitCancel(t *testing.T) {
	b := newBucket(1, time.Now)
	b.reserve(5)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := b.wait(ctx, 5); err == nil {
		t.Fatal("wait must end with ctx")
	}
}

func TestCleanTarget(t *testing.T) {
	c, err := cleanTarget(Target{ID: "nabc123def45", Addr: "1.1.1.1", Family: 4, Method: MethodICMP, Count: 99}, false)
	if err != nil || c.Count != MaxCount {
		t.Fatalf("count not clamped: %+v %v", c, err)
	}
	c, err = cleanTarget(Target{ID: "a_fsn", Addr: "2a01:4f8::1", Family: 6, Method: MethodTrace, Count: 9, MaxTTL: 200}, false)
	if err != nil || c.Count != MaxTraceCount || c.MaxTTL != MaxTTL {
		t.Fatalf("trace not clamped: %+v %v", c, err)
	}
	if _, err := cleanTarget(Target{ID: "a_fsn", Addr: "2a01:4f8::1", Family: 6, Method: MethodTrace, Count: 1}, true); err == nil {
		t.Fatal("trace accepted as anchor fallback")
	}
	for _, bad := range []Target{
		{ID: "nabc123def45", Addr: "10.0.0.1", Family: 4, Method: MethodICMP, Count: 1},
		{ID: "nabc123def45", Addr: "1.1.1.1", Family: 4, Method: "tcp", Count: 1},
		{ID: "../etc", Addr: "1.1.1.1", Family: 4, Method: MethodICMP, Count: 1},
		{ID: "", Addr: "1.1.1.1", Family: 4, Method: MethodICMP, Count: 1},
	} {
		if _, err := cleanTarget(bad, false); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestRoundTargets(t *testing.T) {
	var ts []Target
	ts = append(ts, Target{ID: "n0000000self", Addr: "9.9.9.9", Family: 4, Method: MethodICMP, Count: 1})
	ts = append(ts, Target{ID: "nprivate0000", Addr: "192.168.0.1", Family: 4, Method: MethodICMP, Count: 1})
	for i := range 30 {
		ts = append(ts, Target{ID: "n" + pad11(i), Addr: "1.1.1." + itoa(i+1), Family: 4, Method: MethodUDP, Count: 3})
	}
	ts = append(ts[:3], append([]Target{ts[2]}, ts[3:]...)...) // Duplikat
	out := roundTargets(ts, MaxTargetsLow, "n0000000self", false)
	if len(out) != MaxTargetsLow {
		t.Fatalf("expected %d targets, got %d", MaxTargetsLow, len(out))
	}
	seen := map[string]bool{}
	for _, x := range out {
		if x.ID == "n0000000self" || x.Addr == "192.168.0.1" || seen[x.ID] {
			t.Fatalf("bad target kept: %+v", x)
		}
		seen[x.ID] = true
	}
}

func TestCleanResult(t *testing.T) {
	base := Result{Round: time.Unix(0, 0).UTC(), Target: "a_fsn", Family: 4, Method: MethodICMP}
	now := time.Now()
	r := cleanResult(Result{Target: "evil", Method: "x", Sent: 50, Recv: 70, MinMs: math.NaN(), AvgMs: 5, MaxMs: math.Inf(1),
		JitterMs: -1, Error: "<script>", At: now.Add(time.Hour)}, base, 3, now, now)
	if r.Target != "a_fsn" || r.Method != MethodICMP || r.Sent != 3 || r.Recv != 3 || r.MinMs != 0 || r.MaxMs != 5 ||
		r.JitterMs != 0 || r.Error != "error" || !r.At.Equal(now.UTC()) {
		t.Fatalf("not cleaned: %+v", r)
	}
	tb := base
	tb.Method = MethodTrace
	r = cleanResult(Result{Sent: 3, Recv: 3, Hops: []Hop{{TTL: 1, Addr: "192.168.1.1", RTTMs: 1}, {TTL: 2, Addr: "80.1.2.3", RTTMs: 5},
		{TTL: 99, Addr: "1.1.1.1"}}}, tb, 90, now, now)
	if len(r.Hops) != 2 || r.Hops[0].Addr != "" || r.Hops[1].Addr != "80.1.2.3" {
		t.Fatalf("hops not cleaned: %+v", r.Hops)
	}
}

func TestDropCount(t *testing.T) {
	if k := dropCount(0, 0, 5, 10); k != 5 {
		t.Fatal(k)
	}
	if k := dropCount(3, 0, 5, 10); k != 2 { // vorne wurden 3 schon verworfen
		t.Fatal(k)
	}
	if k := dropCount(9, 0, 5, 10); k != 0 {
		t.Fatal(k)
	}
}

func pad11(i int) string {
	s := itoa(i)
	for len(s) < 11 {
		s = "0" + s
	}
	return s
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
