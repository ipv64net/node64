package sonar

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func netAddrPort(ip string, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr(ip), port)
}

func TestRespLimiterPerSource(t *testing.T) {
	l := newRespLimiter()
	now := time.Unix(1000, 0)
	a := netip.MustParseAddr("8.8.8.8")
	for i := 0; i < respPerSourceRate; i++ {
		if !l.allow(a, now) {
			t.Fatalf("Paket %d abgelehnt", i)
		}
	}
	if l.allow(a, now) {
		t.Fatal("6. Paket in derselben Sekunde erlaubt")
	}
	if !l.allow(netip.MustParseAddr("8.8.4.4"), now) {
		t.Fatal("andere Quelle abgelehnt")
	}
	if l.allow(a, now.Add(100*time.Millisecond)) {
		t.Fatal("nach 100 ms schon wieder erlaubt (0,5 Token)")
	}
	if !l.allow(a, now.Add(300*time.Millisecond)) {
		t.Fatal("nach 300 ms kein Token")
	}
	// IPv6: ein /64 teilt sich die Grenze
	b1, b2 := netip.MustParseAddr("2a00:1:2:3::1"), netip.MustParseAddr("2a00:1:2:3:ffff::9")
	for i := 0; i < respPerSourceRate; i++ {
		l.allow(b1, now)
	}
	if l.allow(b2, now) {
		t.Fatal("gleiches /64 nicht gemeinsam begrenzt")
	}
	if !l.allow(netip.MustParseAddr("2a00:1:2:4::1"), now) {
		t.Fatal("anderes /64 abgelehnt")
	}
}

func TestRespLimiterTotal(t *testing.T) {
	l := newRespLimiter()
	now := time.Unix(1000, 0)
	ok := 0
	for i := 0; i < 200; i++ {
		a := netip.AddrFrom4([4]byte{8, 8, byte(i / 256), byte(i)})
		if l.allow(a, now) {
			ok++
		}
	}
	if ok != respTotalRate {
		t.Fatalf("gesamt %d erlaubt, want %d", ok, respTotalRate)
	}
	if l.allow(netip.MustParseAddr("9.9.9.9"), now.Add(10*time.Millisecond)) {
		t.Fatal("nach 10 ms schon wieder erlaubt (0,5 Token gesamt)")
	}
	if !l.allow(netip.MustParseAddr("9.9.9.9"), now.Add(30*time.Millisecond)) {
		t.Fatal("nach 30 ms kein Token gesamt")
	}
}

func TestRespLimiterMemory(t *testing.T) {
	l := newRespLimiter()
	now := time.Unix(1000, 0)
	for i := 0; i < respMaxSources+500; i++ {
		l.allow(netip.AddrFrom4([4]byte{11, byte(i >> 16), byte(i >> 8), byte(i)}), now.Add(time.Duration(i)*time.Microsecond))
	}
	if len(l.src) > respMaxSources {
		t.Fatalf("%d Quellen gemerkt, Grenze %d", len(l.src), respMaxSources)
	}
	if l.allow(netip.MustParseAddr("12.0.0.1"), now.Add(50*time.Millisecond)) {
		t.Fatal("neue Quelle trotz voller Tabelle erlaubt")
	}
	later := now.Add(2 * time.Second)
	if !l.allow(netip.MustParseAddr("12.0.0.1"), later) {
		t.Fatal("nach Ruhe keine neue Quelle moeglich")
	}
	if len(l.src) > 10 {
		t.Fatalf("alte Quellen nicht entfernt: %d", len(l.src))
	}
}

func TestResponderAnswerRules(t *testing.T) {
	r := &Responder{short: udpShortID("nresp"), lim: newRespLimiter(), seen: map[respKey]*Inbound{}}
	req := make([]byte, s64PacketLen)
	s64Encode(req, s64MagicReq, [8]byte{7}, udpShortID("nsender"))
	out := make([]byte, s64PacketLen)
	now := time.Now()
	for _, c := range []struct {
		src  string
		port uint16
		want bool
	}{
		{"8.8.8.8", 40000, true}, {"::ffff:8.8.4.4", 40000, true}, {"2a00:1450::1", 50000, true},
		{"8.8.8.8", 53, false}, {"8.8.8.8", 0, false},
		{"127.0.0.1", 40000, false}, {"192.168.1.10", 40000, false}, {"10.0.0.1", 40000, false},
		{"::1", 40000, false}, {"fe80::1", 40000, false}, {"fd00::1", 40000, false}, {"224.0.0.1", 40000, false},
	} {
		if got := r.answer(req, netAddrPort(c.src, c.port), now, out); got != c.want {
			t.Errorf("answer von %s:%d = %v, want %v", c.src, c.port, got, c.want)
		}
	}
	r.loopback = true
	if !r.answer(req, netAddrPort("127.0.0.1", 40000), now, out) {
		t.Fatal("Loopback-Testmodus beantwortet Loopback nicht")
	}
	if r.answer(req, netAddrPort("192.168.1.10", 40000), now, out) {
		t.Fatal("Loopback-Testmodus beantwortet private Quelle")
	}
	in := r.Drain()
	// 8.8.8.8 und ::ffff:8.8.4.4 sind IPv4, 2a00:… IPv6, dazu Loopback (IPv4)
	if len(in) != 2 || in[0].Family != 4 || in[0].Count != 3 || in[1].Family != 6 || in[1].Count != 1 {
		t.Fatalf("Drain: %+v", in)
	}
}

func TestResponderSeenBounded(t *testing.T) {
	r := &Responder{short: udpShortID("nresp"), lim: newRespLimiter(), seen: map[respKey]*Inbound{}}
	out := make([]byte, s64PacketLen)
	now := time.Unix(1000, 0)
	req := make([]byte, s64PacketLen)
	for i := 0; i < respMaxSeen+100; i++ {
		s64Encode(req, s64MagicReq, [8]byte{}, [4]byte{byte(i >> 8), byte(i), 1, 2})
		r.lim = newRespLimiter()
		r.answer(req, netAddrPort("8.8.8.8", 40000), now, out)
	}
	if n := len(r.Drain()); n != respMaxSeen {
		t.Fatalf("%d Eintraege, Grenze %d", n, respMaxSeen)
	}
}

func TestResponderLoopbackRate(t *testing.T) {
	_, port := startResponder(t, "127.0.0.1:0", "nresp")
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req := make([]byte, s64PacketLen)
	// ungueltige Pakete: keine Antwort
	for _, b := range [][]byte{req[:10], make([]byte, 63), make([]byte, 65), make([]byte, 1400)} {
		_, _ = c.Write(b)
	}
	for i := 0; i < 20; i++ {
		s64Encode(req, s64MagicReq, [8]byte{byte(i)}, [4]byte{1})
		if _, err := c.Write(req); err != nil {
			t.Fatal(err)
		}
	}
	got := 0
	buf := make([]byte, 2048)
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		n, err := c.Read(buf)
		if err != nil {
			break
		}
		if n != s64PacketLen {
			t.Fatalf("Antwort %d Byte", n)
		}
		if _, s, ok := s64Parse(buf[:n], s64MagicResp); !ok || s != udpShortID("nresp") {
			t.Fatalf("Antwort ungueltig: %x", buf[:n])
		}
		got++
	}
	if got < respPerSourceRate || got > respPerSourceRate+1 {
		t.Fatalf("%d Antworten auf 20 schnelle Anfragen, want %d", got, respPerSourceRate)
	}
}

func TestNewResponderNeedsID(t *testing.T) {
	if _, err := NewResponder("127.0.0.1:0", ""); err == nil {
		t.Fatal("Antworter ohne Node-ID")
	}
	r, err := NewResponder("127.0.0.1:0", "n1")
	if err != nil {
		t.Skip(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal("zweites Close:", err)
	}
}
