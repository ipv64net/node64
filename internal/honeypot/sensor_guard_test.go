package honeypot

import (
	"net"
	"net/netip"
	"testing"
)

// Limit je Quelle: IPv6 je /64, IPv4 je Adresse.
func TestSensorLimitKeyPrefix64(t *testing.T) {
	s := NewSensor(nil, t.TempDir())
	s.perIP.Store(2)
	a := netip.MustParseAddr("2001:db8:1:2::1")
	b := netip.MustParseAddr("2001:db8:1:2:ffff::9")
	c := netip.MustParseAddr("2001:db8:1:3::1")
	if !s.acquire(a) || !s.acquire(b) {
		t.Fatal("erste zwei abgewiesen")
	}
	if s.acquire(netip.MustParseAddr("2001:db8:1:2:abcd::1")) {
		t.Fatal("drittes aus demselben /64 zugelassen")
	}
	if !s.acquire(c) {
		t.Fatal("anderes /64 abgewiesen")
	}
	s.release(a)
	if !s.acquire(netip.MustParseAddr("2001:db8:1:2::7")) {
		t.Fatal("nach release weiter abgewiesen")
	}
	if got := sensorLimitKey(netip.MustParseAddr("192.0.2.7")); got != netip.MustParseAddr("192.0.2.7") {
		t.Fatalf("IPv4: %s", got)
	}
	if !s.acquire(netip.MustParseAddr("192.0.2.7")) || !s.acquire(netip.MustParseAddr("192.0.2.8")) || !s.acquire(netip.MustParseAddr("192.0.2.9")) {
		t.Fatal("IPv4 je Adresse")
	}
}

// Eine Panik im UDP-Dienst beendet weder den Prozess noch den Dienst; ein geschlossener Port beendet ihn.
func TestSensorUDPPanicRecovered(t *testing.T) {
	s := NewSensor(nil, t.TempDir())
	ts := &trapService{key: sensorKey{Service: "test", Port: 1}}
	n := 0
	p := &UDPProto{Service: "test", Handle: func(*Sensor, *trapService, net.PacketConn) {
		n++
		if n < 3 {
			panic("kaputt")
		}
	}}
	for s.serveUDP(ts, p, nil) {
	}
	if n != 3 {
		t.Fatalf("Aufrufe: %d", n)
	}
	func() {
		defer s.recoverPanic("test")
		panic("kaputt")
	}()
}
