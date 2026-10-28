package cdnedge

import (
	"net"
	"net/netip"
	"testing"
)

// Absender ohne Nachweis (UDP, QUIC vor dem Handschlag): eigenes Budget, nicht die Plaetze der Verbindungen.
func TestGuardUDPBudget(t *testing.T) {
	g := newGuard(ShieldConfig{MaxConns: 8, ConnsPerIP: 1, ConnRate: -1})
	a := netip.MustParseAddr("192.0.2.1")
	var rel []func()
	for range 2 { // max_conns / 4
		r, why := g.admitUDP(a, nil)
		if why != "" {
			t.Fatalf("udp: %s", why)
		}
		rel = append(rel, r)
	}
	if _, why := g.admitUDP(netip.MustParseAddr("192.0.2.2"), nil); why != "max_conns" {
		t.Fatalf("udp budget: %q", why)
	}
	if r, why := g.admit(a); why != "" || g.open.Load() != 1 { // TCP-Platz der IP unberuehrt
		t.Fatalf("tcp after udp: %q open %d", why, g.open.Load())
	} else {
		r()
	}
	rel[0]()
	rel[0]()
	if g.udpOpen.Load() != 1 {
		t.Fatalf("udp open: %d", g.udpOpen.Load())
	}
	// guardConn: frei erst mit Close
	r, _ := g.admit(a)
	c1, c2 := net.Pipe()
	defer c2.Close()
	gc := &guardConn{Conn: c1, release: r}
	if _, why := g.admit(a); why != "conns" {
		t.Fatalf("slot not held: %q", why)
	}
	_ = gc.Close()
	_ = gc.Close()
	if g.open.Load() != 0 {
		t.Fatalf("open after close: %d", g.open.Load())
	}
}

// QUIC auf 443: ohne Nachweis nur im UDP-Budget; ab qgRetryAt offenen Handschlaegen verlangt quic-go ein Retry.
func TestQUICGate(t *testing.T) {
	g := newGuard(ShieldConfig{MaxConns: 1000, ConnsPerIP: 1, ConnRate: -1})
	q := newQUICGate(g)
	for i := range qgRetryAt {
		ap := netip.AddrPortFrom(netip.MustParseAddr("198.51.100.7"), uint16(1000+i))
		if !q.admit(net.UDPAddrFromAddrPort(ap), false) {
			t.Fatalf("unverified %d rejected", i)
		}
	}
	if g.open.Load() != 0 || !q.verify(nil) {
		t.Fatalf("open %d retry %v", g.open.Load(), q.verify(nil))
	}
	// mit Nachweis: wie TCP (conns_per_ip = 1)
	v := &net.UDPAddr{IP: net.ParseIP("198.51.100.8"), Port: 1}
	if !q.admit(v, true) || q.admit(&net.UDPAddr{IP: v.IP, Port: 2}, true) {
		t.Fatal("verified admission")
	}
	q.take(v.String(), nil)
	q.take("198.51.100.7:1000", nil)
	if g.open.Load() != 0 || q.pend.Load() != qgRetryAt-1 || q.verify(nil) {
		t.Fatalf("after release: open %d pend %d", g.open.Load(), q.pend.Load())
	}
}

// Modus-1-QUIC: Nachweis ueber die Verbindungs-ID der Node.
func TestQUICProof(t *testing.T) {
	// lange Pakete: 0xc0, Version, DCID-Laenge, DCID, SCID-Laenge, SCID
	long := func(dcid, scid []byte) []byte {
		p := []byte{0xc0, 0, 0, 0, 1, byte(len(dcid))}
		p = append(p, dcid...)
		p = append(p, byte(len(scid)))
		p = append(p, scid...)
		return append(p, make([]byte, 20)...)
	}
	sc := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if id := nodeSCID(long([]byte{9, 9}, sc)); string(id) != string(sc) {
		t.Fatalf("scid: %x", id)
	}
	vn := long([]byte{9}, sc)
	vn[1], vn[2], vn[3], vn[4] = 0, 0, 0, 0
	if nodeSCID(vn) != nil || nodeSCID([]byte{0x40, 1, 2, 3, 4, 5, 6, 7}) != nil {
		t.Fatal("version negotiation or short header")
	}
	f := &qflow{}
	if f.answers(long(sc, nil)) {
		t.Fatal("proof without node id")
	}
	f.scid.Store(&sc)
	short := append([]byte{0x40}, sc...)
	short = append(short, make([]byte, 30)...)
	if !f.answers(long(sc, []byte{7})) || !f.answers(short) || f.answers(long([]byte{1, 2, 3, 4}, nil)) || f.answers(append([]byte{0x40, 1, 2}, make([]byte, 30)...)) {
		t.Fatal("answers")
	}
}
