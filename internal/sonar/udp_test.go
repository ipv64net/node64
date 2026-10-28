package sonar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

func TestS64Format(t *testing.T) {
	nonce := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	short := udpShortID("n0123456789a")
	b := make([]byte, s64PacketLen)
	s64Encode(b, s64MagicReq, nonce, short)
	if string(b[:4]) != "S64?" || b[4] != 1 || b[5] != 1 || !bytes.Equal(b[6:14], nonce[:]) ||
		!bytes.Equal(b[14:18], short[:]) || !bytes.Equal(b[18:], make([]byte, 46)) {
		t.Fatalf("Anfrage falsch: %x", b)
	}
	sum := sha256.Sum256([]byte("n0123456789a"))
	if !bytes.Equal(short[:], sum[:4]) {
		t.Fatal("Kurz-ID ist nicht SHA-256(NodeID)[:4]")
	}
	n, s, ok := s64Parse(b, s64MagicReq)
	if !ok || n != nonce || s != short {
		t.Fatal("gueltige Anfrage abgelehnt")
	}
	if _, _, ok := s64Parse(b, s64MagicResp); ok {
		t.Fatal("Anfrage als Antwort angenommen")
	}
	bad := func(name string, mut func([]byte) []byte) {
		c := mut(append([]byte(nil), b...))
		if _, _, ok := s64Parse(c, s64MagicReq); ok {
			t.Errorf("%s angenommen", name)
		}
	}
	bad("63 Byte", func(c []byte) []byte { return c[:63] })
	bad("65 Byte", func(c []byte) []byte { return append(c, 0) })
	bad("leer", func(c []byte) []byte { return nil })
	bad("Kennung", func(c []byte) []byte { c[3] = '!'; c[0] = 's'; return c })
	bad("Version", func(c []byte) []byte { c[4] = 2; return c })
	bad("Typ", func(c []byte) []byte { c[5] = 2; return c })
	bad("Fuellung", func(c []byte) []byte { c[63] = 1; return c })
	bad("Fuellung vorne", func(c []byte) []byte { c[18] = 0xff; return c })
}

func FuzzS64Parse(f *testing.F) {
	b := make([]byte, s64PacketLen)
	s64Encode(b, s64MagicReq, [8]byte{9}, [4]byte{1, 2, 3, 4})
	f.Add(b)
	f.Add(b[:63])
	f.Add([]byte("S64?"))
	f.Add(bytes.Repeat([]byte{0}, 64))
	r := &Responder{short: udpShortID("nresp"), lim: newRespLimiter(), seen: map[respKey]*Inbound{}, loopback: true}
	f.Fuzz(func(t *testing.T, in []byte) {
		nonce, _, ok := s64Parse(in, s64MagicReq)
		if ok && len(in) != s64PacketLen {
			t.Fatal("falsche Laenge angenommen")
		}
		out := make([]byte, s64PacketLen)
		src := netAddrPort("127.0.0.1", 40000)
		answered := r.answer(in, src, time.Now(), out)
		if answered && !ok {
			t.Fatal("ungueltige Anfrage beantwortet")
		}
		if answered {
			n, s, ok := s64Parse(out, s64MagicResp)
			if !ok || n != nonce || s != r.short || len(out) > len(in) {
				t.Fatal("Antwort falsch")
			}
		}
		r.lim = newRespLimiter() // Ratenbegrenzung soll den Fuzzer nicht bremsen
	})
}

// startResponder startet einen Antworter auf Loopback und liefert seinen Port.
func startResponder(t *testing.T, addr, nodeID string) (*Responder, int) {
	t.Helper()
	r, err := NewResponder(addr, nodeID)
	if err != nil {
		t.Skipf("kein Loopback %s: %v", addr, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	return r, r.LocalAddr().(*net.UDPAddr).Port
}

func TestUDPProbeLoopback(t *testing.T) {
	for _, tc := range []struct {
		listen, addr string
		fam          int
	}{{"127.0.0.1:0", "127.0.0.1", 4}, {"[::1]:0", "::1", 6}} {
		t.Run(tc.addr, func(t *testing.T) {
			r, port := startResponder(t, tc.listen, "ntarget00001")
			p := testProber(t)
			p.udpPort = port
			res := p.Ping(context.Background(), Target{ID: "ntarget00001", Addr: tc.addr, Family: tc.fam, Method: MethodUDP, Count: 4}, time.Now())
			if res.Error != "" || res.Sent != 4 || res.Recv != 4 || res.MinMs <= 0 || res.AvgMs < res.MinMs || res.MaxMs < res.AvgMs {
				t.Fatalf("UDP-Probe: %+v", res)
			}
			in := r.Drain()
			want := hex.EncodeToString(p.short[:])
			if len(in) != 1 || in[0].From != want || in[0].Family != tc.fam || in[0].Count != 4 || in[0].At.IsZero() {
				t.Fatalf("Drain: %+v (want from %s)", in, want)
			}
			if again := r.Drain(); len(again) != 0 {
				t.Fatalf("zweites Drain nicht leer: %+v", again)
			}

			// falscher Knoten antwortet: nicht gezaehlt
			res = p.Ping(context.Background(), Target{ID: "nother000001", Addr: tc.addr, Family: tc.fam, Method: MethodUDP, Count: 2}, time.Now())
			if res.Recv != 0 || res.Sent != 2 || res.Error != probeErrWrongNode {
				t.Fatalf("falscher Knoten: %+v", res)
			}
		})
	}
}

func TestUDPProbeClosedPort(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	c.Close() // Port ist jetzt zu: ICMP Port unerreichbar
	p := testProber(t)
	p.udpPort = port
	res := p.Ping(context.Background(), Target{ID: "n1", Addr: "127.0.0.1", Family: 4, Method: MethodUDP, Count: 3}, time.Now())
	if res.Sent != 3 || res.Recv != 0 || res.Error != "" {
		t.Fatalf("geschlossener Port: %+v", res)
	}
}
