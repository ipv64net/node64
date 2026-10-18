package quicsni

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// firstFlight: Datagramme, die ein echter quic-go-Client zuerst schickt (es antwortet niemand).
func firstFlight(t *testing.T, sni string, v quic.Version) [][]byte {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	go func() {
		_, _ = quic.DialAddr(ctx, pc.LocalAddr().String(), &tls.Config{ServerName: sni, NextProtos: []string{"h3"}, InsecureSkipVerify: true}, //nolint:gosec // Test
			&quic.Config{Versions: []quic.Version{v}})
	}()
	var out [][]byte
	buf := make([]byte, 2048)
	_ = pc.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		out = append(out, append([]byte(nil), buf[:n]...))
	}
	if len(out) == 0 {
		t.Fatal("no packets from the client")
	}
	return out
}

func TestSNIFromRealClient(t *testing.T) {
	for _, v := range []quic.Version{quic.Version1, quic.Version2} {
		pkts := firstFlight(t, "shop.example-name.test", v)
		var a Assembler
		var dcid []byte
		done := false
		for _, p := range pkts {
			if !IsInitial(p) {
				continue
			}
			d, chunks, err := Parse(p)
			if err != nil {
				t.Fatalf("v%x parse: %v", v, err)
			}
			if dcid != nil && !bytes.Equal(d, dcid) {
				continue // Wiederholung mit neuer ID (kommt hier nicht vor)
			}
			dcid = d
			if a.Add(chunks) {
				done = true
				break
			}
		}
		if !done {
			t.Fatalf("v%x: client hello not complete after %d packets", v, len(pkts))
		}
		h, _ := a.Hello()
		if n, ok := ServerName(h); !ok || n != "shop.example-name.test" {
			t.Fatalf("v%x: sni %q %v", v, n, ok)
		}
		t.Logf("v%x: client hello %d bytes", v, len(h))
	}
}

func TestNotInitial(t *testing.T) {
	for _, b := range [][]byte{nil, {0x40, 1, 2, 3}, bytes.Repeat([]byte{0xc0}, 30), append([]byte{0xc0, 0, 0, 0, 1, 8}, make([]byte, 40)...)} {
		if _, _, err := Parse(b); err == nil {
			t.Fatalf("parsed garbage %x", b)
		}
	}
	// Reihenfolge der Stuecke egal, Ueberlappung erlaubt
	hello := []byte{1, 0, 0, 6, 1, 2, 3, 4, 5, 6}
	var a Assembler
	if a.Add([]Chunk{{Offset: 5, Data: hello[5:]}}) || !a.Add([]Chunk{{Offset: 0, Data: hello[:7]}}) {
		t.Fatal("assembler order/overlap")
	}
	if h, _ := a.Hello(); !bytes.Equal(h, hello) {
		t.Fatalf("hello %x", h)
	}
}
