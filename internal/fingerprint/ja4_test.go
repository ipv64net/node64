package fingerprint

import (
	"crypto/tls"
	"encoding/binary"
	"net"
	"regexp"
	"testing"
	"time"
)

// u16s haengt eine Liste von 16-Bit-Werten an.
func u16s(vs ...uint16) []byte {
	var b []byte
	for _, v := range vs {
		b = binary.BigEndian.AppendUint16(b, v)
	}
	return b
}

// ext baut eine Extension (Typ, Laenge, Daten).
func ext(typ uint16, data []byte) []byte {
	return append(u16s(typ, uint16(len(data))), data...)
}

// len16 setzt eine 16-Bit-Laenge vor die Daten.
func len16(data []byte) []byte { return append(u16s(uint16(len(data))), data...) }

// clientHello baut ein ClientHello wie Chrome (Beispiel der JA4-Spezifikation: 15 Cipher, 16 Extensions, h2) als
// Handshake-Nachricht mit Kopf. sni/alpn schaltbar.
func clientHello(sni bool, alpn [][]byte) []byte {
	body := u16s(0x0303)
	body = append(body, make([]byte, 32)...) // Random
	body = append(body, 32)                  // Session-ID
	body = append(body, make([]byte, 32)...)
	body = append(body, len16(u16s(0x2a2a, // GREASE
		0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035))...)
	body = append(body, 1, 0) // Kompression: null
	var e []byte
	e = append(e, ext(0x0a0a, nil)...) // GREASE
	if sni {
		name := []byte("example.com")
		e = append(e, ext(0x0000, len16(append([]byte{0}, len16(name)...)))...)
	}
	for _, x := range [][]byte{
		ext(0x0017, nil), ext(0xff01, []byte{0}), ext(0x000a, len16(u16s(0x3a3a, 0x001d, 0x0017, 0x0018))),
		ext(0x000b, []byte{1, 0}), ext(0x0023, nil),
	} {
		e = append(e, x...)
	}
	if alpn != nil {
		var l []byte
		for _, p := range alpn {
			l = append(append(l, byte(len(p))), p...)
		}
		e = append(e, ext(0x0010, len16(l))...)
	}
	for _, x := range [][]byte{
		ext(0x0005, []byte{1, 0, 0, 0, 0}),
		ext(0x000d, len16(u16s(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601))),
		ext(0x0012, nil), ext(0x0033, len16(append(u16s(0x001d, 32), make([]byte, 32)...))), ext(0x002d, []byte{1, 1}),
		ext(0x002b, append([]byte{6}, u16s(0x6a6a, 0x0304, 0x0303)...)), ext(0x001b, []byte{2, 0, 2}),
		ext(0x4469, len16([]byte{2, 'h', '2'})), ext(0x1a1a, []byte{0}), ext(0x0015, make([]byte, 20)),
	} {
		e = append(e, x...)
	}
	body = append(body, len16(e)...)
	return append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

// records verpackt eine Handshake-Nachricht in TLS-Records zu hoechstens size Bytes.
func records(hs []byte, size int) []byte {
	var out []byte
	for len(hs) > 0 {
		n := min(size, len(hs))
		out = append(append(out, 0x16, 3, 1), len16(hs[:n])...)
		hs = hs[n:]
	}
	return out
}

func TestJA4SpecVector(t *testing.T) {
	// Beispiel aus der JA4-Spezifikation (FoxIO)
	const want = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	hello := clientHello(true, [][]byte{[]byte("h2"), []byte("http/1.1")})
	if got := JA4(hello); got != want {
		t.Fatalf("JA4 %q, erwartet %q", got, want)
	}
	// ein Record, auf mehrere Records verteilt, mit Bytes dahinter, abgeschnitten
	for _, size := range []int{1 << 14, 100} {
		stream := records(hello, size)
		h, more := TLSHello(append(stream, "weiter"...))
		if more || JA4(h) != want {
			t.Fatalf("Strom (%d): %q more=%v", size, JA4(h), more)
		}
		if h, more := TLSHello(stream[:len(stream)-1]); h != nil || !more {
			t.Fatalf("abgeschnitten (%d): more=%v", size, more)
		}
	}
}

func TestJA4Variants(t *testing.T) {
	// ohne SNI und ALPN: "i", "00"; Extensions-Zahl ohne die beiden
	if got := JA4(clientHello(false, nil)); got != "t13i151400_8daaf6152771_e5627efa2ab1" {
		t.Fatalf("ohne SNI/ALPN: %q", got)
	}
	for in, want := range map[string]string{"http/1.1": "h1", "h": "hh", "\xab\xcd": "ad", "x\x01": "71", "": "00"} {
		if got := alpnChars([]byte(in)); got != want {
			t.Fatalf("ALPN %q: %q, erwartet %q", in, got, want)
		}
	}
	if !grease(0x0a0a) || !grease(0xfafa) || grease(0x0a1a) || grease(0x1301) {
		t.Fatal("GREASE")
	}
	if count(5) != "05" || count(150) != "99" || tlsVersion(0x0303) != "12" || tlsVersion(1) != "00" {
		t.Fatal("Hilfen")
	}
	// kaputt oder kein ClientHello: nichts, kein Warten
	for _, b := range [][]byte{
		{0x16, 3, 1, 0, 4, 2, 0, 0, 0},                                      // ServerHello
		{0x15, 3, 1, 0, 2, 2, 40},                                           // Alert
		[]byte("GET / HTTP/1.1\r\n\r\n"),                                    // kein TLS
		records(append([]byte{1, 0, 0x40, 0}, make([]byte, 100)...), 1<<14), // groesser als MaxHello
	} {
		if h, more := TLSHello(b); h != nil || more {
			t.Fatalf("%x: more=%v", b, more)
		}
	}
	if JA4([]byte{1, 0, 0, 2, 3, 3}) != "" || JA4(nil) != "" { // ohne Random
		t.Fatal("kaputtes ClientHello")
	}
}

// Ein echtes ClientHello von crypto/tls ergibt einen gueltigen JA4.
func TestJA4GoClient(t *testing.T) {
	a, b := net.Pipe()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: "example.com", NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true}) //nolint:gosec // Test
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_ = c.Handshake()
	}()
	var buf []byte
	tmp := make([]byte, 4096)
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		n, err := b.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if h, more := TLSHello(buf); !more {
			if !regexp.MustCompile(`^t13d\d{4}h2_[0-9a-f]{12}_[0-9a-f]{12}$`).MatchString(JA4(h)) {
				t.Fatalf("JA4 %q", JA4(h))
			}
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	a.Close()
	b.Close()
}
