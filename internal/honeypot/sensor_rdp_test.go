package honeypot

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"net"
	"testing"
	"time"
)

// sensorRDPPkt baut einen X.224 Connection Request in TPKT (Cookie-Zeile roh, Negotiation Request optional).
func sensorRDPPkt(cookie string, neg bool, proto uint32) []byte {
	x := []byte{0, 0xe0, 0, 0, 0xab, 0xcd, 0} // LI, CR, DST-REF, SRC-REF, Klasse
	x = append(x, cookie...)
	if neg {
		x = append(x, 1, 0, 8, 0)
		x = binary.LittleEndian.AppendUint32(x, proto)
	}
	x[0] = byte(len(x) - 1)
	p := []byte{3, 0, 0, 0}
	binary.BigEndian.PutUint16(p[2:], uint16(4+len(x)))
	return append(p, x...)
}

// sensorRDPSend verbindet, schickt b und liefert alles bis zur Trennung durch den Sensor.
func sensorRDPSend(t *testing.T, port int, b []byte) []byte {
	t.Helper()
	c, err := net.Dial("tcp", sensorAddrOf(port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if len(b) > 0 {
		if _, err := c.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	_ = c.(*net.TCPConn).CloseWrite() // Ende der Eingabe, der Sensor wartet nicht bis zum Zeitlimit
	return sensorRDPReadAll(t, c)
}

// sensorRDPReadAll liest bis zur Trennung durch den Sensor (auch RST bei ungelesenen Daten); Zeitlimit ist ein Fehler.
func sensorRDPReadAll(t *testing.T, c net.Conn) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var out []byte
	buf := make([]byte, 256)
	for {
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatalf("nicht getrennt, bisher % x", out)
			}
			return out
		}
	}
}

// sensorRDPConfirm prueft Connection Confirm mit Negotiation Failure und liefert den Fehlercode.
func sensorRDPConfirm(t *testing.T, out []byte) uint32 {
	t.Helper()
	if len(out) != 19 || !bytes.Equal(out[:6], []byte{3, 0, 0, 19, 14, 0xd0}) || out[6] != 0xab || out[7] != 0xcd ||
		out[11] != 3 || out[13] != 8 {
		t.Fatalf("Antwort: % x", out)
	}
	return binary.LittleEndian.Uint32(out[15:])
}

func TestSensorRDP(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcRDP, p, ""}}})

	// typischer Bot: Cookie mit Benutzername, TLS + CredSSP angefragt
	pkt := sensorRDPPkt("Cookie: mstshash=Administrator\r\n", true, 3)
	if code := sensorRDPConfirm(t, sensorRDPSend(t, p, pkt)); code != sensorRDPSSLNoCert {
		t.Fatalf("Fehlercode %d", code)
	}
	e := rec.wait(t, sensorKind(KindRDPBrute))
	if e.Username != "Administrator" || e.Password != "" || e.Detail != "req=ssl,hybrid" || e.Service != SvcRDP ||
		e.Port != p || !bytes.Equal(e.Payload, pkt) {
		t.Fatalf("Ereignis: %+v", e)
	}

	// nur Standard-RDP, Zusatzbits, Restricted Admin
	pkt = sensorRDPPkt("Cookie: mstshash=nmap\r\n", true, 0)
	if code := sensorRDPConfirm(t, sensorRDPSend(t, p, pkt)); code != sensorRDPSSLRequired {
		t.Fatalf("Fehlercode %d", code)
	}
	rec.wait(t, func(e Event) bool { return e.Kind == KindRDPBrute && e.Username == "nmap" && e.Detail == "req=rdp" })
	pkt = sensorRDPPkt("Cookie: mstshash=user1\r\n", true, 0x41)
	pkt[len(pkt)-7] = 1
	sensorRDPConfirm(t, sensorRDPSend(t, p, pkt))
	rec.wait(t, func(e Event) bool {
		return e.Username == "user1" && e.Detail == "req=ssl,0x40 restricted-admin"
	})

	// Cookie ohne CRLF und ohne Negotiation Request, Steuerzeichen entfernt
	sensorRDPConfirm(t, sensorRDPSend(t, p, sensorRDPPkt("Cookie: mstshash=ro\x01ot", false, 0)))
	rec.wait(t, func(e Event) bool { return e.Kind == KindRDPBrute && e.Username == "root" && e.Detail == "req=none" })
	if s.counters.Logins.Load() != 4 {
		t.Fatalf("Logins = %d", s.counters.Logins.Load())
	}

	// ohne Cookie, nur TLS: Probe, CredSSP verlangt
	if code := sensorRDPConfirm(t, sensorRDPSend(t, p, sensorRDPPkt("", true, 1))); code != sensorRDPHybridRequired {
		t.Fatalf("Fehlercode %d", code)
	}
	rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Detail == "req=ssl" })

	// Routing-Token statt Benutzername
	sensorRDPConfirm(t, sensorRDPSend(t, p, sensorRDPPkt("Cookie: msts=3640205228.15629.0000\r\n", false, 0)))
	rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Detail == "req=none routing-token" })
	if n := rec.count(sensorKind(KindRDPBrute)); n != 4 {
		t.Fatalf("Versuche: %d", n)
	}
}

func TestSensorRDPJunk(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcRDP, p, ""}}})
	probe := func(detail string) Event {
		t.Helper()
		return rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Detail == detail })
	}

	// nichts gesendet
	sensorRDPSend(t, p, nil)
	probe("")

	// kein RDP: wie am generischen Port eingeordnet
	if out := sensorRDPSend(t, p, []byte("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")); len(out) != 0 {
		t.Fatalf("Antwort auf HTTP: %q", out)
	}
	if e := probe("http"); e.Path != "/x" || e.Host != "a" {
		t.Fatalf("HTTP: %+v", e)
	}
	sensorRDPSend(t, p, []byte{0xff, 0xfe, 0, 1, 2})
	probe("rdp: no tpkt")
	sensorRDPSend(t, p, []byte{3, 0})
	probe("rdp: short")

	// TPKT zu lang / zu kurz, abgeschnitten, kein Connection Request
	sensorRDPSend(t, p, []byte{3, 0, 0xff, 0xff, 1, 2, 3})
	probe("rdp: bad tpkt")
	sensorRDPSend(t, p, []byte{3, 0, 0, 5, 0})
	rec.wait(t, func(e Event) bool { return e.Detail == "rdp: bad tpkt" && len(e.Payload) == 4 && e.Payload[3] == 5 })
	pkt := sensorRDPPkt("Cookie: mstshash=cut\r\n", true, 3)
	sensorRDPSend(t, p, pkt[:20])
	if e := probe("rdp: short tpkt"); !bytes.Equal(e.Payload, pkt[:20]) || e.Username != "" {
		t.Fatalf("abgeschnitten: %+v", e)
	}
	pkt = sensorRDPPkt("Cookie: mstshash=data\r\n", true, 3)
	pkt[5] = 0xf0 // Data TPDU
	sensorRDPSend(t, p, pkt)
	probe("rdp: no connection request")
	pkt = sensorRDPPkt("", false, 0)
	pkt[4] = 2 // LI zu klein
	sensorRDPSend(t, p, pkt)
	rec.wait(t, func(e Event) bool { return e.Detail == "rdp: no connection request" && len(e.Payload) == 11 })

	// Zufallsdaten (auch mit TPKT-Kopf): keine Panik, Sensor antwortet danach normal
	r := rand.New(rand.NewPCG(1, 2))
	for i := range 40 {
		b := make([]byte, 1+r.IntN(300))
		for j := range b {
			b[j] = byte(r.UintN(256))
		}
		if i%2 == 0 && len(b) >= 4 {
			b[0], b[1] = 3, 0
			binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
		}
		c, err := net.Dial("tcp", sensorAddrOf(p))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write(b)
		_ = c.(*net.TCPConn).CloseWrite()
		sensorRDPReadAll(t, c)
		c.Close()
	}
	sensorRDPConfirm(t, sensorRDPSend(t, p, sensorRDPPkt("Cookie: mstshash=last\r\n", true, 2)))
	rec.wait(t, func(e Event) bool { return e.Kind == KindRDPBrute && e.Username == "last" && e.Detail == "req=hybrid" })
}
