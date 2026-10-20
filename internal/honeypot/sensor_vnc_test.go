package honeypot

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net"
	"testing"
	"time"
)

// sensorVNCDial verbindet und liest die Version des Sensors.
func sensorVNCDial(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", sensorAddrOf(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if got := sensorVNCRead(t, c, 12); string(got) != "RFB 003.008\n" {
		t.Fatalf("Version: %q", got)
	}
	return c
}

// sensorVNCRead liest genau n Bytes.
func sensorVNCRead(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("%d Bytes nicht erhalten: %v (% x)", n, err, b)
	}
	return b
}

func sensorVNCWrite(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
}

// sensorVNCAuth fuehrt Challenge/Antwort durch und liefert den Rest bis zur Trennung.
func sensorVNCAuth(t *testing.T, c net.Conn, resp []byte) []byte {
	t.Helper()
	if ch := sensorVNCRead(t, c, 16); bytes.Equal(ch, make([]byte, 16)) {
		t.Fatal("Challenge nur Nullen")
	}
	sensorVNCWrite(t, c, resp)
	return []byte(sensorPlainClosed(t, c))
}

func TestSensorVNC(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcVNC, p, ""}}})
	resp := []byte("0123456789abcdef")
	failed38 := binary.BigEndian.AppendUint32([]byte{0, 0, 0, 1}, uint32(len(sensorVNCReason)))
	failed38 = append(failed38, sensorVNCReason...)

	// 3.8: Typenliste, Wahl 2, Challenge, Antwort, SecurityResult mit Grund
	c := sensorVNCDial(t, p)
	sensorVNCWrite(t, c, []byte("RFB 003.008\n"))
	if got := sensorVNCRead(t, c, 2); !bytes.Equal(got, []byte{1, 2}) {
		t.Fatalf("Typen: % x", got)
	}
	sensorVNCWrite(t, c, []byte{2})
	if out := sensorVNCAuth(t, c, resp); !bytes.Equal(out, failed38) {
		t.Fatalf("Ergebnis: % x", out)
	}
	e := rec.wait(t, sensorKind(KindVNCBrute))
	if e.Username != "" || e.Password != "" || e.Detail != "vnc-auth" || !bytes.Equal(e.Payload, resp) ||
		e.Client != "RFB 003.008" || e.Service != SvcVNC || e.Port != p {
		t.Fatalf("Ereignis: %+v", e)
	}

	// 3.7: wie 3.8, SecurityResult ohne Grund
	c = sensorVNCDial(t, p)
	sensorVNCWrite(t, c, []byte("RFB 003.007\n"))
	sensorVNCRead(t, c, 2)
	sensorVNCWrite(t, c, []byte{2})
	if out := sensorVNCAuth(t, c, resp); !bytes.Equal(out, []byte{0, 0, 0, 1}) {
		t.Fatalf("Ergebnis 3.7: % x", out)
	}
	rec.wait(t, func(e Event) bool { return e.Kind == KindVNCBrute && e.Client == "RFB 003.007" })

	// 3.3: Server bestimmt den Typ (uint32 2), sonst wie 3.7
	c = sensorVNCDial(t, p)
	sensorVNCWrite(t, c, []byte("RFB 003.003\n"))
	if got := sensorVNCRead(t, c, 4); !bytes.Equal(got, []byte{0, 0, 0, 2}) {
		t.Fatalf("Typ 3.3: % x", got)
	}
	if out := sensorVNCAuth(t, c, resp); !bytes.Equal(out, []byte{0, 0, 0, 1}) {
		t.Fatalf("Ergebnis 3.3: % x", out)
	}
	rec.wait(t, func(e Event) bool { return e.Kind == KindVNCBrute && e.Client == "RFB 003.003" })

	// Abweichende Versionen: 3.889 gilt als 3.8, 3.5 als 3.3
	c = sensorVNCDial(t, p)
	sensorVNCWrite(t, c, []byte("RFB 003.889\n"))
	sensorVNCRead(t, c, 2)
	sensorVNCWrite(t, c, []byte{2})
	if out := sensorVNCAuth(t, c, resp); !bytes.Equal(out, failed38) {
		t.Fatalf("Ergebnis 3.889: % x", out)
	}
	c = sensorVNCDial(t, p)
	sensorVNCWrite(t, c, []byte("RFB 003.005\n"))
	if got := sensorVNCRead(t, c, 4); !bytes.Equal(got, []byte{0, 0, 0, 2}) {
		t.Fatalf("Typ 3.5: % x", got)
	}
	sensorVNCAuth(t, c, resp)

	sensorWaitCounter(t, s.counters.Logins.Load, 5)
	if n := rec.count(sensorKind(KindVNCBrute)); n != 5 || rec.count(sensorKind(KindProbe)) != 0 {
		t.Fatalf("Ereignisse: %+v", rec.all())
	}
}

func TestSensorVNCJunk(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcVNC, p, ""}}})
	probe := func(detail string) Event {
		t.Helper()
		return rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Detail == detail })
	}
	half := func(c net.Conn) { _ = c.(*net.TCPConn).CloseWrite() }

	// nur Banner gelesen
	c := sensorVNCDial(t, p)
	half(c)
	sensorPlainClosed(t, c)
	probe("")

	// keine oder abgeschnittene Version
	c = sensorVNCDial(t, p)
	sensorVNCWrite(t, c, []byte("RFB 00"))
	half(c)
	sensorPlainClosed(t, c)
	if e := probe("vnc: short version"); string(e.Payload) != "RFB 00" {
		t.Fatalf("kurz: %+v", e)
	}
	for _, v := range []string{"GET / HTTP/1", "RFB 002.008\n", "RFB 003.-08\n", "RFB 003.008\r"} {
		c = sensorVNCDial(t, p)
		sensorVNCWrite(t, c, []byte(v))
		sensorPlainClosed(t, c)
		rec.wait(t, func(e Event) bool { return e.Detail == "vnc: bad version" && string(e.Payload) == v })
	}

	// falscher Sicherheitstyp, keine Wahl, unvollstaendige Antwort
	c = sensorVNCDial(t, p)
	sensorVNCWrite(t, c, []byte("RFB 003.008\n"))
	sensorVNCRead(t, c, 2)
	sensorVNCWrite(t, c, []byte{1})
	sensorPlainClosed(t, c)
	if e := probe("vnc: security type 1"); e.Client != "RFB 003.008" {
		t.Fatalf("Typ: %+v", e)
	}
	c = sensorVNCDial(t, p)
	sensorVNCWrite(t, c, []byte("RFB 003.007\n"))
	sensorVNCRead(t, c, 2)
	half(c)
	sensorPlainClosed(t, c)
	probe("vnc: no security type")
	c = sensorVNCDial(t, p)
	sensorVNCWrite(t, c, []byte("RFB 003.008\n"))
	sensorVNCRead(t, c, 2)
	sensorVNCWrite(t, c, []byte{2})
	sensorVNCRead(t, c, 16)
	sensorVNCWrite(t, c, []byte("12345678"))
	half(c)
	sensorPlainClosed(t, c)
	if e := probe("vnc: no response"); string(e.Payload) != "12345678" {
		t.Fatalf("kurz: %+v", e)
	}
	if n := rec.count(sensorKind(KindVNCBrute)); n != 0 {
		t.Fatalf("Anmeldung gemeldet: %d", n)
	}

	// Zufallsdaten nach dem Banner: keine Panik, Sensor arbeitet weiter
	r := rand.New(rand.NewPCG(3, 4))
	for range 30 {
		b := make([]byte, 1+r.IntN(60))
		for j := range b {
			b[j] = byte(r.UintN(256))
		}
		c = sensorVNCDial(t, p)
		_, _ = c.Write(b)
		half(c)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.ReadAll(c)
		c.Close()
	}
	c = sensorVNCDial(t, p)
	sensorVNCWrite(t, c, []byte("RFB 003.008\n"))
	sensorVNCRead(t, c, 2)
	sensorVNCWrite(t, c, []byte{2})
	sensorVNCAuth(t, c, bytes.Repeat([]byte{0xee}, 16))
	rec.wait(t, func(e Event) bool { return e.Kind == KindVNCBrute && e.Payload[0] == 0xee })
}
