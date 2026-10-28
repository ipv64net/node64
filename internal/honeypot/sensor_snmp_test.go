package honeypot

import (
	"errors"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// sensorFreeUDPPort liefert einen freien UDP-Port.
func sensorFreeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	p := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	return p
}

// sensorUDPDial verbindet einen UDP-Client mit dem Sensor.
func sensorUDPDial(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.Dial("udp", sensorAddrOf(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// sensorUDPReply schickt ein Paket und liefert die Antwort (nil = keine innerhalb wait).
func sensorUDPReply(t *testing.T, c net.Conn, b []byte, wait time.Duration) []byte {
	t.Helper()
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 8192)
	n, err := c.Read(buf)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	if n > len(b) {
		t.Fatalf("Antwort %d Bytes groesser als Anfrage %d", n, len(b))
	}
	return buf[:n]
}

// sensorTLV baut ein BER-Element.
func sensorTLV(tag byte, parts ...[]byte) []byte {
	var v []byte
	for _, p := range parts {
		v = append(v, p...)
	}
	switch l := len(v); {
	case l < 0x80:
		return append([]byte{tag, byte(l)}, v...)
	case l < 0x100:
		return append([]byte{tag, 0x81, byte(l)}, v...)
	default:
		return append([]byte{tag, 0x82, byte(l >> 8), byte(l)}, v...)
	}
}

// sensorOID kodiert eine OID in Punktschreibweise.
func sensorOID(s string) []byte {
	var n []uint64
	for _, p := range strings.Split(s, ".") {
		x, _ := strconv.ParseUint(p, 10, 64)
		n = append(n, x)
	}
	n = append([]uint64{n[0]*40 + n[1]}, n[2:]...)
	var b []byte
	for _, x := range n {
		var tmp []byte
		tmp = append(tmp, byte(x&0x7f))
		for x >>= 7; x > 0; x >>= 7 {
			tmp = append([]byte{byte(x&0x7f) | 0x80}, tmp...)
		}
		b = append(b, tmp...)
	}
	return sensorTLV(0x06, b)
}

// sensorSNMPPkt baut eine SNMPv1/v2c-Nachricht mit einer Variablen.
func sensorSNMPPkt(ver byte, community string, pdu byte, oid string) []byte {
	vb := sensorTLV(0x30, sensorTLV(0x30, sensorOID(oid), []byte{0x05, 0}))
	p := sensorTLV(pdu, sensorTLV(0x02, []byte{0x12, 0x34}), sensorTLV(0x02, []byte{0}), sensorTLV(0x02, []byte{0}), vb)
	return sensorTLV(0x30, sensorTLV(0x02, []byte{ver}), sensorTLV(0x04, []byte(community)), p)
}

// sensorSNMPv3Pkt baut eine SNMPv3-Nachricht (USM, ohne Authentisierung).
func sensorSNMPv3Pkt(user string) []byte {
	glob := sensorTLV(0x30, sensorTLV(0x02, []byte{0x01}), sensorTLV(0x02, []byte{0x05, 0xdc}), sensorTLV(0x04, []byte{0x04}), sensorTLV(0x02, []byte{3}))
	usm := sensorTLV(0x30, sensorTLV(0x04, []byte{0x80, 0, 0x1f, 0x88}), sensorTLV(0x02, []byte{0}), sensorTLV(0x02, []byte{0}),
		sensorTLV(0x04, []byte(user)), sensorTLV(0x04), sensorTLV(0x04))
	data := sensorTLV(0x30, sensorTLV(0x04), sensorTLV(0x04), sensorTLV(0xA0, sensorTLV(0x02, []byte{1}), sensorTLV(0x02, []byte{0}), sensorTLV(0x02, []byte{0}), sensorTLV(0x30)))
	return sensorTLV(0x30, sensorTLV(0x02, []byte{3}), glob, sensorTLV(0x04, usm), data)
}

func TestSensorSNMP(t *testing.T) {
	p := sensorFreeUDPPort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcSNMP, p, ""}}})
	if st := s.Status(); len(st) != 1 || !st[0].Listen {
		t.Fatalf("Status: %+v", st)
	}
	c := sensorUDPDial(t, p)
	comm := func(c string) func(Event) bool {
		return func(e Event) bool { return e.Kind == KindSNMPBrute && e.Password == c }
	}

	// v2c get: keine Antwort
	if r := sensorUDPReply(t, c, sensorSNMPPkt(1, "public", 0xA0, "1.3.6.1.2.1.1.1.0"), 300*time.Millisecond); r != nil {
		t.Fatalf("Antwort: %x", r)
	}
	e := rec.wait(t, comm("public"))
	if e.Detail != "v2c get 1.3.6.1.2.1.1.1.0" || e.Service != SvcSNMP || e.Port != p || e.Username != "" || e.Src.String() != "127.0.0.1" || e.SrcPort == 0 {
		t.Fatalf("Ereignis: %+v", e)
	}
	if s.counters.Logins.Load() != 1 {
		t.Fatalf("Logins = %d", s.counters.Logins.Load())
	}

	send := func(b []byte) {
		t.Helper()
		if _, err := c.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	// v1 getnext, getbulk, set, Trap v1 (Enterprise-OID)
	send(sensorSNMPPkt(0, "private", 0xA1, "1.3.6.1.2.1.1"))
	send(sensorSNMPPkt(1, "bulk", 0xA5, "1.3.6.1"))
	send(sensorSNMPPkt(1, "write", 0xA3, "1.3.6.1.2.1.1.5.0"))
	trap := sensorTLV(0x30, sensorTLV(0x02, []byte{0}), sensorTLV(0x04, []byte("traps")),
		sensorTLV(0xA4, sensorOID("1.3.6.1.4.1.9"), sensorTLV(0x40, []byte{10, 0, 0, 1}), sensorTLV(0x02, []byte{6})))
	send(trap)
	for k, d := range map[string]string{"private": "v1 getnext 1.3.6.1.2.1.1", "bulk": "v2c getbulk 1.3.6.1", "write": "v2c set 1.3.6.1.2.1.1.5.0", "traps": "v1 trap 1.3.6.1.4.1.9"} {
		if e := rec.wait(t, comm(k)); e.Detail != d {
			t.Fatalf("%s: %q", k, e.Detail)
		}
	}

	// lange OID gekuerzt
	send(sensorSNMPPkt(1, "longoid", 0xA0, "1.3"+strings.Repeat(".123456789", 20)))
	if e := rec.wait(t, comm("longoid")); len(e.Detail) != len("v2c get ")+sensorSNMPOID || !strings.HasPrefix(e.Detail, "v2c get 1.3.123456789.") {
		t.Fatalf("OID: %q", e.Detail)
	}

	// v3: Name, Discovery ohne Namen
	send(sensorSNMPv3Pkt("admin"))
	if e := rec.wait(t, func(e Event) bool { return e.Kind == KindSNMPBrute && e.Username == "admin" }); e.Detail != "v3" || e.Password != "" {
		t.Fatalf("v3: %+v", e)
	}
	send(sensorSNMPv3Pkt(""))
	rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Detail == "v3 discovery" })

	// Rate-Limit: gleiche Community innerhalb einer Minute nur einmal (Marke danach: Pakete in Reihenfolge bearbeitet)
	for i := 0; i < 5; i++ {
		send(sensorSNMPPkt(1, "public", 0xA0, "1.3.6.1.2.1.1.1.0"))
		send(sensorSNMPv3Pkt("admin"))
	}
	send(sensorSNMPPkt(1, "marker1", 0xA0, "1.3"))
	rec.wait(t, comm("marker1"))
	if n := rec.count(comm("public")); n != 1 {
		t.Fatalf("public %d mal", n)
	}
	if n := rec.count(func(e Event) bool { return e.Username == "admin" }); n != 1 {
		t.Fatalf("admin %d mal", n)
	}

	// kaputte Pakete: keine Panik, einmal Probe je Quelle und Minute, danach geht es weiter
	ok := sensorSNMPPkt(1, "cut", 0xA0, "1.3.6.1.2.1.1.1.0")
	junk := [][]byte{
		{0x30},
		{0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
		{0x30, 0x80, 0x02, 0x01, 0x01, 0, 0}, // unbestimmte Laenge
		{0x3f, 0x01, 0x00},                   // Tag mit mehreren Bytes
		{0x30, 0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		sensorTLV(0x30, sensorTLV(0x02, []byte{1, 2, 3, 4, 5}), sensorTLV(0x04, []byte("x"))),             // Version zu lang
		sensorTLV(0x30, sensorTLV(0x02, []byte{2}), sensorTLV(0x04, []byte("x")), sensorTLV(0xA0)),        // Version 2 gibt es nicht
		sensorTLV(0x30, sensorTLV(0x02, []byte{1}), sensorTLV(0x04, []byte("x")), sensorTLV(0xB0)),        // keine PDU
		sensorTLV(0x30, sensorTLV(0x02, []byte{3}), sensorTLV(0x30), sensorTLV(0x04, []byte{0x30, 0x05})), // v3 kaputt
		ok[:len(ok)-3],
		[]byte("GET / HTTP/1.0\r\n\r\n"),
	}
	for _, b := range junk {
		send(b)
	}
	send(sensorSNMPPkt(1, "marker2", 0xA0, "1.3"))
	rec.wait(t, comm("marker2"))
	if n := rec.count(func(e Event) bool { return e.Detail == "snmp: bad packet" }); n != 1 {
		t.Fatalf("Proben: %d", n)
	}
	if e := rec.wait(t, func(e Event) bool { return e.Detail == "snmp: bad packet" }); e.Kind != KindProbe || string(e.Payload) != "\x30" {
		t.Fatalf("Probe: %+v", e)
	}

	// Community ohne OID (Variablenliste kaputt) zaehlt trotzdem
	send(sensorTLV(0x30, sensorTLV(0x02, []byte{1}), sensorTLV(0x04, []byte("nooid")), sensorTLV(0xA0, sensorTLV(0x02, []byte{1}))))
	if e := rec.wait(t, comm("nooid")); e.Detail != "v2c get" {
		t.Fatalf("ohne OID: %q", e.Detail)
	}

	// bis zuletzt keine einzige Antwort
	if r := sensorUDPReply(t, c, sensorSNMPPkt(1, "last", 0xA0, "1.3"), 300*time.Millisecond); r != nil {
		t.Fatalf("Antwort: %x", r)
	}
}

func TestSensorSNMPPerSource(t *testing.T) {
	p := sensorFreeUDPPort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcSNMP, p, ""}}})
	c := sensorUDPDial(t, p)
	for i := 0; i < sensorSNMPPerSrc+20; i++ {
		_, _ = c.Write(sensorSNMPPkt(1, "c"+strconv.Itoa(i), 0xA0, "1.3"))
		if i%16 == 15 {
			time.Sleep(5 * time.Millisecond) // Empfangspuffer nicht ueberlaufen lassen
		}
	}
	sensorWaitCounter(t, func() int64 { return int64(rec.count(sensorKind(KindSNMPBrute))) }, sensorSNMPPerSrc)
	time.Sleep(200 * time.Millisecond)
	if n := rec.count(sensorKind(KindSNMPBrute)); n != sensorSNMPPerSrc {
		t.Fatalf("Ereignisse: %d", n)
	}
}

// Zufaellige und abgeschnittene Pakete: keine Panik.
func TestSensorSNMPParseFuzz(t *testing.T) {
	good := [][]byte{sensorSNMPPkt(1, "public", 0xA5, "1.3.6.1.2.1.1.1.0"), sensorSNMPv3Pkt("user")}
	for _, g := range good {
		for i := 0; i <= len(g); i++ {
			sensorSNMPParse(g[:i])
			for j := 0; j < 8; j++ {
				b := append([]byte(nil), g...)
				b[rand.N(len(b))] = byte(rand.N(256))
				sensorSNMPParse(b[:i])
			}
		}
	}
	for i := 0; i < 2000; i++ {
		b := make([]byte, rand.N(64))
		for j := range b {
			b[j] = byte(rand.N(256))
		}
		sensorSNMPParse(b)
	}
	if m, ok := sensorSNMPParse(good[0]); !ok || m.community != "public" || m.detail() != "v2c getbulk 1.3.6.1.2.1.1.1.0" {
		t.Fatalf("%+v %v", m, ok)
	}
}

// Lange BER-Laengen (4 Bytes, oberstes Bit gesetzt): auf 32 Bit kein negativer Wert, keine Panik.
func TestSensorSNMPBERLongLen(t *testing.T) {
	for _, b := range [][]byte{
		{0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF},
		{0x30, 0x84, 0x80, 0x00, 0x00, 0x00, 1, 2, 3},
		{0x30, 0x84, 0x00, 0x00, 0x00, 0x02, 1},
	} {
		r := sensorSNMPBER{b: b}
		if _, v := r.next(); v != nil || !r.bad {
			t.Fatalf("%x: %x %v", b, v, r.bad)
		}
		sensorSNMPParse(b)
	}
	r := sensorSNMPBER{b: []byte{0x04, 0x84, 0, 0, 0, 2, 'a', 'b'}}
	if tag, v := r.next(); r.bad || tag != 0x04 || string(v) != "ab" {
		t.Fatalf("%x %q %v", tag, v, r.bad)
	}
}

func TestSensorUDPLimit(t *testing.T) {
	l := newSensorUDPLimit(time.Minute, 2)
	now := time.Now()
	if !l.allow("a", now) || !l.allow("a", now) || l.allow("a", now.Add(59*time.Second)) {
		t.Fatal("Fenster")
	}
	if !l.allow("a", now.Add(time.Minute)) {
		t.Fatal("neues Fenster")
	}
	// Tabelle voll: neue Schluessel abgelehnt, bis alte ablaufen
	for i := len(l.m); i < sensorUDPKeys; i++ {
		l.allow("k"+strconv.Itoa(i), now)
	}
	if l.allow("neu", now.Add(time.Second)) {
		t.Fatal("volle Tabelle")
	}
	if !l.allow("neu", now.Add(2*time.Minute)) || len(l.m) > sensorUDPKeys {
		t.Fatalf("nach Ablauf: %d", len(l.m))
	}
}
