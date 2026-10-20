package honeypot

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net"
	"testing"
	"time"
	"unicode/utf16"
)

// tdsTestUCS2 kodiert s als UCS-2 (little endian).
func tdsTestUCS2(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

// tdsTestPrelogin baut ein PRELOGIN mit VERSION und ENCRYPTION enc.
func tdsTestPrelogin(enc byte) []byte {
	body := []byte{
		0x00, 0, 11, 0, 6, // VERSION
		0x01, 0, 17, 0, 1, // ENCRYPTION
		0xff,
		0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
		enc,
	}
	return sensorMSSQLPacket(tdsPrelogin, body)
}

// tdsTestLogin7 baut ein LOGIN7 (TDS 7.4) mit verschleiertem Passwort; flags2 = OptionFlags2.
func tdsTestLogin7(host, user, pass, app, server string, flags2 byte) []byte {
	fixed := make([]byte, 94)
	binary.LittleEndian.PutUint32(fixed[4:], 0x74000004)
	binary.LittleEndian.PutUint32(fixed[8:], 4096)
	fixed[25] = flags2
	var data []byte
	put := func(at int, v []byte, chars int) {
		binary.LittleEndian.PutUint16(fixed[at:], uint16(len(fixed)+len(data)))
		binary.LittleEndian.PutUint16(fixed[at+2:], uint16(chars))
		data = append(data, v...)
	}
	enc := tdsTestUCS2(pass)
	for i, x := range enc { // Nibbles tauschen, dann XOR 0xA5
		enc[i] = (x<<4 | x>>4) ^ 0xa5
	}
	put(36, tdsTestUCS2(host), len(utf16.Encode([]rune(host))))
	put(40, tdsTestUCS2(user), len(utf16.Encode([]rune(user))))
	put(44, enc, len(utf16.Encode([]rune(pass))))
	put(48, tdsTestUCS2(app), len(utf16.Encode([]rune(app))))
	put(52, tdsTestUCS2(server), len(utf16.Encode([]rune(server))))
	put(60, tdsTestUCS2("ODBC"), 4)
	body := append(fixed, data...)
	binary.LittleEndian.PutUint32(body, uint32(len(body)))
	return sensorMSSQLPacket(tdsLogin7, body)
}

// tdsTestReadPacket liest ein Antwort-Paket des Sensors.
func tdsTestReadPacket(t *testing.T, c net.Conn) (byte, []byte) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var h [8]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		t.Fatalf("kein Paket: %v", err)
	}
	body := make([]byte, int(binary.BigEndian.Uint16(h[2:]))-8)
	if _, err := io.ReadFull(c, body); err != nil {
		t.Fatalf("Paket unvollstaendig: %v", err)
	}
	if h[1]&1 == 0 {
		t.Fatalf("kein EOM: %x", h)
	}
	return h[0], body
}

func tdsTestDial(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", sensorAddrOf(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestSensorMSSQL(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcMSSQL, p, ""}}})

	c := tdsTestDial(t, p)
	_, _ = c.Write(tdsTestPrelogin(tdsEncOff))
	typ, body := tdsTestReadPacket(t, c)
	enc, ok := sensorMSSQLPrelogin(body)
	if typ != tdsReply || !ok || enc != tdsEncNotSup || !bytes.Contains(body, []byte{0x0f, 0x00, 0x07, 0xd0}) {
		t.Fatalf("PRELOGIN-Antwort: %x %x", typ, body)
	}
	_, _ = c.Write(tdsTestLogin7("WIN-BOT01", "sa", "P@ssw0rd!ä", "Microsoft SQL Server Management Studio", "10.0.0.1", 0))
	typ, body = tdsTestReadPacket(t, c)
	if typ != tdsReply || body[0] != 0xaa || binary.LittleEndian.Uint32(body[3:]) != 18456 ||
		!bytes.Contains(body, tdsTestUCS2("Login failed for user 'sa'.")) || !bytes.Contains(body, []byte{0xfd, 0x02, 0x00}) {
		t.Fatalf("Login-Antwort: %x", body)
	}
	sensorPlainClosed(t, c)
	e := rec.wait(t, sensorKind(KindDBBrute))
	if e.Service != SvcMSSQL || e.Port != p || e.Username != "sa" || e.Password != "P@ssw0rd!ä" || e.Client != "WIN-BOT01" ||
		e.Host != "10.0.0.1" || e.Detail != "app=Microsoft SQL Server Management Studio" {
		t.Fatalf("Ereignis: %+v", e)
	}
	if s.counters.Logins.Load() != 1 {
		t.Fatalf("Logins = %d", s.counters.Logins.Load())
	}

	// LOGIN7 ohne PRELOGIN (alte Clients), leeres Passwort, TDS 7.4 wie oben
	c2 := tdsTestDial(t, p)
	_, _ = c2.Write(tdsTestLogin7("", "admin", "", "", "", 0))
	tdsTestReadPacket(t, c2)
	rec.wait(t, func(e Event) bool {
		return e.Kind == KindDBBrute && e.Username == "admin" && e.Password == "" && e.Detail == ""
	})

	// Windows-Anmeldung ohne Zugangsdaten: Probe
	c3 := tdsTestDial(t, p)
	_, _ = c3.Write(tdsTestLogin7("PC", "", "", "app", "", 0x80))
	tdsTestReadPacket(t, c3)
	rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Detail == "sspi app=app" && e.Client == "PC" })
	if rec.count(sensorKind(KindProbe)) != 1 {
		t.Fatalf("Probe trotz Anmeldung: %+v", rec.all())
	}
}

func TestSensorMSSQLTLS(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcMSSQL, p, ""}}})

	for _, enc := range []byte{tdsEncOn, tdsEncReq} {
		c := tdsTestDial(t, p)
		_, _ = c.Write(tdsTestPrelogin(enc))
		tdsTestReadPacket(t, c)
		sensorPlainClosed(t, c)
	}
	// TDS 8: gleich ein TLS-ClientHello
	c := tdsTestDial(t, p)
	_, _ = c.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0, 0, 1, 0})
	sensorPlainClosed(t, c)
	deadline := time.Now().Add(5 * time.Second)
	for rec.count(func(e Event) bool { return e.Kind == KindProbe && e.Detail == "tls" }) < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("tls-Proben: %+v", rec.all())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if rec.count(sensorKind(KindDBBrute)) != 0 {
		t.Fatal("Anmeldung trotz TLS")
	}
}

func TestSensorMSSQLJunk(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcMSSQL, p, ""}}})

	good := tdsTestLogin7("h", "sa", "x", "a", "s", 0)
	badOff := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(badOff[8+40:], 0xfff0)    // Offset UserName hinter dem Ende
	huge := []byte{tdsLogin7, 0x00, 0xff, 0xff, 0, 0, 1, 0} // ohne EOM, 64 KB angekuendigt
	cases := []struct {
		name, detail string
		data         []byte
	}{
		{"leer", "", nil},
		{"http", "mssql: bad packet", []byte("GET / HTTP/1.0\r\n\r\n")},
		{"kurz", "mssql: short packet", []byte{tdsPrelogin, 1, 0}},
		{"laenge<8", "mssql: bad packet", []byte{tdsLogin7, 1, 0, 4, 0, 0, 1, 0}},
		{"zu gross", "mssql: bad packet", append(huge, huge...)},
		{"offset", "mssql: bad login", badOff},
		{"login kurz", "mssql: bad login", sensorMSSQLPacket(tdsLogin7, make([]byte, 40))},
		{"prelogin kaputt", "mssql: bad prelogin", sensorMSSQLPacket(tdsPrelogin, []byte{0x01, 0, 200, 0, 1, 0xff})},
		{"anderer Typ", "mssql: no login", append(tdsTestPrelogin(tdsEncOff), sensorMSSQLPacket(0x01, []byte("select 1"))...)},
	}
	for _, tc := range cases {
		match := func(e Event) bool { return e.Kind == KindProbe && e.Detail == tc.detail }
		before := rec.count(match)
		c := tdsTestDial(t, p)
		if tc.data != nil {
			_, _ = c.Write(tc.data)
		}
		if tc.name == "leer" || tc.name == "kurz" {
			_ = c.(*net.TCPConn).CloseWrite()
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.Copy(io.Discard, c) // Sensor trennt
		deadline := time.Now().Add(5 * time.Second)
		for rec.count(match) <= before {
			if time.Now().After(deadline) {
				t.Fatalf("%s: Probe %q fehlt: %+v", tc.name, tc.detail, rec.all())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if n := rec.count(sensorKind(KindDBBrute)); n != 0 {
		t.Fatalf("Anmeldungen: %d", n)
	}
}

// Zerleger mit abgeschnittenen und zufaelligen Daten: kein Panic.
func TestSensorMSSQLParseRobust(t *testing.T) {
	good := tdsTestLogin7("host", "user", "pass", "app", "srv", 0)[8:]
	for i := 0; i <= len(good); i++ {
		sensorMSSQLParseLogin(good[:i])
		sensorMSSQLPrelogin(good[:i])
	}
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 20000; i++ {
		b := make([]byte, r.IntN(200))
		for j := range b {
			b[j] = byte(r.UintN(256))
		}
		sensorMSSQLParseLogin(b)
		sensorMSSQLPrelogin(b)
	}
	m, ok := sensorMSSQLParseLogin(good)
	if !ok || m.host != "host" || m.user != "user" || m.pass != "pass" || m.app != "app" || m.server != "srv" || m.tds != 0x74000004 {
		t.Fatalf("LOGIN7: %+v %v", m, ok)
	}
	// alte TDS-Version: Zeilennummer 2 Bytes, DONE 4 Byte Zeilenzahl
	old := sensorMSSQLLoginFailed("x", 0x71000001)
	wide := sensorMSSQLLoginFailed("x", 0x74000004)
	if len(wide)-len(old) != 6 {
		t.Fatalf("Laengen %d %d", len(old), len(wide))
	}
}
