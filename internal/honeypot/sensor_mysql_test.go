package honeypot

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// sensorMySQLResp baut eine Handshake-Response 4.1 (auth mit 1-Byte-Laenge bzw. lenenc, db/plugin/attrs optional).
func sensorMySQLResp(caps uint32, user string, auth []byte, db, plugin string, attrs ...string) []byte {
	b := binary.LittleEndian.AppendUint32(nil, caps)
	b = binary.LittleEndian.AppendUint32(b, 1<<24)
	b = append(b, 255)
	b = append(b, make([]byte, 23)...)
	b = append(append(b, user...), 0)
	b = append(append(b, byte(len(auth))), auth...) // 1-Byte-Laenge, als lenenc gleich (< 251)
	if caps&sensorMySQLCapDB != 0 {
		b = append(append(b, db...), 0)
	}
	if caps&sensorMySQLCapPlugin != 0 {
		b = append(append(b, plugin...), 0)
	}
	if caps&sensorMySQLCapAttrs != 0 {
		var a []byte
		for _, s := range attrs {
			a = append(append(a, byte(len(s))), s...)
		}
		b = append(append(b, byte(len(a))), a...)
	}
	return b
}

// sensorMySQLGet liest ein Paket vom Sensor.
func sensorMySQLGet(t *testing.T, c net.Conn) (byte, []byte) {
	t.Helper()
	h := sensorDBRead(t, c, 4)
	n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	return h[3], sensorDBRead(t, c, n)
}

// sensorMySQLDial verbindet, prueft das Greeting und liefert den Salt.
func sensorMySQLDial(t *testing.T, port int) (net.Conn, []byte) {
	t.Helper()
	c := sensorPGDial(t, port)
	seq, g := sensorMySQLGet(t, c)
	if seq != 0 || g[0] != 10 || !bytes.HasPrefix(g[1:], []byte(sensorMySQLVersion+"\x00")) {
		t.Fatalf("Greeting: %q", g)
	}
	r := &sensorMySQLReader{b: g[1:]}
	r.cstr()
	r.skip(4)
	salt := append([]byte{}, r.skip(8)...)
	r.skip(1)
	lo := r.skip(2)
	r.skip(3)
	hi := r.skip(2)
	caps := uint32(binary.LittleEndian.Uint16(lo)) | uint32(binary.LittleEndian.Uint16(hi))<<16
	n := int(r.byte())
	r.skip(10)
	salt = append(salt, r.skip(n-1-8)...)
	r.skip(1)
	plugin := r.cstr()
	if r.bad || len(salt) != 20 || bytes.IndexByte(salt, 0) >= 0 || plugin != sensorMySQLNative ||
		caps&sensorMySQLCapPlugin == 0 || caps&sensorMySQLCap41 == 0 || caps&sensorMySQLCapSSL != 0 {
		t.Fatalf("Greeting: salt %q plugin %q caps %x", salt, plugin, caps)
	}
	return c, salt
}

func TestSensorMySQL(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcMySQL, p, ""}}})
	const caps = sensorMySQLCap41 | sensorMySQLCapSecure | sensorMySQLCapPlugin | sensorMySQLCapDB | sensorMySQLCapAttrs |
		sensorMySQLCapLenData
	hash := bytes.Repeat([]byte{0xab}, 20)

	// Hash, Wechsel auf Klartext, Passwort erfasst
	c, salt := sensorMySQLDial(t, p)
	c2, salt2 := sensorMySQLDial(t, p)
	if bytes.Equal(salt, salt2) {
		t.Fatal("Salt nicht zufaellig")
	}
	c2.Close()
	_, _ = c.Write(sensorMySQLPacket(1, sensorMySQLResp(caps, "root", hash, "mysql", sensorMySQLNative,
		"_client_name", "libmysql", "_client_version", "8.0.36", "_os", "Linux")))
	seq, sw := sensorMySQLGet(t, c)
	if seq != 2 || !bytes.Equal(sw, []byte("\xfe"+sensorMySQLClear+"\x00")) {
		t.Fatalf("AuthSwitch: %d %q", seq, sw)
	}
	_, _ = c.Write(sensorMySQLPacket(3, []byte("t00r!\x00")))
	seq, er := sensorMySQLGet(t, c)
	if seq != 4 || er[0] != 0xff || binary.LittleEndian.Uint16(er[1:]) != 1045 ||
		string(er[3:]) != "#28000Access denied for user 'root'@'127.0.0.1' (using password: YES)" {
		t.Fatalf("ERR: %d %q", seq, er)
	}
	if rest := sensorDBRest(t, c); len(rest) != 0 {
		t.Fatalf("nach ERR: %q", rest)
	}
	e := rec.wait(t, sensorKind(KindDBBrute))
	if e.Username != "root" || e.Password != "t00r!" || e.Detail != "db=mysql" || e.Client != "libmysql 8.0.36" ||
		e.Service != SvcMySQL || e.Port != p {
		t.Fatalf("Ereignis: %+v", e)
	}

	// Client lehnt Klartext ab (trennt): nur Hash
	c, _ = sensorMySQLDial(t, p)
	_, _ = c.Write(sensorMySQLPacket(1, sensorMySQLResp(sensorMySQLCap41|sensorMySQLCapSecure|sensorMySQLCapPlugin,
		"admin", hash, "", sensorMySQLNative)))
	sensorMySQLGet(t, c)
	c.Close()
	e = rec.wait(t, func(e Event) bool { return e.Kind == KindDBBrute && e.Username == "admin" })
	if e.Password != "" || e.Detail != "hash" {
		t.Fatalf("Hash: %+v", e)
	}

	// Klartext schon in der Response: kein Wechsel
	c, _ = sensorMySQLDial(t, p)
	_, _ = c.Write(sensorMySQLPacket(1, sensorMySQLResp(caps&^sensorMySQLCapAttrs, "sa", []byte("pw\x00"), "db1",
		sensorMySQLClear)))
	seq, er = sensorMySQLGet(t, c)
	if seq != 2 || er[0] != 0xff {
		t.Fatalf("Klartext: %d %q", seq, er)
	}
	e = rec.wait(t, func(e Event) bool { return e.Kind == KindDBBrute && e.Username == "sa" })
	if e.Password != "pw" || e.Detail != "db=db1" {
		t.Fatalf("Klartext: %+v", e)
	}

	// leeres Passwort, ohne PLUGIN_AUTH
	c, _ = sensorMySQLDial(t, p)
	_, _ = c.Write(sensorMySQLPacket(1, sensorMySQLResp(sensorMySQLCap41|sensorMySQLCapSecure, "guest", nil, "", "")))
	_, er = sensorMySQLGet(t, c)
	if !strings.HasSuffix(string(er), "(using password: NO)") {
		t.Fatalf("leer: %q", er)
	}
	e = rec.wait(t, func(e Event) bool { return e.Kind == KindDBBrute && e.Username == "guest" })
	if e.Password != "" || e.Detail != "" {
		t.Fatalf("leer: %+v", e)
	}

	// SSL-Anfrage: Ereignis tls, getrennt
	c, _ = sensorMySQLDial(t, p)
	ssl := binary.LittleEndian.AppendUint32(nil, sensorMySQLCap41|sensorMySQLCapSSL|sensorMySQLCapSecure)
	ssl = append(ssl, make([]byte, 28)...)
	_, _ = c.Write(sensorMySQLPacket(1, ssl))
	if rest := sensorDBRest(t, c); len(rest) != 0 {
		t.Fatalf("tls: %q", rest)
	}
	rec.wait(t, func(e Event) bool { return e.Kind == KindDBBrute && e.Detail == "tls" && e.Username == "" })

	if s.counters.Logins.Load() != 4 || rec.count(sensorKind(KindProbe)) != 1 { // Probe: c2 ohne Daten
		t.Fatalf("Logins = %d, Proben = %d", s.counters.Logins.Load(), rec.count(sensorKind(KindProbe)))
	}
}

func TestSensorMySQLJunk(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcMySQL, p, ""}}})

	probe := func(in []byte, detail string) {
		t.Helper()
		c, _ := sensorMySQLDial(t, p)
		if len(in) > 0 {
			_, _ = c.Write(in)
		}
		_ = c.(*net.TCPConn).CloseWrite()
		sensorDBRest(t, c)
		e := rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Detail == detail })
		if len(e.Payload) > MaxPayload || !bytes.HasPrefix(in, e.Payload) {
			t.Fatalf("%s: Payload %q", detail, e.Payload)
		}
		rec.mu.Lock()
		rec.ev = nil
		rec.mu.Unlock()
	}
	resp := sensorMySQLResp(sensorMySQLCap41|sensorMySQLCapSecure, "u", []byte("x"), "", "")
	probe(nil, "")
	probe([]byte{0xff, 0xff, 0xff, 1, 0}, "mysql: bad handshake")                         // riesige Laenge
	probe([]byte{10, 0, 0, 1, 'a'}, "mysql: bad handshake")                               // abgebrochen
	probe(sensorMySQLPacket(1, []byte{0x85, 0x00, 0, 0, 0, 'u', 0}), "mysql: old client") // Protokoll 3.20
	probe(sensorMySQLPacket(1, resp[:30]), "mysql: bad handshake")                        // zu kurz
	probe(sensorMySQLPacket(1, append(resp[:len(resp)-2], 200)), "mysql: bad handshake")
	lenenc := sensorMySQLResp(sensorMySQLCap41|sensorMySQLCapLenData, "u", nil, "", "")
	lenenc = append(lenenc[:len(lenenc)-1], 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff) // riesiges lenenc
	probe(sensorMySQLPacket(1, lenenc), "mysql: bad handshake")
	probe([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), "mysql: bad handshake")

	// kaputte Attribute und Ueberlaenge: Anmeldung trotzdem erfasst, Felder gekuerzt
	long := strings.Repeat("z", 1000)
	b := sensorMySQLResp(sensorMySQLCap41|sensorMySQLCapSecure|sensorMySQLCapDB|sensorMySQLCapPlugin|sensorMySQLCapAttrs,
		long, []byte("pw"), long, sensorMySQLClear)
	b = append(b[:len(b)-1], 0xfc, 0xff) // Attribute abgeschnitten
	c, _ := sensorMySQLDial(t, p)
	_, _ = c.Write(sensorMySQLPacket(1, b))
	_, er := sensorMySQLGet(t, c)
	if er[0] != 0xff || len(er) > 200 {
		t.Fatalf("ERR: %q", er)
	}
	e := rec.wait(t, sensorKind(KindDBBrute))
	if len(e.Username) != MaxText || e.Password != "pw" || e.Detail != "db="+long[:sensorDBName] || e.Client != "" {
		t.Fatalf("lang: %d %q %q %q", len(e.Username), e.Password, e.Detail, e.Client)
	}
	if s.counters.Logins.Load() != 1 {
		t.Fatalf("Logins = %d", s.counters.Logins.Load())
	}
}
