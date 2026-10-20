package honeypot

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// sensorPGMsg baut eine Nachricht ohne Typ-Byte (Laenge, Code, Rumpf).
func sensorPGMsg(code uint32, body []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(8+len(body)))
	b = binary.BigEndian.AppendUint32(b, code)
	return append(b, body...)
}

// sensorPGStart baut eine StartupMessage 3.0 aus Name/Wert-Paaren.
func sensorPGStart(kv ...string) []byte {
	var b []byte
	for _, s := range kv {
		b = append(append(b, s...), 0)
	}
	return sensorPGMsg(196608, append(b, 0))
}

func sensorPGPass(p string) []byte {
	b := binary.BigEndian.AppendUint32([]byte{'p'}, uint32(4+len(p)+1))
	return append(append(b, p...), 0)
}

func sensorPGDial(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", sensorAddrOf(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// sensorDBRead liest genau n Bytes.
func sensorDBRead(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("Antwort fehlt: %v", err)
	}
	return b
}

// sensorDBRest liest bis zum Schliessen durch den Sensor (RST nach ungelesenen Bytes ist erlaubt).
func sensorDBRest(t *testing.T, c net.Conn) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(c)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("nicht getrennt")
	}
	return b
}

func TestSensorPG(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcPostgre, p, ""}}})

	// SSL und GSS abgelehnt, dann Klartext-Anmeldung
	c := sensorPGDial(t, p)
	_, _ = c.Write(sensorPGMsg(80877103, nil))
	if b := sensorDBRead(t, c, 1); b[0] != 'N' {
		t.Fatalf("SSL: %q", b)
	}
	_, _ = c.Write(sensorPGMsg(80877104, nil))
	if b := sensorDBRead(t, c, 1); b[0] != 'N' {
		t.Fatalf("GSS: %q", b)
	}
	_, _ = c.Write(sensorPGStart("user", "postgres", "database", "prod", "application_name", "psql"))
	if b := sensorDBRead(t, c, 9); !bytes.Equal(b, []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}) {
		t.Fatalf("Auth-Anfrage: %v", b)
	}
	_, _ = c.Write(sensorPGPass("s3cr et"))
	out := sensorDBRest(t, c)
	if len(out) < 5 || out[0] != 'E' || int(binary.BigEndian.Uint32(out[1:])) != len(out)-1 ||
		!bytes.Contains(out, []byte("C28P01\x00")) ||
		!bytes.Contains(out, []byte("Mpassword authentication failed for user \"postgres\"\x00")) {
		t.Fatalf("Fehler: %q", out)
	}
	e := rec.wait(t, sensorKind(KindDBBrute))
	if e.Username != "postgres" || e.Password != "s3cr et" || e.Detail != "db=prod" || e.Client != "psql" ||
		e.Service != SvcPostgre || e.Port != p {
		t.Fatalf("Ereignis: %+v", e)
	}

	// ohne database: Standard ist der Benutzername
	c2 := sensorPGDial(t, p)
	_, _ = c2.Write(sensorPGStart("user", "admin"))
	sensorDBRead(t, c2, 9)
	_, _ = c2.Write(sensorPGPass(""))
	sensorDBRest(t, c2)
	e = rec.wait(t, func(e Event) bool { return e.Kind == KindDBBrute && e.Username == "admin" })
	if e.Password != "" || e.Detail != "db=admin" {
		t.Fatalf("ohne database: %+v", e)
	}
	if s.counters.Logins.Load() != 2 || rec.count(sensorKind(KindProbe)) != 0 {
		t.Fatalf("Logins = %d, Proben = %d", s.counters.Logins.Load(), rec.count(sensorKind(KindProbe)))
	}

	// ohne Passwort getrennt: Probe mit Benutzername
	c3 := sensorPGDial(t, p)
	_, _ = c3.Write(sensorPGStart("user", "scan"))
	sensorDBRead(t, c3, 9)
	c3.Close()
	e = rec.wait(t, sensorKind(KindProbe))
	if e.Detail != "pg: no password" || e.Username != "scan" || !bytes.HasPrefix(e.Payload, sensorPGStart("user", "scan")) {
		t.Fatalf("ohne Passwort: %+v", e)
	}

	// ohne user: 28000
	c4 := sensorPGDial(t, p)
	_, _ = c4.Write(sensorPGStart("database", "x"))
	if out := sensorDBRest(t, c4); !bytes.Contains(out, []byte("C28000\x00")) {
		t.Fatalf("ohne user: %q", out)
	}
	rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Detail == "pg: no user" })
}

func TestSensorPGJunk(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcPostgre, p, ""}}})

	probe := func(in []byte, detail string) {
		t.Helper()
		c := sensorPGDial(t, p)
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
	probe(nil, "")
	probe(sensorPGMsg(80877102, make([]byte, 8)), "pg: cancel")
	probe(sensorPGMsg(80877103, nil), "pg: ssl")
	probe(bytes.Repeat(sensorPGMsg(80877103, nil), 3), "pg: negotiate")
	probe(sensorPGMsg(131072, nil), "pg: protocol 2.0")
	probe([]byte{0xff, 0xff, 0xff, 0xff, 0, 3, 0, 0}, "pg: bad startup")  // riesige Laenge
	probe([]byte{0, 0, 0, 4, 0, 3, 0, 0}, "pg: bad startup")              // zu kurz
	probe([]byte{0, 0, 0, 20, 0, 3, 0, 0, 'u'}, "pg: short startup")      // abgebrochen
	probe(sensorPGMsg(196608, []byte("user\x00x")), "pg: bad startup")    // ohne NUL
	probe([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), "pg: bad startup") // anderes Protokoll
	probe(append(sensorPGStart("user", "u"), 'Q', 0, 0, 0, 5, 0), "pg: no password")
	probe(append(sensorPGStart("user", "u"), 'p', 0x7f, 0xff, 0xff, 0xff), "pg: bad password")
	probe(append(sensorPGStart("user", "u"), 'p', 0, 0, 0, 100, 'x'), "pg: bad password")

	// ueberlange Werte: Felder gekuerzt, Fehlertext begrenzt
	long := strings.Repeat("y", 1500)
	c := sensorPGDial(t, p)
	_, _ = c.Write(sensorPGStart("user", long, "database", long))
	sensorDBRead(t, c, 9)
	_, _ = c.Write(sensorPGPass("pw"))
	if out := sensorDBRest(t, c); len(out) > 300 {
		t.Fatalf("Fehler zu lang: %d", len(out))
	}
	e := rec.wait(t, sensorKind(KindDBBrute))
	if len(e.Username) != MaxText || e.Detail != "db="+long[:sensorDBName] || e.Password != "pw" {
		t.Fatalf("lang: %d %q", len(e.Username), e.Detail)
	}
	if s.counters.Logins.Load() != 1 {
		t.Fatalf("Logins = %d", s.counters.Logins.Load())
	}
}
