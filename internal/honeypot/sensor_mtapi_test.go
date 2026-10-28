package honeypot

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	mrand "math/rand/v2"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

// sensorMTAPISent kodiert einen Satz (Woerter mit Laenge, leeres Wort am Ende).
func sensorMTAPISent(words ...string) []byte {
	var b []byte
	for _, w := range words {
		b = sensorMTAPIEnc(b, w)
	}
	return append(b, 0)
}

// sensorMTAPIRead liest einen Satz der Antwort.
func sensorMTAPIRead(t *testing.T, c net.Conn, br *bufio.Reader) []string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var words []string
	for {
		n, err := sensorMTAPILen(br)
		if err != nil {
			t.Fatalf("Antwort: %v (bisher %q)", err, words)
		}
		if n == 0 {
			return words
		}
		w := make([]byte, n)
		if _, err := io.ReadFull(br, w); err != nil {
			t.Fatal(err)
		}
		words = append(words, string(w))
	}
}

// sensorMTAPIWant prueft einen Satz der Antwort.
func sensorMTAPIWant(t *testing.T, c net.Conn, br *bufio.Reader, want ...string) []string {
	t.Helper()
	got := sensorMTAPIRead(t, c, br)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Antwort %q, erwartet %q", got, want)
	}
	return got
}

// sensorMTAPIEnd prueft, dass der Sensor trennt (EOF oder Reset, kein Zeitlimit), und liefert den Rest.
func sensorMTAPIEnd(t *testing.T, c net.Conn, br io.Reader) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(br)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("nicht getrennt")
	}
	return b
}

func sensorMTAPIDial(t *testing.T, p int) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", sensorAddrOf(p))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, bufio.NewReader(c)
}

func TestSensorMTAPI(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcMTAPI, p, ""}}})
	msg := "=message=invalid user name or password (6)"

	c, br := sensorMTAPIDial(t, p)
	// neues Verfahren, mit Tag
	_, _ = c.Write(sensorMTAPISent("/login", "=name=admin", "=password=geheim", ".tag=7"))
	sensorMTAPIWant(t, c, br, "!trap", msg, ".tag=7")
	sensorMTAPIWant(t, c, br, "!done", ".tag=7")
	e := rec.wait(t, sensorKind(KindRouterBrute))
	if e.Username != "admin" || e.Password != "geheim" || e.Detail != "" || e.Service != SvcMTAPI || e.Port != p || e.Client != "" || e.Src.String() != "127.0.0.1" {
		t.Fatalf("Ereignis: %+v", e)
	}

	// altes Verfahren: Challenge, dann =response=
	_, _ = c.Write(sensorMTAPISent("/login"))
	got := sensorMTAPIRead(t, c, br)
	if len(got) != 2 || got[0] != "!done" || !strings.HasPrefix(got[1], "=ret=") || len(got[1]) != 5+32 {
		t.Fatalf("Challenge: %q", got)
	}
	_, _ = c.Write(sensorMTAPISent("/login", "=name=olduser", "=response=00"+strings.Repeat("ab", 16)))
	sensorMTAPIWant(t, c, br, "!trap", msg)
	sensorMTAPIWant(t, c, br, "!done")
	e = rec.wait(t, func(e Event) bool { return e.Kind == KindRouterBrute && e.Username == "olduser" })
	if e.Password != "" || e.Detail != "challenge" {
		t.Fatalf("challenge: %+v", e)
	}

	// langes Passwort (Laenge mit 2 Bytes kodiert), Feld auf MaxText gekuerzt
	_, _ = c.Write(sensorMTAPISent("/login", "=name=long", "=password="+strings.Repeat("p", 300)))
	sensorMTAPIWant(t, c, br, "!trap", msg)
	sensorMTAPIWant(t, c, br, "!done")
	e = rec.wait(t, func(e Event) bool { return e.Kind == KindRouterBrute && e.Username == "long" })
	if len(e.Password) != MaxText {
		t.Fatalf("Passwort: %d", len(e.Password))
	}

	// nach sensorMTAPITries Versuchen getrennt
	_, _ = c.Write(append(sensorMTAPISent("/login", "=name=a", "=password=a"), sensorMTAPISent("/login", "=name=b", "=password=b")...))
	for i := 0; i < 2; i++ {
		sensorMTAPIWant(t, c, br, "!trap", msg)
		sensorMTAPIWant(t, c, br, "!done")
	}
	if rest := sensorMTAPIEnd(t, c, br); len(rest) != 0 {
		t.Fatalf("Rest: %q", rest)
	}
	sensorWaitCounter(t, s.counters.Logins.Load, sensorMTAPITries)
	if n := rec.count(sensorKind(KindRouterBrute)); n != sensorMTAPITries {
		t.Fatalf("Versuche: %d", n)
	}
	if rec.count(sensorKind(KindProbe)) != 0 {
		t.Fatal("Probe trotz Anmeldung")
	}

	// Challenge mit Name, dann Ende: Name wird gemeldet
	c2, br2 := sensorMTAPIDial(t, p)
	_, _ = c2.Write(sensorMTAPISent("/login", "=name=bob"))
	if got := sensorMTAPIRead(t, c2, br2); got[0] != "!done" {
		t.Fatalf("Challenge: %q", got)
	}
	c2.Close()
	e = rec.wait(t, func(e Event) bool { return e.Kind == KindRouterBrute && e.Username == "bob" })
	if e.Password != "" || e.Detail != "challenge" {
		t.Fatalf("bob: %+v", e)
	}
}

func TestSensorMTAPINotLoggedIn(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcMTAPI, p, ""}}})

	c, br := sensorMTAPIDial(t, p)
	req := sensorMTAPISent("/system/resource/print")
	_, _ = c.Write(req)
	sensorMTAPIWant(t, c, br, "!fatal", "not logged in")
	sensorMTAPIEnd(t, c, br)
	e := rec.wait(t, sensorKind(KindProbe))
	if e.Detail != "/system/resource/print" || !bytes.Equal(e.Payload, req) {
		t.Fatalf("Probe: %+v", e)
	}

	// /quit
	c2, br2 := sensorMTAPIDial(t, p)
	_, _ = c2.Write(sensorMTAPISent("/quit"))
	sensorMTAPIWant(t, c2, br2, "!fatal", "session terminated on request")
	sensorMTAPIEnd(t, c2, br2)
	rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Detail == "/quit" })
}

func TestSensorMTAPITLS(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcMTAPI, p, ""}}})

	c, err := tls.Dial("tcp", sensorAddrOf(p), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	_, _ = c.Write(sensorMTAPISent("/login", "=name=tlsuser", "=password=tlspass"))
	sensorMTAPIWant(t, c, br, "!trap", "=message=invalid user name or password (6)")
	sensorMTAPIWant(t, c, br, "!done")
	e := rec.wait(t, sensorKind(KindRouterBrute))
	if e.Username != "tlsuser" || e.Password != "tlspass" || e.Client != "tls" || e.Port != p {
		t.Fatalf("Ereignis: %+v", e)
	}

	// 0x16 ohne gueltigen Handshake
	c2, _ := sensorMTAPIDial(t, p)
	_, _ = c2.Write([]byte{0x16, 3, 1, 0, 1, 0xff})
	_ = c2.(*net.TCPConn).CloseWrite()
	sensorMTAPIEnd(t, c2, c2)
	rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Detail == "tls: no handshake" })
}

func TestSensorMTAPIJunk(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcMTAPI, p, ""}}})
	bad := func(e Event) bool { return e.Kind == KindProbe && strings.Contains(e.Detail, "bad word") }

	cases := [][]byte{
		{0xF8},                         // Steuerbyte
		{0xF0, 0xff, 0xff, 0xff, 0xff}, // 4 GiB
		{0xE1, 0x00, 0x00, 0x00},       // ueber sensorMTAPIWord
		append(bytes.Repeat([]byte{1, 'a'}, sensorMTAPIWords+1), 0), // zu viele Woerter
	}
	for i, b := range cases {
		c, br := sensorMTAPIDial(t, p)
		_, _ = c.Write(b)
		sensorMTAPIEnd(t, c, br)
		if n := len(b); i < 3 {
			e := rec.wait(t, func(e Event) bool { return bad(e) && len(e.Payload) == n })
			if !bytes.Equal(e.Payload, b) {
				t.Fatalf("Payload %d: %x", i, e.Payload)
			}
		}
	}
	sensorWaitCounter(t, func() int64 { return int64(rec.count(bad)) }, int64(len(cases)))

	// abgeschnittenes Wort, dann Ende; nur Verbindung
	c, _ := sensorMTAPIDial(t, p)
	_, _ = c.Write([]byte{5, 'a', 'b'})
	c.Close()
	rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && string(e.Payload) == "\x05ab" })
	c2, _ := sensorMTAPIDial(t, p)
	c2.Close()
	rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Detail == "" && len(e.Payload) == 0 })

	// Satzgrenze: /login ohne Passwort zaehlt nicht als Versuch, nach sensorMTAPICmds Saetzen getrennt
	c3, br3 := sensorMTAPIDial(t, p)
	_, _ = c3.Write(bytes.Repeat(sensorMTAPISent("/login"), sensorMTAPICmds))
	for i := 0; i < sensorMTAPICmds; i++ {
		if got := sensorMTAPIRead(t, c3, br3); got[0] != "!done" {
			t.Fatalf("Satz %d: %q", i, got)
		}
	}
	sensorMTAPIEnd(t, c3, br3)
	if rec.count(sensorKind(KindRouterBrute)) != 0 {
		t.Fatal("Anmeldung ohne Name gemeldet")
	}
}

// Wortlaengen: alle Kodierungen hin und zurueck.
func TestSensorMTAPILen(t *testing.T) {
	for _, n := range []int{0, 1, 0x7f, 0x80, 0x3fff, 0x4000, 0x1fffff} {
		b := sensorMTAPIEnc(nil, strings.Repeat("x", n))
		got, err := sensorMTAPILen(bufio.NewReader(bytes.NewReader(b)))
		if err != nil || got != n {
			t.Fatalf("%d: %d %v", n, got, err)
		}
	}
	if n, err := sensorMTAPILen(bufio.NewReader(bytes.NewReader([]byte{0xF0, 1, 2, 3, 4}))); err != nil || n != 0x01020304 {
		t.Fatalf("5 Bytes: %x %v", n, err)
	}
	for _, b := range [][]byte{{0xF1}, {0xFF}, {0x81}, {0xF0, 1}, {0xF0, 0x80, 0, 0, 0}, {0xF0, 0xFF, 0xFF, 0xFF, 0xFF}} {
		if _, err := sensorMTAPILen(bufio.NewReader(bytes.NewReader(b))); err == nil {
			t.Fatalf("%x: kein Fehler", b)
		}
	}
	// Zufaellige Laengen: nie negativ (auch auf 32 Bit), nie ueber 2^31-1
	for i := 0; i < 5000; i++ {
		b := make([]byte, 5)
		for j := range b {
			b[j] = byte(mrand.N(256))
		}
		if i%2 == 0 {
			b[0] = 0xF0
		}
		if n, err := sensorMTAPILen(bufio.NewReader(bytes.NewReader(b))); err == nil && (n < 0 || n > 0x7fffffff) {
			t.Fatalf("%x: %d", b, n)
		}
	}
}

// Ein Wort mit 4 Laengenbytes und gesetztem obersten Bit: Fehler statt Panik (TCP 8728: F0 80 00 00 00).
func TestSensorMTAPIHugeWord(t *testing.T) {
	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	a := &sensorMTAPI{br: bufio.NewReader(bytes.NewReader([]byte{0xF0, 0x80, 0, 0, 0})), c: &trapConn{Conn: p1}, end: time.Now().Add(time.Minute)}
	if _, err := a.sentence(); err == nil {
		t.Fatal("kein Fehler")
	}
}
