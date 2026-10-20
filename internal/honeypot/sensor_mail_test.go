package honeypot

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func sensorB64Enc(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestSensorSMTP(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcSMTP, p, ""}}})

	c := sensorPlainDial(t, p, "220 "+sensorMailHost+" ESMTP\r\n")
	if out := sensorPlainSay(t, c, "EHLO "+strings.Repeat("h", 200), "250 SMTPUTF8\r\n"); !strings.Contains(out, "250-AUTH PLAIN LOGIN\r\n") {
		t.Fatalf("EHLO: %q", out)
	}
	sensorPlainSay(t, c, "STARTTLS", "454 ")
	sensorPlainSay(t, c, "AUTH PLAIN "+sensorB64Enc("\x00alice\x00s3cret"), "535 ")
	e := rec.wait(t, sensorKind(KindMailBrute))
	if e.Username != "alice" || e.Password != "s3cret" || e.Service != SvcSMTP || e.Detail != "plain" || e.Client != strings.Repeat("h", sensorPlainClient) {
		t.Fatalf("PLAIN: %+v", e)
	}
	// PLAIN ohne Initial-Response, LOGIN zweistufig
	sensorPlainSay(t, c, "AUTH PLAIN", "334 \r\n")
	sensorPlainSay(t, c, sensorB64Enc("admin\x00\x00pw"), "535 ")
	rec.wait(t, func(e Event) bool { return e.Username == "admin" && e.Password == "pw" })
	sensorPlainSay(t, c, "AUTH LOGIN", "334 VXNlcm5hbWU6\r\n")
	sensorPlainSay(t, c, sensorB64Enc("bob@example.org"), "334 UGFzc3dvcmQ6\r\n")
	sensorPlainSay(t, c, sensorB64Enc("hunter2"), "535 ")
	e = rec.wait(t, func(e Event) bool { return e.Username == "bob@example.org" })
	if e.Password != "hunter2" || e.Detail != "login" || e.Kind != KindMailBrute {
		t.Fatalf("LOGIN: %+v", e)
	}
	// Abbruch, Muell, unbekannter Mechanismus: kein Versuch
	sensorPlainSay(t, c, "AUTH LOGIN", "334 ")
	sensorPlainSay(t, c, "*", "501 5.7.0 ")
	sensorPlainSay(t, c, "AUTH PLAIN !!!", "501 5.5.2 ")
	sensorPlainSay(t, c, "AUTH CRAM-MD5", "535 ")

	// Relay-Test
	sensorPlainSay(t, c, "MAIL FROM:<spam@example.net> SIZE=100", "250 ")
	sensorPlainSay(t, c, "RCPT TO:<victim@example.com>", "554 5.7.1 ")
	sensorPlainSay(t, c, "RCPT TO:<other@example.com>", "554 5.7.1 ")
	sensorPlainSay(t, c, "DATA", "554 ")
	r := rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Detail == "relay" })
	if string(r.Payload) != "MAIL FROM:<spam@example.net> RCPT TO:<victim@example.com>" || r.Username != "" {
		t.Fatalf("Relay: %+v", r)
	}
	if n := rec.count(func(e Event) bool { return e.Detail == "relay" }); n != 1 {
		t.Fatalf("Relay-Ereignisse: %d", n)
	}

	// weitere Versuche bis zur Grenze, dann 421 und getrennt
	_, _ = io.WriteString(c, "AUTH PLAIN "+sensorB64Enc("\x00u4\x00p4")+"\r\nAUTH PLAIN "+sensorB64Enc("\x00u5\x00p5")+"\r\n")
	if out := sensorPlainClosed(t, c); !strings.Contains(out, "421 ") {
		t.Fatalf("keine 421: %q", out)
	}
	if n := rec.count(sensorKind(KindMailBrute)); n != sensorMailTries {
		t.Fatalf("Versuche: %d", n)
	}
	if s.counters.Logins.Load() != sensorMailTries {
		t.Fatalf("Logins = %d", s.counters.Logins.Load())
	}

	// Verbindung ohne Anmeldung -> Probe mit Client und Befehlen
	c2 := sensorPlainDial(t, p, "220 ")
	sensorPlainSay(t, c2, "HELO scanner", "250 ")
	sensorPlainSay(t, c2, "QUIT", "221 ")
	sensorPlainClosed(t, c2)
	e = rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Detail == "HELO QUIT" })
	if e.Client != "scanner" || string(e.Payload) != "HELO scanner" {
		t.Fatalf("Probe: %+v", e)
	}
}

func TestSensorPOP3(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcPOP3, p, ""}}})

	c := sensorPlainDial(t, p, "+OK ")
	sensorPlainSay(t, c, "CAPA", "\r\n.\r\n")
	sensorPlainSay(t, c, "PASS x", "-ERR ")
	sensorPlainSay(t, c, "USER info@example.org", "+OK\r\n")
	sensorPlainSay(t, c, "PASS my pass", "-ERR [AUTH] ")
	e := rec.wait(t, sensorKind(KindMailBrute))
	if e.Username != "info@example.org" || e.Password != "my pass" || e.Service != SvcPOP3 || e.Detail != "user" {
		t.Fatalf("USER/PASS: %+v", e)
	}
	sensorPlainSay(t, c, "APOP mrose c4c9334bac560ecc979e58001b3e22fb", "-ERR [AUTH] ")
	e = rec.wait(t, func(e Event) bool { return e.Detail == "apop" })
	if e.Username != "mrose" || e.Password != "" {
		t.Fatalf("APOP: %+v", e)
	}
	sensorPlainSay(t, c, "AUTH PLAIN", "+ \r\n")
	sensorPlainSay(t, c, sensorB64Enc("\x00carol\x00pw1"), "-ERR [AUTH] ")
	rec.wait(t, func(e Event) bool { return e.Username == "carol" && e.Password == "pw1" && e.Detail == "plain" })
	sensorPlainSay(t, c, "STLS", "-ERR ")
	sensorPlainSay(t, c, "RETR 1", "-ERR Unknown")
	sensorPlainSay(t, c, "QUIT", "+OK ")
	sensorPlainClosed(t, c)
	if n := rec.count(sensorKind(KindMailBrute)); n != 3 {
		t.Fatalf("Versuche: %d", n)
	}
}

func TestSensorIMAP(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcIMAP, p, ""}}})

	c := sensorPlainDial(t, p, "* OK [CAPABILITY ")
	sensorPlainSay(t, c, "a1 CAPABILITY", "a1 OK ")
	sensorPlainSay(t, c, `a2 LOGIN "us\"er" "p a\\ss"`, "a2 NO [AUTHENTICATIONFAILED] ")
	e := rec.wait(t, sensorKind(KindMailBrute))
	if e.Username != `us"er` || e.Password != `p a\ss` || e.Service != SvcIMAP || e.Detail != "login" {
		t.Fatalf("LOGIN quoted: %+v", e)
	}
	// Literale: synchron {n} (Server antwortet "+") und LITERAL+ {n+} (ohne Rueckfrage)
	sensorPlainSay(t, c, "a3 LOGIN {4}", "+ Ready")
	if _, err := io.WriteString(c, "root {6+}\r\nsecret\r\n"); err != nil {
		t.Fatal(err)
	}
	sensorReadUntil(t, c, "a3 NO ")
	rec.wait(t, func(e Event) bool { return e.Username == "root" && e.Password == "secret" })
	// AUTHENTICATE PLAIN mit SASL-IR und mit Rueckfrage
	sensorPlainSay(t, c, "a4 AUTHENTICATE PLAIN "+sensorB64Enc("\x00dave\x00pw4"), "a4 NO ")
	sensorPlainSay(t, c, "a5 authenticate plain", "+ \r\n")
	sensorPlainSay(t, c, sensorB64Enc("\x00erin\x00pw5"), "a5 NO ")
	e = rec.wait(t, func(e Event) bool { return e.Username == "erin" })
	if e.Password != "pw5" || e.Detail != "plain" {
		t.Fatalf("AUTHENTICATE: %+v", e)
	}
	// kein Versuch: Abbruch, ungueltiges Tag, zu grosses Literal, Befehl ohne Anmeldung
	sensorPlainSay(t, c, "a6 AUTHENTICATE LOGIN", "+ VXNlcm5hbWU6")
	sensorPlainSay(t, c, "*", "a6 BAD ")
	sensorPlainSay(t, c, "(x CAPABILITY", "* BAD ")
	sensorPlainSay(t, c, "a7 LOGIN {99999}", "a7 BAD ")
	sensorPlainSay(t, c, "a8 SELECT INBOX", "a8 BAD ")
	sensorPlainSay(t, c, "a9 STARTTLS", "a9 NO ")
	if n := rec.count(sensorKind(KindMailBrute)); n != 4 {
		t.Fatalf("Versuche: %d", n)
	}
	// fuenfter Versuch -> BYE und getrennt
	sensorPlainSay(t, c, "b1 LOGIN last try", "b1 NO ")
	if out := sensorPlainClosed(t, c); !strings.Contains(out, "* BYE") {
		t.Fatalf("kein BYE: %q", out)
	}
	if n := rec.count(sensorKind(KindMailBrute)); n != sensorMailTries {
		t.Fatalf("Versuche: %d", n)
	}
}

func TestSensorSASL(t *testing.T) {
	for _, tc := range []struct{ in, user, pass string }{
		{sensorB64Enc("\x00u\x00p"), "u", "p"},
		{sensorB64Enc("authz\x00u\x00p\x00x"), "u", "p\x00x"},
		{sensorB64Enc("only\x00\x00p"), "only", "p"},
		{strings.TrimRight(sensorB64Enc("\x00ab\x00c"), "="), "ab", "c"},
	} {
		u, p, ok := sensorSASLPlain(tc.in)
		if !ok || u != tc.user || p != tc.pass {
			t.Fatalf("%q -> %q %q %v", tc.in, u, p, ok)
		}
	}
	for _, in := range []string{"", "!!", sensorB64Enc("nonul"), sensorB64Enc("a\x00b")} {
		if _, _, ok := sensorSASLPlain(in); ok {
			t.Fatalf("%q angenommen", in)
		}
	}
}

// Muell auf allen Mail-Diensten: keine Panik, Verbindung endet, nur Probe- oder Anmelde-Ereignisse.
func TestSensorMailJunk(t *testing.T) {
	sensorPlainNoDelay(t)
	ps, p3, pi := sensorFreePort(t), sensorFreePort(t), sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcSMTP, ps, ""}, {SvcPOP3, p3, ""}, {SvcIMAP, pi, ""}}})
	junk := []string{"", "\x00\xff\xfe", "AUTH", "AUTH LOGIN =", "AUTH PLAIN =", "a LOGIN", `a LOGIN "open`, "a LOGIN {x}",
		"a LOGIN {3+}", "a AUTHENTICATE", "a AUTHENTICATE PLAIN ===", "RCPT", "MAIL", "APOP", "USER", strings.Repeat("Z", 3000)}
	for _, port := range []int{ps, p3, pi} {
		c, err := net.Dial("tcp", sensorAddrOf(port))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(c, strings.Join(junk, "\r\n")+"\r\n")
		_ = c.(*net.TCPConn).CloseWrite()
		sensorPlainClosed(t, c)
		c.Close()
	}
	for _, e := range rec.all() {
		if e.Kind != KindProbe && e.Kind != KindMailBrute {
			t.Fatalf("Ereignis: %+v", e)
		}
	}
	rec.wait(t, func(e Event) bool { return e.Service == SvcSMTP })
	rec.wait(t, func(e Event) bool { return e.Service == SvcPOP3 })
	rec.wait(t, func(e Event) bool { return e.Service == SvcIMAP })
}

// Zeilenlaenge der Sitzung ueber net.Pipe.
func TestSensorPlainLine(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	p := &sensorPlain{c: &trapConn{Conn: a}, br: bufio.NewReader(a), end: time.Now().Add(time.Minute)}
	go func() { _, _ = io.WriteString(b, strings.Repeat("x", 2000)+"\r\nnext\n") }()
	l, err := p.line()
	if err != nil || len(l) != sensorPlainLine {
		t.Fatalf("Zeile: %d %v", len(l), err)
	}
	if l, err = p.line(); err != nil || l != "next" {
		t.Fatalf("naechste Zeile: %q %v", l, err)
	}
}
