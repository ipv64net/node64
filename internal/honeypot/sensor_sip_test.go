package honeypot

import (
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
	"time"
)

// sensorSIPMsg baut eine Anfrage wie ein Scanner (CRLF, Leerzeile am Ende).
func sensorSIPMsg(method, uri string, extra ...string) []byte {
	h := []string{method + " " + uri + " SIP/2.0",
		"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-524287-1---abcdef;rport",
		"Max-Forwards: 70",
		`From: "100"<sip:100@10.0.0.1>;tag=6434396633623535`,
		`To: "100"<sip:100@10.0.0.1>`,
		"Call-ID: 917427339401337@10.0.0.1",
		"CSeq: 1 " + method,
		"Contact: <sip:100@10.0.0.1:5060>",
		"Accept: application/sdp",
		"Content-Length: 0"}
	h = append(h, extra...)
	return []byte(strings.Join(h, "\r\n") + "\r\n\r\n")
}

func TestSensorSIP(t *testing.T) {
	p := sensorFreeUDPPort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcSIP, p, ""}}})
	c := sensorUDPDial(t, p)
	wait := 2 * time.Second

	// OPTIONS-Scanner: 404, Kopfzeilen uebernommen
	r := string(sensorUDPReply(t, c, sensorSIPMsg("OPTIONS", "sip:100@127.0.0.1", "User-Agent: friendly-scanner"), wait))
	if !strings.HasPrefix(r, "SIP/2.0 404 Not Found\r\n") || !strings.Contains(r, "\r\nCall-ID: 917427339401337@10.0.0.1\r\n") ||
		!strings.Contains(r, "\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=") || !strings.Contains(r, "\r\nCSeq: 1 OPTIONS\r\n") || !strings.HasSuffix(r, "\r\n\r\n") {
		t.Fatalf("Antwort: %q", r)
	}
	e := rec.wait(t, sensorKind(KindSIPScan))
	if e.UA != "friendly-scanner" || e.Method != "OPTIONS" || e.Detail != "options 100" || e.Service != SvcSIP || e.Port != p || e.Src.String() != "127.0.0.1" {
		t.Fatalf("Ereignis: %+v", e)
	}

	// REGISTER ohne Anmeldedaten: 401 mit Challenge, sip:scan
	r = string(sensorUDPReply(t, c, sensorSIPMsg("REGISTER", "sip:127.0.0.1", "User-Agent: pplsip"), wait))
	if !strings.HasPrefix(r, "SIP/2.0 401 Unauthorized\r\n") || !strings.Contains(r, "\r\nWWW-Authenticate: Digest realm=\"sip\", nonce=\"") ||
		!strings.Contains(r, "\r\nTo: \"100\"<sip:100@10.0.0.1>;tag=") {
		t.Fatalf("Antwort: %q", r)
	}
	rec.wait(t, func(e Event) bool {
		return e.Kind == KindSIPScan && e.Method == "REGISTER" && e.Detail == "register" && e.UA == "pplsip"
	})

	// REGISTER mit Digest: sip:bruteforce
	auth := `Authorization: Digest username="1001", realm="sip", nonce="abc", uri="sip:127.0.0.1", response="0123456789abcdef0123456789abcdef", algorithm=MD5`
	r = string(sensorUDPReply(t, c, sensorSIPMsg("REGISTER", "sip:127.0.0.1", auth), wait))
	if !strings.HasPrefix(r, "SIP/2.0 401 Unauthorized\r\n") {
		t.Fatalf("Antwort: %q", r)
	}
	e = rec.wait(t, sensorKind(KindSIPBrute))
	if e.Username != "1001" || e.Detail != "digest" || e.Password != "" || e.Method != "REGISTER" {
		t.Fatalf("Ereignis: %+v", e)
	}
	if s.counters.Logins.Load() != 1 {
		t.Fatalf("Logins = %d", s.counters.Logins.Load())
	}

	// INVITE mit Proxy-Authorization, Name ohne Anfuehrungszeichen, kompakte Kopfzeilen
	inv := "INVITE sip:200@127.0.0.1 SIP/2.0\nv: SIP/2.0/UDP 10.0.0.2\nf: <sip:a@b>;tag=1\nt: <sip:200@127.0.0.1>\ni: x1\nCSeq: 2 INVITE\n" +
		"Proxy-Authorization: digest realm=\"x\",username=bob,nonce=\"n\"\nUser-Agent: sipcli/v1.8\nContent-Length: 0\n\n"
	r = string(sensorUDPReply(t, c, []byte(inv), wait))
	if !strings.HasPrefix(r, "SIP/2.0 401 Unauthorized\r\n") || !strings.Contains(r, "\r\nCall-ID: x1\r\n") {
		t.Fatalf("Antwort: %q", r)
	}
	if e := rec.wait(t, func(e Event) bool { return e.Kind == KindSIPBrute && e.Username == "bob" }); e.UA != "sipcli/v1.8" || e.Method != "INVITE" {
		t.Fatalf("INVITE: %+v", e)
	}

	// kurze Anfrage: nur die Statuszeile; noch kuerzer: keine Antwort
	small := []byte("OPTIONS sip:a SIP/2.0\r\n\r\n")
	if r := string(sensorUDPReply(t, c, small, wait)); r != "SIP/2.0 404 Not Found\r\n\r\n" {
		t.Fatalf("kurz: %q", r)
	}
	if r := sensorUDPReply(t, c, []byte("INVITE s SIP/2.0\n\n"), 300*time.Millisecond); r != nil {
		t.Fatalf("zu kurz: %q", r)
	}
	rec.wait(t, func(e Event) bool { return e.Kind == KindSIPScan && e.Method == "INVITE" && e.Detail == "invite" })

	// ACK, SIP-Antwort, Muell: keine Antwort
	if r := sensorUDPReply(t, c, sensorSIPMsg("ACK", "sip:100@127.0.0.1"), 300*time.Millisecond); r != nil {
		t.Fatalf("ACK: %q", r)
	}
	rec.wait(t, func(e Event) bool { return e.Method == "ACK" })
	for _, b := range []string{"SIP/2.0 200 OK\r\nVia: x\r\n\r\n", "hello", "\x00\x01\x02", "options sip:a SIP/2.0\r\n\r\n", "OPTIONS  SIP/2.0\r\n\r\n"} {
		if r := sensorUDPReply(t, c, []byte(b), 200*time.Millisecond); r != nil {
			t.Fatalf("%q beantwortet: %q", b, r)
		}
	}
	if n := rec.count(func(e Event) bool { return e.Kind == KindProbe && e.Detail == "sip: no request" }); n != 5 {
		t.Fatalf("Proben: %d", n)
	}
}

func TestSensorSIPRateLimit(t *testing.T) {
	p := sensorFreeUDPPort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcSIP, p, ""}}})
	c := sensorUDPDial(t, p)
	req := sensorSIPMsg("OPTIONS", "sip:100@127.0.0.1", "User-Agent: friendly-scanner")
	for i := 0; i < sensorSIPPerSrc+15; i++ {
		_, _ = c.Write(req)
		if i%16 == 15 {
			time.Sleep(5 * time.Millisecond)
		}
	}
	replies := 0
	buf := make([]byte, 8192)
	for {
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.Read(buf)
		if err != nil {
			break
		}
		if n > len(req) {
			t.Fatalf("Antwort %d > Anfrage %d", n, len(req))
		}
		replies++
	}
	if replies != sensorSIPPerSrc {
		t.Fatalf("Antworten: %d", replies)
	}
	if n := rec.count(sensorKind(KindSIPScan)); n != sensorSIPPerSrc {
		t.Fatalf("Ereignisse: %d", n)
	}
}

// Zufaellige, abgeschnittene und uebergrosse Anfragen: keine Panik, Antwort nie groesser als die Anfrage.
func TestSensorSIPParseFuzz(t *testing.T) {
	good := sensorSIPMsg("REGISTER", "sip:1@x", `Authorization: Digest username="a\"b\\c", nonce="n"`, "User-Agent: "+strings.Repeat("u", 600))
	r, ok := sensorSIPParse(good)
	if !ok || !r.digest || r.user != `a"b\c` || len(r.ua) != sensorSIPField {
		t.Fatalf("%+v %v", r, ok)
	}
	for i := 0; i <= len(good); i++ {
		for j := 0; j < 4; j++ {
			b := append([]byte(nil), good[:i]...)
			if len(b) > 0 && j > 0 {
				b[rand.N(len(b))] = byte(rand.N(256))
			}
			if r, ok := sensorSIPParse(b); ok {
				if out := sensorSIPAnswer(&r, "401 Unauthorized", true, len(b)); len(out) > len(b) {
					t.Fatalf("Antwort zu gross: %d > %d", len(out), len(b))
				}
			}
		}
	}
	for _, v := range []string{"Digest", "Digest ", "Digest username", `Digest username="`, `Digest a=1,,, username = x`, `Basic username="x"`, `Digest realm="a,username=y", username=z`} {
		u, ok := sensorSIPDigestUser(v)
		t.Logf("%q -> %q %v", v, u, ok)
	}
	if u, _ := sensorSIPDigestUser(`Digest realm="a,username=y", username=z`); u != "z" {
		t.Fatalf("Quoting: %q", u)
	}
	if _, ok := sensorSIPDigestUser(`Basic username="x"`); ok {
		t.Fatal("Basic")
	}
	many := "OPTIONS sip:a SIP/2.0\r\n" + strings.Repeat("X-H: 1\r\n", 100) + "User-Agent: late\r\n\r\n"
	if r, ok := sensorSIPParse([]byte(many)); !ok || r.ua != "" {
		t.Fatalf("Kopfzeilen nicht begrenzt: %+v", r)
	}
	for i := 0; i < 1000; i++ {
		b := []byte("INVITE sip:" + strconv.Itoa(i) + " SIP/2.0\r\n")
		for j := rand.N(200); j > 0; j-- {
			b = append(b, byte(rand.N(256)))
		}
		if r, ok := sensorSIPParse(b); ok {
			if out := sensorSIPAnswer(&r, "401 Unauthorized", true, len(b)); len(out) > len(b) {
				t.Fatal("Antwort zu gross")
			}
		}
	}
}
