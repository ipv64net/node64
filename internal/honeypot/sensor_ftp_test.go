package honeypot

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// sensorPlainNoDelay schaltet die Pause vor Ablehnungen fuer den Test ab (Cleanup laeuft nach s.Stop).
func sensorPlainNoDelay(t *testing.T) {
	old := sensorPlainDelay
	sensorPlainDelay = 0
	t.Cleanup(func() { sensorPlainDelay = old })
}

// sensorPlainDial verbindet und wartet auf das Banner.
func sensorPlainDial(t *testing.T, port int, banner string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", sensorAddrOf(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	sensorReadUntil(t, c, banner)
	return c
}

// sensorPlainSay schickt eine Zeile und wartet auf want in der Antwort.
func sensorPlainSay(t *testing.T, c net.Conn, line, want string) string {
	t.Helper()
	if _, err := io.WriteString(c, line+"\r\n"); err != nil {
		t.Fatal(err)
	}
	return string(sensorReadUntil(t, c, want))
}

// sensorPlainClosed prueft, dass der Sensor die Verbindung schliesst, und liefert den Rest der Ausgabe.
func sensorPlainClosed(t *testing.T, c net.Conn) string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("nicht getrennt: %v", err)
	}
	return string(b)
}

func TestSensorFTP(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcFTP, p, ""}}})

	c := sensorPlainDial(t, p, "220 FTP server ready\r\n")
	sensorPlainSay(t, c, "SYST", "215 UNIX Type: L8\r\n")
	sensorPlainSay(t, c, "FEAT", "211 End\r\n")
	sensorPlainSay(t, c, "AUTH TLS", "502 ")
	sensorPlainSay(t, c, "LIST", "530 ")
	sensorPlainSay(t, c, "PASS nouser", "503 ")
	sensorPlainSay(t, c, "USER root", "331 ")
	sensorPlainSay(t, c, "PASS pass word", "530 Login incorrect.\r\n")
	e := rec.wait(t, sensorKind(KindFTPBrute))
	if e.Username != "root" || e.Password != "pass word" || e.Service != SvcFTP || e.Port != p || e.Detail != "" {
		t.Fatalf("Ereignis: %+v", e)
	}
	sensorPlainSay(t, c, "USER anonymous", "331 ")
	sensorPlainSay(t, c, "PASS guest@example.org", "530 ")
	e = rec.wait(t, func(e Event) bool { return e.Kind == KindFTPBrute && e.Username == "anonymous" })
	if e.Password != "guest@example.org" || e.Detail != "anonymous" {
		t.Fatalf("anonymous: %+v", e)
	}

	// weitere Versuche, nach sensorFTPTries getrennt
	_, _ = io.WriteString(c, "USER a\r\nPASS a\r\nUSER b\r\nPASS b\r\nUSER c\r\nPASS c\r\n")
	sensorPlainClosed(t, c)
	if n := rec.count(sensorKind(KindFTPBrute)); n != sensorFTPTries {
		t.Fatalf("Versuche: %d", n)
	}
	if s.counters.Logins.Load() != sensorFTPTries {
		t.Fatalf("Logins = %d", s.counters.Logins.Load())
	}
	if rec.count(sensorKind(KindProbe)) != 0 {
		t.Fatal("Probe trotz Anmeldung")
	}

	// USER ohne PASS bis zum Ende zaehlt als Versuch
	c2 := sensorPlainDial(t, p, "220 ")
	sensorPlainSay(t, c2, "USER admin", "331 ")
	c2.Close()
	rec.wait(t, func(e Event) bool { return e.Kind == KindFTPBrute && e.Username == "admin" && e.Password == "" })
}

func TestSensorFTPJunk(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcFTP, p, ""}}})
	junk := string([]byte{0, 0xff, 0x16, 3, 1})

	// Muell, ueberlange Zeile, dann QUIT: keine Anmeldung, Probe mit den Befehlen
	c := sensorPlainDial(t, p, "220 ")
	sensorPlainSay(t, c, junk, "530 ")
	sensorPlainSay(t, c, "SITE "+strings.Repeat("x", 5000), "530 ")
	sensorPlainSay(t, c, "QUIT", "221 ")
	sensorPlainClosed(t, c)
	e := rec.wait(t, sensorKind(KindProbe))
	if e.Detail != "????? SITE QUIT" || e.Username != "" || string(e.Payload) != junk {
		t.Fatalf("Probe: %+v", e)
	}

	// ueberlange Zeile wird gekuerzt (Zeile auf sensorPlainLine, Feld auf MaxText)
	c1 := sensorPlainDial(t, p, "220 ")
	sensorPlainSay(t, c1, "USER "+strings.Repeat("y", 5000), "331 ")
	sensorPlainSay(t, c1, "PASS x", "530 ")
	l := rec.wait(t, sensorKind(KindFTPBrute))
	if len(l.Username) != MaxText || l.Password != "x" {
		t.Fatalf("Zeile nicht begrenzt: %d %q", len(l.Username), l.Password)
	}

	// nur Verbindung, nichts gesendet
	c2 := sensorPlainDial(t, p, "220 ")
	c2.Close()
	rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Detail == "" })

	// Befehlsgrenze: nach sensorPlainCmds Zeilen getrennt (genau so viele schicken, sonst RST statt FIN)
	c3 := sensorPlainDial(t, p, "220 ")
	_, _ = io.WriteString(c3, strings.Repeat("NOOP\r\n", sensorPlainCmds))
	if out := sensorPlainClosed(t, c3); strings.Count(out, "200 NOOP ok.") != sensorPlainCmds {
		t.Fatalf("Befehle: %d", strings.Count(out, "200 NOOP ok."))
	}
}
