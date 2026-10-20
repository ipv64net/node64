package honeypot

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// sensorReadUntil liest, bis want im (von IAC befreiten) Strom auftaucht.
func sensorReadUntil(t *testing.T, c net.Conn, want string) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got []byte
	buf := make([]byte, 256)
	for !bytes.Contains(got, []byte(want)) {
		n, err := c.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			t.Fatalf("%q nicht erhalten (%v), bisher %q", want, err, got)
		}
	}
	return got
}

func TestSensorTelnet(t *testing.T) {
	old := sensorTelDelay
	sensorTelDelay = 0
	t.Cleanup(func() { sensorTelDelay = old }) // laeuft nach s.Stop (Cleanups rueckwaerts)
	p := sensorFreePort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcTelnet, p, ""}}})

	c, err := net.Dial("tcp", sensorAddrOf(p))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	first := sensorReadUntil(t, c, "login: ")
	if !bytes.HasPrefix(first, sensorTelIAC) {
		t.Fatalf("keine Telnet-Optionen: %q", first)
	}
	// Antwort auf die Optionen und eine Unterverhandlung (Fenstergroesse) vor dem Benutzernamen
	_, _ = c.Write([]byte("\xff\xfb\x1f\xff\xfa\x1f\x00\x50\x00\x18\xff\xf0\xff\xfd\x01root\r\n"))
	if got := sensorReadUntil(t, c, "Password: "); !bytes.Contains(got, []byte("root")) {
		t.Fatalf("kein Echo: %q", got)
	}
	_, _ = c.Write([]byte("xc3511\r\x00"))
	sensorReadUntil(t, c, "Login incorrect")
	e := rec.wait(t, sensorKind(KindTelnetBrute))
	if e.Username != "root" || e.Password != "xc3511" || e.Service != SvcTelnet {
		t.Fatalf("Ereignis: %+v", e)
	}

	// weitere Versuche, dann getrennt
	for _, cred := range []string{"admin\r\nadmin\r\n", "user\nuser\n"} {
		_, _ = c.Write([]byte(cred))
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("nicht getrennt: %v", err)
	}
	if n := rec.count(sensorKind(KindTelnetBrute)); n != sensorTelTries {
		t.Fatalf("Versuche: %d", n)
	}
	rec.wait(t, func(e Event) bool { return e.Kind == KindTelnetBrute && e.Username == "user" && e.Password == "user" })
	if s.counters.Logins.Load() != sensorTelTries {
		t.Fatalf("Logins = %d", s.counters.Logins.Load())
	}
}
