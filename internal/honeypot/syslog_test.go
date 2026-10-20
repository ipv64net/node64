package honeypot

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func TestParseSyslog3164(t *testing.T) {
	now := time.Date(2026, 10, 11, 22, 20, 0, 0, time.Local)
	at := func(mon time.Month, d, h, m, s int) time.Time {
		return time.Date(2026, mon, d, h, m, s, 0, time.Local).UTC()
	}
	from := netip.MustParseAddr("192.168.1.1")
	cases := []struct {
		in              string
		host, prog, msg string
		tm              time.Time
	}{
		{"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for someone on /dev/pts/8", "mymachine", "su", "'su root' failed for someone on /dev/pts/8", at(10, 11, 22, 14, 15)},
		{"<13>Oct  1 03:04:05 host sshd[123]: Failed password", "host", "sshd", "Failed password", now.UTC()}, // 10 Tage alt: Empfangszeit
		{"<13>Oct 11 22:04:05.250 host sshd[123]: x", "host", "sshd", "x", at(10, 11, 22, 4, 5).Add(250 * time.Millisecond)},
		{"<134>Oct 11 22:14:15 filterlog[12345]: 5,,,1000000103,igb0", "", "filterlog", "5,,,1000000103,igb0", at(10, 11, 22, 14, 15)},
		{"Oct 11 22:14:15 host app: ohne PRI", "host", "app", "ohne PRI", at(10, 11, 22, 14, 15)},
		{"<134>system,error,critical login failure for user admin from 198.51.100.7 via ssh", "", "", "system,error,critical login failure for user admin from 198.51.100.7 via ssh", now.UTC()},
		{"<134>Oct 11 22:14:15 MikroTik system,error,critical login failure", "MikroTik", "", "system,error,critical login failure", at(10, 11, 22, 14, 15)},
		{"<43>php-fpm[123]: /index.php: webConfigurator authentication error", "", "php-fpm", "/index.php: webConfigurator authentication error", now.UTC()},
		{`<189>date=2026-10-11 time=22:14:15 devname="FG" logdesc="Admin login failed" srcip=198.51.100.7`, "", "", `date=2026-10-11 time=22:14:15 devname="FG" logdesc="Admin login failed" srcip=198.51.100.7`, now.UTC()},
		{`<30>Oct 11 22:14:15 fw device="SFW" src_ip=198.51.100.7`, "fw", "", `device="SFW" src_ip=198.51.100.7`, at(10, 11, 22, 14, 15)},
		{"<30>2026-10-11T20:14:15Z host app[1]: hi", "host", "app", "hi", time.Date(2026, 10, 11, 20, 14, 15, 0, time.UTC)},
		{"<30>myhost sshd[1]: ohne Zeit", "myhost", "sshd", "ohne Zeit", now.UTC()},
		{"<38>Oct 11 22:14:15 U7PG2,f09fc2000000,v6.5.28.14491 dropbear[1234]: Bad password", "U7PG2,f09fc2000000,v6.5.28.14491", "dropbear", "Bad password", at(10, 11, 22, 14, 15)},
		{"<14>Oct 11 22:14:15 2001:db8::1 postfix/smtpd[9]: warning", "2001:db8::1", "postfix/smtpd", "warning", at(10, 11, 22, 14, 15)},
		{"<999>kaputte PRI", "", "", "<999>kaputte PRI", now.UTC()},
		{"nur Text\r\n\x00", "", "", "nur Text", now.UTC()},
		{"<14>Feb 30 10:00:00 h a: unmoeglicher Tag", "h", "a", "unmoeglicher Tag", now.UTC()},
		{"<14>Oct 11 25:00:00 h a: falsche Stunde", "", "", "Oct 11 25:00:00 h a: falsche Stunde", now.UTC()},
	}
	for _, c := range cases {
		l := ParseSyslog([]byte(c.in), from, now)
		if l.Host != c.host || l.Program != c.prog || l.Message != c.msg || !l.Time.Equal(c.tm) {
			t.Errorf("%q:\n got host=%q prog=%q msg=%q time=%v\nwant host=%q prog=%q msg=%q time=%v", c.in, l.Host, l.Program, l.Message, l.Time, c.host, c.prog, c.msg, c.tm)
		}
		if l.Origin != SrcSyslog || l.Format != "syslog" || l.Time.Location() != time.UTC {
			t.Errorf("%q: origin/format/zone falsch: %+v", c.in, l)
		}
	}
}

func TestParseSyslogYearChange(t *testing.T) {
	// Nachricht vom 31.12., empfangen am 1.1. kurz nach Mitternacht
	now := time.Date(2027, 1, 1, 0, 5, 0, 0, time.Local)
	l := ParseSyslog([]byte("<13>Dec 31 23:59:00 h a: x"), netip.Addr{}, now)
	if want := time.Date(2026, 12, 31, 23, 59, 0, 0, time.Local).UTC(); !l.Time.Equal(want) {
		t.Errorf("Jahreswechsel rueckwaerts: %v, want %v", l.Time, want)
	}
	// Geraeteuhr etwas vor: Nachricht vom 1.1., empfangen am 31.12.
	now = time.Date(2026, 12, 31, 23, 59, 0, 0, time.Local)
	l = ParseSyslog([]byte("<13>Jan  1 00:01:00 h a: x"), netip.Addr{}, now)
	if want := time.Date(2027, 1, 1, 0, 1, 0, 0, time.Local).UTC(); !l.Time.Equal(want) {
		t.Errorf("Jahreswechsel vorwaerts: %v, want %v", l.Time, want)
	}
	// unplausibel (Monate entfernt): Empfangszeit
	now = time.Date(2026, 10, 11, 12, 0, 0, 0, time.Local)
	l = ParseSyslog([]byte("<13>Mar  3 10:00:00 h a: x"), netip.Addr{}, now)
	if !l.Time.Equal(now.UTC()) {
		t.Errorf("unplausibel: %v", l.Time)
	}
	// Null-Zeit: jetzt
	l = ParseSyslog([]byte("x"), netip.Addr{}, time.Time{})
	if time.Since(l.Time) > time.Minute {
		t.Errorf("now leer: %v", l.Time)
	}
}

func TestParseSyslog5424(t *testing.T) {
	now := time.Date(2003, 10, 11, 22, 0, 0, 0, time.UTC)
	cases := []struct {
		in              string
		host, prog, msg string
		tm              time.Time
	}{
		{"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] \xEF\xBB\xBFAn application event log entry",
			"mymachine.example.com", "evntslog", "An application event log entry", time.Date(2003, 10, 11, 22, 14, 15, 3e6, time.UTC)},
		{"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed", "mymachine.example.com", "su", "BOM'su root' failed", time.Date(2003, 10, 11, 22, 14, 15, 3e6, time.UTC)},
		{"<34>1 2003-10-12T00:14:15+02:00 h sshd[77] 77 - - msg", "h", "sshd", "msg", time.Date(2003, 10, 11, 22, 14, 15, 0, time.UTC)},
		{"<34>1 - - - - - - nur Nachricht", "", "", "nur Nachricht", now},
		{"<34>1 - - - - - [a b=\"x\\]y\"][c@1 d=\"e\"] nach SD", "", "", "nach SD", now},
		{"<34>1 - h app - - [kaputt b=\"x", "h", "app", "[kaputt b=\"x", now},
		{"<34>1 - h app - -", "h", "app", "", now},
		{"<34>1 2003-10-11T22:14:15Z", "", "", "", time.Date(2003, 10, 11, 22, 14, 15, 0, time.UTC)},
		{"<34>1 1999-01-01T00:00:00Z h app - - - alt", "h", "app", "alt", now},    // unplausibel
		{"<34>1 kein-zeitstempel h app", "", "", "1 kein-zeitstempel h app", now}, // kein 5424
		{`<134>1 2003-10-11T22:14:15+00:00 OPNsense.localdomain filterlog 54321 - [meta sequenceId="1"] 82,,,fae559338f65e11c53669fc3642c93c2,vtnet0`,
			"OPNsense.localdomain", "filterlog", "82,,,fae559338f65e11c53669fc3642c93c2,vtnet0", time.Date(2003, 10, 11, 22, 14, 15, 0, time.UTC)},
	}
	for _, c := range cases {
		l := ParseSyslog([]byte(c.in), netip.Addr{}, now)
		if l.Host != c.host || l.Program != c.prog || l.Message != c.msg || !l.Time.Equal(c.tm) {
			t.Errorf("%q:\n got host=%q prog=%q msg=%q time=%v\nwant host=%q prog=%q msg=%q time=%v", c.in, l.Host, l.Program, l.Message, l.Time, c.host, c.prog, c.msg, c.tm)
		}
	}
}

// Fuzz-artiger Kurztest: zufaellige und verstuemmelte Eingaben duerfen nicht zu Panik oder zu langen Nachrichten fuehren.
func TestParseSyslogGarbage(t *testing.T) {
	seeds := []string{
		"<165>1 2003-10-11T22:14:15.003Z h a p m [x y=\"z\"] \xEF\xBB\xBFmsg",
		"<34>Oct 11 22:14:15 mymachine su[1]: msg",
		"<", "<>", "<1", "<12>", "<191>", "<192>x", "1 ", "1 -", "Oct", "Oct 11", "Oct 11 22:14:1", "[", "]", ":", "a[:", "a[]:",
		"\xEF\xBB\xBF", "\x00\x00", "<34>1 - - - - - [", "<34>1 - - - - - [\"\\", strings.Repeat("<", 100),
	}
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 3000; i++ {
		var b []byte
		if i%2 == 0 {
			s := seeds[rnd.Intn(len(seeds))]
			b = []byte(s[:rnd.Intn(len(s)+1)])
			for k := 0; k < 3 && len(b) > 0; k++ {
				b[rnd.Intn(len(b))] = byte(rnd.Intn(256))
			}
		} else {
			b = make([]byte, rnd.Intn(200))
			rnd.Read(b)
		}
		_ = ParseSyslog(b, netip.Addr{}, time.Now())
	}
	long := []byte("<34>Oct 11 22:14:15 h a: " + strings.Repeat("x", 3*SyslogMaxMsg))
	if l := ParseSyslog(long, netip.Addr{}, time.Now()); len(l.Message) > SyslogMaxMsg {
		t.Errorf("Nachricht nicht gekuerzt: %d", len(l.Message))
	}
}

func FuzzParseSyslog(f *testing.F) {
	for _, s := range []string{"<34>Oct 11 22:14:15 h su: x", "<165>1 2003-10-11T22:14:15.003Z h a - - [x y=\"z\"] m", "<1>", "x=1 y=\"2\""} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		l := ParseSyslog(b, netip.Addr{}, time.Now())
		if len(l.Message) > SyslogMaxMsg {
			t.Fatal("zu lang")
		}
		_ = utf8.ValidString(l.Message)
	})
}

func TestSyslogReadFrame(t *testing.T) {
	m1 := "<13>Oct 11 22:14:15 h a: eins"
	in := strconv.Itoa(len(m1)) + " " + m1 + // Octet-Counting
		"<13>zwei\n" + // Zeile
		"\n\n<13>drei\x00" + // leere Zeilen, NUL
		"2026-10-11T20:14:15Z ohne PRI\r\n" + // Ziffern ohne Octet-Count
		"5 fuenf" +
		"12345\n" + // nur Ziffern als Zeile
		"<13>" + strings.Repeat("y", SyslogMaxMsg+100) + "\n" + // zu lang: gekuerzt
		strconv.Itoa(SyslogMaxMsg+10) + " " + strings.Repeat("z", SyslogMaxMsg+10) + // Octet-Count zu lang: gekuerzt
		"letzte ohne Ende"
	want := []string{"<13>Oct 11 22:14:15 h a: eins", "<13>zwei", "<13>drei", "2026-10-11T20:14:15Z ohne PRI\r", "fuenf", "12345",
		"<13>" + strings.Repeat("y", SyslogMaxMsg-4), strings.Repeat("z", SyslogMaxMsg), "letzte ohne Ende"}
	r := bufio.NewReaderSize(strings.NewReader(in), 64)
	buf := make([]byte, 0, SyslogMaxMsg)
	var got []string
	for {
		m, err := syslogReadFrame(r, buf)
		if len(m) > 0 {
			got = append(got, string(m))
		}
		if err != nil {
			if err != io.EOF {
				t.Fatal(err)
			}
			break
		}
	}
	if len(got) != len(want) {
		t.Fatalf("got %d Nachrichten, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Nachricht %d: got %q (%d), want %q (%d)", i, trunc(got[i]), len(got[i]), trunc(want[i]), len(want[i]))
		}
	}

	// kaputter Octet-Count: zu gross bzw. zu viele Ziffern
	for _, bad := range []string{"999999 x", "1234567 x", "70000 " + strings.Repeat("a", 10)} {
		r := bufio.NewReader(strings.NewReader(bad))
		if _, err := syslogReadFrame(r, nil); !errors.Is(err, errSyslogFrame) {
			t.Errorf("%q: err %v, want errSyslogFrame", trunc(bad), err)
		}
	}
}

func trunc(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

func TestSyslogAllowed(t *testing.T) {
	def := NewSyslogServer(sensorTestLog(), 514, nil, nil)
	for ip, want := range map[string]bool{
		"10.1.2.3": true, "172.16.0.1": true, "172.32.0.1": false, "192.168.178.1": true, "100.64.1.1": true,
		"127.0.0.1": true, "::1": true, "fd00::1": true, "fe80::1": true, "198.51.100.7": false, "2001:db8::1": false,
		"8.8.8.8": false,
	} {
		if got := def.allowed(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Standard %s: %v, want %v", ip, got, want)
		}
	}
	if def.allowed(netip.Addr{}) {
		t.Error("ungueltige Adresse erlaubt")
	}
	own := NewSyslogServer(sensorTestLog(), 514, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("::ffff:203.0.113.0/120"), {}}, nil)
	for ip, want := range map[string]bool{"198.51.100.7": true, "203.0.113.9": true, "192.168.1.1": false, "127.0.0.1": false, "198.51.101.1": false} {
		if got := own.allowed(netip.MustParseAddr(ip)); got != want {
			t.Errorf("eigene %s: %v, want %v", ip, got, want)
		}
	}
}

// syslogRec sammelt die Nachrichten des Empfaengers.
type syslogRec struct {
	mu    sync.Mutex
	lines []LogLine
}

func (r *syslogRec) feed(l LogLine) {
	r.mu.Lock()
	r.lines = append(r.lines, l)
	r.mu.Unlock()
}

func (r *syslogRec) wait(t *testing.T, n int) []LogLine {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		got := append([]LogLine(nil), r.lines...)
		r.mu.Unlock()
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("nur %d von %d Nachrichten", len(got), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// syslogFreePort sucht einen Port, der fuer UDP und TCP frei ist. Geprueft wird IPv4 einzeln: unter Windows laesst
// sich ein Dual-Stack-Socket auch dann binden, wenn ein anderer Prozess denselben IPv4-UDP-Port haelt (die Datagramme
// gingen dann dorthin).
func syslogFreePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 100; i++ {
		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		p := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		addr := ":" + strconv.Itoa(p)
		ok := true
		for _, nw := range []string{"udp4", "udp", "tcp4"} {
			var c io.Closer
			if nw == "tcp4" {
				c, err = net.Listen(nw, addr)
			} else {
				c, err = net.ListenPacket(nw, addr)
			}
			if err != nil {
				ok = false
				break
			}
			_ = c.Close()
		}
		if ok {
			return p
		}
	}
	t.Fatal("kein freier Port")
	return 0
}

func syslogStartTest(t *testing.T, allow []netip.Prefix, tune func(*SyslogServer)) (*SyslogServer, *syslogRec, int) {
	t.Helper()
	rec := &syslogRec{}
	port := syslogFreePort(t)
	s := NewSyslogServer(sensorTestLog(), port, allow, rec.feed)
	if tune != nil {
		tune(s)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	return s, rec, port
}

func syslogDial(t *testing.T, network string, port int) net.Conn {
	t.Helper()
	c, err := net.Dial(network, "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestSyslogServerUDPAndTCP(t *testing.T) {
	s, rec, port := syslogStartTest(t, nil, nil)
	if st := s.Status(); !st.UDP || !st.TCP || st.Error != "" || st.Port != port {
		t.Fatalf("Status: %+v", st)
	}
	u := syslogDial(t, "udp", port)
	if _, err := u.Write([]byte("<134>Oct 11 22:14:15 MikroTik system,error,critical login failure for user admin from 198.51.100.7 via ssh\n")); err != nil {
		t.Fatal(err)
	}
	got := rec.wait(t, 1)
	if got[0].File != "udp://127.0.0.1" || got[0].Host != "MikroTik" || got[0].Origin != SrcSyslog || !strings.HasPrefix(got[0].Message, "system,error,critical login failure") {
		t.Errorf("UDP: %+v", got[0])
	}

	c := syslogDial(t, "tcp", port)
	msg1 := "<13>1 - h app - - - eins"
	if _, err := fmt.Fprintf(c, "%d %s<13>zwei\n<13>drei\x00", len(msg1), msg1); err != nil {
		t.Fatal(err)
	}
	got = rec.wait(t, 4)
	for i, want := range []string{"eins", "zwei", "drei"} {
		if l := got[1+i]; l.Message != want || l.File != "tcp://127.0.0.1" {
			t.Errorf("TCP %d: %+v", i, l)
		}
	}
	// lange UDP-Nachricht wird gekuerzt
	if _, err := u.Write([]byte("<13>h a: " + strings.Repeat("x", SyslogMaxMsg+500))); err != nil {
		t.Fatal(err)
	}
	got = rec.wait(t, 5)
	if n := len(got[4].Message); n > SyslogMaxMsg || n < SyslogMaxMsg-20 {
		t.Errorf("UDP lang: %d", n)
	}
	if st := s.Status(); st.Messages != 5 || st.Denied != 0 {
		t.Errorf("Zaehler: %+v", st)
	}
	// IPv6 auf demselben Port (falls der Rechner ::1 hat)
	if u6, err := net.Dial("udp", "[::1]:"+strconv.Itoa(port)); err == nil {
		defer u6.Close()
		_, _ = u6.Write([]byte("<13>ueber IPv6"))
		if got = rec.wait(t, 6); got[5].File != "udp://::1" || got[5].Message != "ueber IPv6" {
			t.Errorf("IPv6: %+v", got[5])
		}
	}
}

func TestSyslogServerDenied(t *testing.T) {
	s, rec, port := syslogStartTest(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, nil)
	u := syslogDial(t, "udp", port)
	_, _ = u.Write([]byte("<13>verboten"))
	c := syslogDial(t, "tcp", port)
	_, _ = c.Write([]byte("<13>verboten\n"))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Errorf("TCP fremder Absender nicht geschlossen: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for s.Status().Denied < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if st := s.Status(); st.Denied != 2 || st.Messages != 0 {
		t.Errorf("Status: %+v", st)
	}
	rec.mu.Lock()
	n := len(rec.lines)
	rec.mu.Unlock()
	if n != 0 {
		t.Errorf("%d Nachrichten trotz Sperre", n)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func TestSyslogServerPortBusy(t *testing.T) {
	port := syslogFreePort(t)
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	rec := &syslogRec{}
	s := NewSyslogServer(sensorTestLog(), port, nil, rec.feed)
	err = s.Start(context.Background())
	defer s.Stop()
	st := s.Status()
	if err == nil || !strings.HasPrefix(st.Error, "tcp: ") || !st.UDP || st.TCP {
		t.Fatalf("err=%v Status=%+v", err, st)
	}
	u := syslogDial(t, "udp", port)
	_, _ = u.Write([]byte("<13>udp laeuft weiter"))
	if got := rec.wait(t, 1); got[0].Message != "udp laeuft weiter" {
		t.Errorf("%+v", got[0])
	}
	// ungueltiger Port
	bad := NewSyslogServer(sensorTestLog(), 70000, nil, nil)
	if err := bad.Start(context.Background()); err == nil || bad.Status().Error == "" {
		t.Error("Port 70000 angenommen")
	}
	bad.Stop()
}

func TestSyslogServerLimits(t *testing.T) {
	s, rec, port := syslogStartTest(t, nil, func(s *SyslogServer) {
		s.maxConns = 2
		s.idle = 300 * time.Millisecond
	})
	_ = s
	c1 := syslogDial(t, "tcp", port)
	c2 := syslogDial(t, "tcp", port)
	_, _ = c1.Write([]byte("<13>a\n"))
	_, _ = c2.Write([]byte("<13>b\n"))
	rec.wait(t, 2)
	c3 := syslogDial(t, "tcp", port)
	_ = c3.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if _, err := c3.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Errorf("dritte Verbindung nicht abgewiesen: %v", err)
	}
	// Zeitlimit ohne Daten: c1/c2 werden geschlossen, danach ist wieder Platz
	for _, c := range []net.Conn{c1, c2} {
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
			t.Errorf("Leerlauf nicht geschlossen: %v", err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	c4 := syslogDial(t, "tcp", port)
	_, _ = c4.Write([]byte("<13>c\n"))
	if got := rec.wait(t, 3); got[2].Message != "c" {
		t.Errorf("%+v", got[2])
	}
	// kaputter Octet-Count schliesst die Verbindung
	c5 := syslogDial(t, "tcp", port)
	_, _ = c5.Write([]byte("9999999 x"))
	_ = c5.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c5.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Errorf("kaputter Octet-Count nicht geschlossen: %v", err)
	}
}

func TestSyslogServerGarbageAndPanic(t *testing.T) {
	var mu sync.Mutex
	after := false
	port := syslogFreePort(t)
	s := NewSyslogServer(sensorTestLog(), port, nil, func(l LogLine) {
		mu.Lock()
		if l.Message == "danach" {
			after = true
		}
		mu.Unlock()
		if strings.Contains(l.Message, "panik") {
			panic("Regel kaputt")
		}
	})
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	rnd := rand.New(rand.NewSource(2))
	junk := make([]byte, 20000)
	rnd.Read(junk)
	c := syslogDial(t, "tcp", port)
	_, _ = c.Write(junk)
	_ = c.Close()
	u := syslogDial(t, "udp", port)
	_, _ = u.Write([]byte("<13>panik"))
	_, _ = u.Write(junk[:1000])
	_, _ = u.Write([]byte("<13>danach"))
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		done := after
		mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Empfaenger nach Muell/Panik nicht mehr aktiv")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st := s.Status(); !st.UDP || !st.TCP {
		t.Errorf("Status: %+v", st)
	}
}

func TestSyslogServerStop(t *testing.T) {
	rec := &syslogRec{}
	port := syslogFreePort(t)
	s := NewSyslogServer(sensorTestLog(), port, nil, rec.feed)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil { // zweites Start: nichts
		t.Fatal(err)
	}
	var conns []net.Conn
	for i := 0; i < 5; i++ {
		c := syslogDial(t, "tcp", port)
		_, _ = c.Write([]byte("<13>halb offen ohne Zeilenende"))
		conns = append(conns, c)
	}
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	s.Stop()
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Stop dauerte %v", d)
	}
	if st := s.Status(); st.UDP || st.TCP {
		t.Errorf("nach Stop: %+v", st)
	}
	for _, c := range conns {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
			t.Errorf("Verbindung nach Stop offen: %v", err)
		}
	}
	s.Stop() // doppelt: kein Haenger
	// erneut starten (UDP und TCP wieder offen)
	if err := s.Start(context.Background()); err != nil {
		t.Logf("Neustart: %v", err) // TCP-Port kann unter Windows kurz belegt sein
	}
	if st := s.Status(); !st.UDP {
		t.Errorf("Neustart: %+v", st)
	}
	s.Stop()
}
