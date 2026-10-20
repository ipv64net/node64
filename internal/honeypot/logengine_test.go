package honeypot

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// engClock ist eine Uhr fuer Tests (kein echtes Warten).
type engClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *engClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *engClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// engRule trifft "<prefix> <ip>" (Fehlversuch), "<prefix>-ok <ip>" (Erfolg), "<prefix>-heavy <ip>" (Gewicht 5).
func engRule(id, prefix, svc string, thr int, win time.Duration) *LogRule {
	return &LogRule{ID: id, Version: 2, Kind: KindSSHBrute, Service: svc, Port: 22, Threshold: thr, Window: win,
		Match: func(l *LogLine) (LogHit, bool) {
			word, ip, ok := strings.Cut(l.Message, " ")
			if !ok {
				return LogHit{}, false
			}
			a, err := netip.ParseAddr(ip)
			if err != nil {
				return LogHit{}, false
			}
			switch word {
			case prefix:
				return LogHit{Src: a}, true
			case prefix + "-ok":
				return LogHit{Src: a, Success: true}, true
			case prefix + "-heavy":
				return LogHit{Src: a, Weight: 5, Port: 2222}, true
			case prefix + "-panic":
				panic("broken rule")
			}
			return LogHit{}, false
		}}
}

type engSink struct {
	mu  sync.Mutex
	evs []Event
}

func (s *engSink) sink(e Event) {
	s.mu.Lock()
	s.evs = append(s.evs, e)
	s.mu.Unlock()
}

func (s *engSink) n() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.evs)
}

func newEngTest(rules ...*LogRule) (*logEngine, *engClock, *engSink) {
	c := &engClock{t: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)}
	e := newLogEngine(nil, rules, c.now)
	s := &engSink{}
	e.setSink(s.sink)
	return e, c, s
}

func engFeed(e *logEngine, c *engClock, msg string) {
	e.feed(LogLine{Time: c.now(), Origin: SrcLog, Format: "syslog", Program: "test", Message: msg})
}

func TestLogEngineThreshold(t *testing.T) {
	e, c, s := newEngTest(engRule("a/brute", "fail", SvcSSH, 5, 10*time.Minute))
	for i := 0; i < 4; i++ {
		engFeed(e, c, "fail 203.0.113.1")
		c.add(time.Minute)
	}
	if s.n() != 0 {
		t.Fatal("event before threshold")
	}
	engFeed(e, c, "fail 203.0.113.1")
	if s.n() != 1 {
		t.Fatalf("events %d, want 1", s.n())
	}
	ev := s.evs[0]
	if ev.Src != netip.MustParseAddr("203.0.113.1") || ev.Kind != KindSSHBrute || ev.Service != SvcSSH || ev.Port != 22 ||
		ev.Source != SrcLog || ev.Rule != "a/brute@2" || ev.Detail != "a/brute" || !ev.Time.Equal(c.now()) {
		t.Fatalf("event %+v", ev)
	}
	if ev.Username != "" || ev.Password != "" || ev.Path != "" || ev.UA != "" || ev.Payload != nil || ev.Method != "" ||
		ev.Host != "" || ev.Client != "" || ev.SrcPort != 0 {
		t.Fatalf("event carries log content: %+v", ev)
	}
	if e.tracked() != 0 {
		t.Fatal("counter not reset after event")
	}
	// anhaltender Angriff: je weitere Schwelle wieder ein Ereignis
	for i := 0; i < 10; i++ {
		engFeed(e, c, "fail 203.0.113.1")
	}
	if s.n() != 3 {
		t.Fatalf("events %d, want 3", s.n())
	}
	if e.lines.Load() != 15 || e.hits.Load() != 15 || e.events.Load() != 3 {
		t.Fatalf("counters %d %d %d", e.lines.Load(), e.hits.Load(), e.events.Load())
	}
}

func TestLogEngineWindow(t *testing.T) {
	e, c, s := newEngTest(engRule("a/brute", "fail", SvcSSH, 5, 10*time.Minute))
	for i := 0; i < 4; i++ {
		engFeed(e, c, "fail 203.0.113.1")
	}
	c.add(11 * time.Minute) // Fenster abgelaufen: neu beginnen
	for i := 0; i < 4; i++ {
		engFeed(e, c, "fail 203.0.113.1")
	}
	if s.n() != 0 {
		t.Fatal("hits outside the window counted together")
	}
	engFeed(e, c, "fail 203.0.113.1")
	if s.n() != 1 {
		t.Fatalf("events %d, want 1", s.n())
	}
}

func TestLogEngineSuccessResets(t *testing.T) {
	a := engRule("a/brute", "fail", SvcSSH, 5, 10*time.Minute)
	b := engRule("b/brute", "other", SvcSSH, 5, 10*time.Minute)
	m := engRule("m/brute", "mail", SvcSMTP, 5, 10*time.Minute)
	e, c, s := newEngTest(a, b, m)
	for i := 0; i < 4; i++ {
		engFeed(e, c, "fail 203.0.113.1")
		engFeed(e, c, "other 203.0.113.1")
		engFeed(e, c, "mail 203.0.113.1")
		engFeed(e, c, "fail 203.0.113.2")
	}
	engFeed(e, c, "fail-ok 203.0.113.1") // Vertipper, dann Erfolg: alle Regeln mit Dienst ssh fuer diese IP
	engFeed(e, c, "fail 203.0.113.1")
	engFeed(e, c, "other 203.0.113.1")
	if s.n() != 0 {
		t.Fatalf("events after success: %+v", s.evs)
	}
	engFeed(e, c, "mail 203.0.113.1") // anderer Dienst: zaehlt weiter
	engFeed(e, c, "fail 203.0.113.2") // andere IP: zaehlt weiter
	if s.n() != 2 || s.evs[0].Kind != KindSSHBrute || s.evs[0].Service != SvcSMTP || s.evs[1].Src != netip.MustParseAddr("203.0.113.2") {
		t.Fatalf("events %+v", s.evs)
	}
	if e.hits.Load() != 20 {
		t.Fatalf("hits %d (success lines are no hits)", e.hits.Load())
	}
}

func TestLogEngineWeight(t *testing.T) {
	e, c, s := newEngTest(engRule("a/brute", "fail", SvcSSH, 5, 10*time.Minute))
	engFeed(e, c, "fail-heavy 2001:db8::1")
	if s.n() != 1 || s.evs[0].Port != 2222 || s.evs[0].Src != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("events %+v", s.evs)
	}
	engFeed(e, c, "fail ::ffff:203.0.113.9") // IPv4 in IPv6 zaehlt als IPv4
	for i := 0; i < 4; i++ {
		engFeed(e, c, "fail 203.0.113.9")
	}
	if s.n() != 2 || s.evs[1].Src != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("events %+v", s.evs)
	}
}

func TestLogEnginePrivateCounted(t *testing.T) {
	e, c, s := newEngTest(engRule("a/brute", "fail", SvcSSH, 2, 10*time.Minute))
	engFeed(e, c, "fail 192.168.1.5")
	engFeed(e, c, "fail 192.168.1.5")
	engFeed(e, c, "fail 127.0.0.1")
	engFeed(e, c, "fail 127.0.0.1")
	if s.n() != 2 {
		t.Fatalf("events %d, want 2", s.n())
	}
}

func TestLogEngineMemoryLimit(t *testing.T) {
	e, c, s := newEngTest(engRule("a/brute", "fail", SvcSSH, 2, 10*time.Minute))
	e.max = 3
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"} {
		engFeed(e, c, "fail "+ip)
		c.add(time.Second)
	}
	if e.tracked() != 3 {
		t.Fatalf("tracked %d, want 3", e.tracked())
	}
	engFeed(e, c, "fail 203.0.113.1") // aelteste fiel weg: beginnt neu
	if s.n() != 0 {
		t.Fatal("evicted counter survived")
	}
	engFeed(e, c, "fail 203.0.113.4")
	if s.n() != 1 || s.evs[0].Src != netip.MustParseAddr("203.0.113.4") {
		t.Fatalf("events %+v", s.evs)
	}
}

func TestLogEngineSweep(t *testing.T) {
	short := engRule("a/brute", "fail", SvcSSH, 5, time.Minute)
	long := engRule("b/brute", "slow", SvcSSH, 5, time.Hour)
	e, c, _ := newEngTest(short, long)
	for i := 1; i <= 50; i++ {
		engFeed(e, c, "fail 203.0.113."+itoa(i))
	}
	engFeed(e, c, "slow 198.51.100.1")
	c.add(5 * time.Minute)
	engFeed(e, c, "fail 198.51.100.2")
	if e.tracked() != 2 { // die 50 kurzen sind abgelaufen, der lange und der neue bleiben
		t.Fatalf("tracked %d, want 2", e.tracked())
	}
}

func TestLogEngineOriginAndPanic(t *testing.T) {
	r := engRule("a/brute", "fail", SvcSSH, 1, time.Minute)
	r.Origins = []string{SrcSyslog}
	e, c, s := newEngTest(engRule("p/brute", "boom", SvcSSH, 1, time.Minute), r)
	engFeed(e, c, "fail 203.0.113.1") // Datei: Regel gilt nur fuer Syslog
	if s.n() != 0 {
		t.Fatal("origin ignored")
	}
	e.feed(LogLine{Origin: SrcSyslog, Message: "fail 203.0.113.1"}) // ohne Zeit: Uhr der Engine
	if s.n() != 1 || s.evs[0].Source != SrcSyslog || !s.evs[0].Time.Equal(c.now()) {
		t.Fatalf("events %+v", s.evs)
	}
	engFeed(e, c, "boom-panic 203.0.113.1") // fehlerhafte Regel beendet nichts
}

func TestLogEngineConcurrent(t *testing.T) {
	e, c, s := newEngTest(engRule("a/brute", "fail", SvcSSH, 5, time.Hour))
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				engFeed(e, c, "fail 203.0.113."+itoa(i%10))
			}
		}(g)
	}
	wg.Wait()
	if s.n() != 800 || e.events.Load() != 800 || e.lines.Load() != 4000 {
		t.Fatalf("events %d lines %d, want 800/4000", s.n(), e.lines.Load())
	}
}

func TestLogParseAllow(t *testing.T) {
	got := logParseAllow([]string{" 10.0.0.0/8", "192.168.1.7", "bad", "", "2001:db8::/32", "::ffff:10.1.2.3"})
	want := []string{"10.0.0.0/8", "192.168.1.7/32", "2001:db8::/32", "10.1.2.3/32"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("%d: %v, want %s", i, got[i], want[i])
		}
	}
}

// Log-Sensor als Ganzes: Datei -> Regel -> Sink.

func TestLogSensorApply(t *testing.T) {
	dir := t.TempDir()
	auth := filepath.Join(dir, "auth.log")
	appendFile(t, auth, "Oct 20 11:00:00 box sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2\n")
	s := NewLogSensor(nil)
	t.Cleanup(s.Stop)
	sink := &engSink{}

	st := s.Apply(context.Background(), LogConfig{Files: []LogFile{{Path: auth}, {Path: " "}, {Path: auth}}}, sink.sink)
	if len(st.Files) != 1 || !st.Files[0].OK || st.Files[0].Format != "syslog" || st.Syslog != nil {
		t.Fatalf("status %+v", st)
	}
	for i := 0; i < 5; i++ {
		appendFile(t, auth, "Oct 20 12:00:0"+itoa(i)+" box sshd[1]: Failed password for invalid user admin"+itoa(i)+" from 203.0.113.50 port 4"+itoa(i)+" ssh2\n")
	}
	s.tail.poll()
	if sink.n() != 1 {
		t.Fatalf("events %d, want 1 (old line must not count)", sink.n())
	}
	ev := sink.evs[0]
	if ev.Source != SrcLog || ev.Rule != "sshd/bruteforce@1" || ev.Kind != KindSSHBrute || ev.Port != 22 ||
		ev.Username != "" || ev.Detail != "sshd/bruteforce" || ev.Src != netip.MustParseAddr("203.0.113.50") {
		t.Fatalf("event %+v", ev)
	}
	if st := s.Status(); st.Lines != 5 || st.Hits != 5 || st.Events != 1 || st.Files[0].Lines != 5 {
		t.Fatalf("status %+v", st)
	}

	// aendern: andere Datei; die alte wird geschlossen
	web := filepath.Join(dir, "access.log")
	appendFile(t, web, "")
	st = s.Apply(context.Background(), LogConfig{Files: []LogFile{{Path: web}}}, sink.sink)
	if len(st.Files) != 1 || st.Files[0].Path != web || st.Files[0].Format != "nginx" {
		t.Fatalf("status %+v", st)
	}
	appendFile(t, web, `203.0.113.51 - - [20/Oct/2026:12:00:01 +0200] "GET /.env HTTP/1.1" 404 1 "-" "-"`+"\n")
	s.tail.poll()
	if sink.n() != 2 || sink.evs[1].Kind != KindHTTPExploit || sink.evs[1].Path != "" || sink.evs[1].Rule != "nginx/exploit@1" {
		t.Fatalf("events %+v", sink.evs)
	}

	// aus
	st = s.Apply(context.Background(), LogConfig{}, sink.sink)
	if len(st.Files) != 0 || st.Syslog != nil || s.tail != nil {
		t.Fatalf("status %+v", st)
	}
	if err := os.Remove(auth); err != nil { // keine offenen Dateien mehr
		t.Fatal(err)
	}
}

func TestLogSensorSyslogOnOff(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	s := NewLogSensor(nil)
	t.Cleanup(s.Stop)
	st := s.Apply(context.Background(), LogConfig{SyslogPort: port, SyslogAllow: []string{"127.0.0.1/32"}}, nil)
	if st.Syslog == nil || st.Syslog.Port != port {
		t.Fatalf("syslog status %+v", st.Syslog)
	}
	first := s.sys
	if s.Apply(context.Background(), LogConfig{SyslogPort: port, SyslogAllow: []string{"127.0.0.1/32"}}, nil); s.sys != first && s.sysErr == nil {
		t.Fatal("unchanged syslog config restarted the receiver")
	}
	if st := s.Apply(context.Background(), LogConfig{}, nil); st.Syslog != nil || s.sys != nil {
		t.Fatalf("syslog still on: %+v", st.Syslog)
	}
}
