package honeypot

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// sensorRec sammelt die Ereignisse eines Sensors im Test.
type sensorRec struct {
	mu sync.Mutex
	ev []Event
}

func (r *sensorRec) sink(e Event) {
	r.mu.Lock()
	r.ev = append(r.ev, e)
	r.mu.Unlock()
}

func (r *sensorRec) all() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.ev...)
}

// wait wartet auf das erste passende Ereignis.
func (r *sensorRec) wait(t *testing.T, match func(Event) bool) Event {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range r.all() {
			if match(e) {
				return e
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Ereignis nicht gefunden; bisher: %+v", r.all())
	return Event{}
}

func (r *sensorRec) count(match func(Event) bool) int {
	n := 0
	for _, e := range r.all() {
		if match(e) {
			n++
		}
	}
	return n
}

func sensorKind(k string) func(Event) bool { return func(e Event) bool { return e.Kind == k } }

func sensorFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

func sensorTestLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// sensorStart oeffnet die Dienste und prueft, dass alle offen sind.
func sensorStart(t *testing.T, cfg Config) (*Sensor, *sensorRec) {
	t.Helper()
	s := NewSensor(sensorTestLog(), t.TempDir())
	rec := &sensorRec{}
	for _, st := range s.Apply(context.Background(), cfg, rec.sink) {
		if !st.Listen {
			t.Fatalf("Dienst nicht offen: %+v", st)
		}
	}
	t.Cleanup(s.Stop)
	return s, rec
}

func sensorAddrOf(port int) string { return "127.0.0.1:" + strconv.Itoa(port) }

func sensorWaitCounter(t *testing.T, f func() int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for f() < want {
		if time.Now().After(deadline) {
			t.Fatalf("Zaehler %d, erwartet %d", f(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSensorApplyIdempotent(t *testing.T) {
	p1, p2, p3, p4 := sensorFreePort(t), sensorFreePort(t), sensorFreePort(t), sensorFreePort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcTCP, p1, ""}, {SvcTCP, p2, ""}}})
	s.mu.Lock()
	t1 := s.svcs[sensorKey{SvcTCP, p1, ""}]
	s.mu.Unlock()

	// offene Verbindung auf p1 ueberlebt Apply
	c, err := net.Dial("tcp", sensorAddrOf(p1))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sensorWaitCounter(t, s.counters.Connections.Load, 1)

	busy, err := net.Listen("tcp", ":"+strconv.Itoa(p3))
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	s.SetPortCheck(func(service string, port int) error {
		if port == p4 {
			return errors.New("port reserved")
		}
		return nil
	})
	st := s.Apply(context.Background(), Config{Services: []Service{{SvcTCP, p1, ""}, {SvcTCP, p3, ""}, {SvcTCP, p4, ""}, {"gopher", 70, ""}}}, rec.sink)
	if len(st) != 4 {
		t.Fatalf("Status: %+v", st)
	}
	if !st[0].Listen || st[0].Port != p1 || st[0].Conns != 1 {
		t.Fatalf("p1: %+v", st[0])
	}
	if st[1].Listen || st[1].Error == "" {
		t.Fatalf("belegter Port: %+v", st[1])
	}
	if st[2].Listen || st[2].Error != "port reserved" {
		t.Fatalf("Port-Pruefung: %+v", st[2])
	}
	if st[3].Error != "unknown service" {
		t.Fatalf("ungueltiger Dienst: %+v", st[3])
	}
	s.mu.Lock()
	same := s.svcs[sensorKey{SvcTCP, p1, ""}] == t1 && t1.ln != nil
	s.mu.Unlock()
	if !same {
		t.Fatal("p1 wurde neu geoeffnet")
	}
	if _, err := c.Write([]byte("still here")); err != nil {
		t.Fatal(err)
	}
	rec.wait(t, func(e Event) bool { return e.Port == p1 && string(e.Payload) == "still here" })

	// p2 ist zu
	if c2, err := net.DialTimeout("tcp", sensorAddrOf(p2), 3*time.Second); err == nil {
		c2.Close()
		t.Fatal("p2 noch offen")
	}

	// Port wieder frei -> naechstes Apply oeffnet ihn
	busy.Close()
	st = s.Apply(context.Background(), Config{Services: []Service{{SvcTCP, p1, ""}, {SvcTCP, p3, ""}}}, rec.sink)
	if !st[1].Listen || st[1].Error != "" {
		t.Fatalf("p3 nach Freigabe: %+v", st[1])
	}

	s.Stop()
	if len(s.Status()) != 0 {
		t.Fatalf("Status nach Stop: %+v", s.Status())
	}
	if c3, err := net.DialTimeout("tcp", sensorAddrOf(p1), 3*time.Second); err == nil {
		c3.Close()
		t.Fatal("p1 nach Stop noch offen")
	}
}

func TestSensorLimits(t *testing.T) {
	p := sensorFreePort(t)
	s, _ := sensorStart(t, Config{Services: []Service{{SvcTCP, p, ""}}, MaxConnsPerIP: 2})
	var keep []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", sensorAddrOf(p))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		keep = append(keep, c)
	}
	sensorWaitCounter(t, s.counters.Connections.Load, 2)

	c, err := net.Dial("tcp", sensorAddrOf(p))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("dritte Verbindung nicht abgewiesen")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("dritte Verbindung nicht abgewiesen (Zeitlimit)")
	}
	sensorWaitCounter(t, s.counters.Dropped.Load, 1)
	if n := s.counters.Connections.Load(); n != 2 {
		t.Fatalf("Connections = %d", n)
	}

	// nach dem Schliessen einer Verbindung geht wieder eine
	keep[0].Close()
	sensorWaitCounter(t, func() int64 {
		s.connMu.Lock()
		defer s.connMu.Unlock()
		return int64(2 - s.nconns) // frei gewordene Plaetze
	}, 1)
	c4, err := net.Dial("tcp", sensorAddrOf(p))
	if err != nil {
		t.Fatal(err)
	}
	defer c4.Close()
	sensorWaitCounter(t, s.counters.Connections.Load, 3)
}
