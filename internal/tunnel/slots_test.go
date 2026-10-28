package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// rawHello: Anmeldung von Hand ueber TCP (Slot frei waehlbar).
func rawHello(t *testing.T, f *fixture, slot int) Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel) // die Sitzung haengt am Kontext des Aufbaus: erst am Ende des Tests abbrechen
	sess, err := dialTCP(ctx, f.addrT.String(), &tls.Config{ServerName: "edge.test", RootCAs: f.pool, MinVersion: tls.VersionTLS13, NextProtos: []string{ALPN}})
	if err != nil {
		t.Fatal(err)
	}
	ctrl, err := sess.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeMsg(ctrl, Hello{Version: Version, Tunnel: "t1", Token: "secret", Slot: slot}); err != nil {
		t.Fatal(err)
	}
	var w Welcome
	if err := readMsg(bufio.NewReader(ctrl), &w); err != nil || w.Error != "" {
		t.Fatalf("welcome: %+v %v", w, err)
	}
	return sess
}

func closedSoon(s Session) bool {
	select {
	case <-s.Done():
		return true
	case <-time.After(3 * time.Second):
		return false
	}
}

// Je Tunnel und Slot eine Verbindung: eine zweite ersetzt die erste; ein weiterer Stream der Node beendet die Sitzung.
func TestTunnelSlotReplacedAndExtraStream(t *testing.T) {
	f := newFixture(t)
	s1 := rawHello(t, f, 0)
	<-f.peers
	s2 := rawHello(t, f, 0)
	<-f.peers
	if !closedSoon(s1) {
		t.Fatal("old session of the slot not closed")
	}
	f.srv.mu.Lock()
	n := len(f.srv.slots)
	f.srv.mu.Unlock()
	if n != 1 {
		t.Fatalf("slots: %d", n)
	}
	st, err := s2.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = st.Write([]byte("x"))
	if !closedSoon(s2) {
		t.Fatal("session with an unexpected stream not closed")
	}
}

// Slot ueber der Grenze des Servers: aus, aber nach der Pause neu versucht (Klasse angehoben, Update-Wettlauf).
func TestTunnelSlotRetry(t *testing.T) {
	f := newFixture(t)
	var limit atomic.Int64
	limit.Store(1)
	f.srv.Sessions = func(string) int { return int(limit.Load()) }
	c := NewClient(ClientConfig{Tunnel: "t1", Token: "secret", Node: "test", Sessions: 2, RootCAs: f.pool,
		Edges:   []Edge{{Name: "e1", Host: "edge.test", Port: f.addrT.(*net.TCPAddr).Port}},
		Handler: func(st Stream, _ Header) { _ = st.Close() }})
	c.resolve = func(context.Context, Edge) []net.IP { return []net.IP{net.ParseIP("127.0.0.1")} }
	c.forceTCP, c.offWait = true, 200*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	waitFor(t, "one session", func() bool { s := c.Status()[0]; return s.Sessions == 1 && s.Wanted == 1 })
	limit.Store(2)
	waitFor(t, "second slot again", func() bool { s := c.Status()[0]; return s.Sessions == 2 && s.Wanted == 2 })
}
