package tunnel

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Serverliste aendern (Server je Account, Ersatz bei Ausfall): ein neuer Server kommt dazu, ohne dass der bleibende neu
// verbindet; ein entfernter wird getrennt; nach dem Ende von Run startet SetEdges nichts mehr.
func TestSetEdges(t *testing.T) {
	f1 := newFixture(t)
	f2 := &fixture{peers: make(chan *Peer, 8), srv: &Server{Name: "e2", TLS: f1.srv.TLS, Auth: f1.srv.Auth}} // gleiches Zertifikat
	f2.srv.Up = func(p *Peer) { f2.peers <- p }
	var err error
	if f2.addrQ, err = f2.srv.ServeQUIC("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f2.srv.Close)
	edge := func(name string, f *fixture) Edge {
		return Edge{Name: name, Host: "edge.test", Port: f.addrQ.(*net.UDPAddr).Port}
	}
	c := NewClient(ClientConfig{Tunnel: "t1", Token: "secret", Node: "test", Edges: []Edge{edge("a", f1)}, RootCAs: f1.pool,
		Handler: func(st Stream, h Header) { _ = st.Close() }})
	c.resolve = func(context.Context, Edge) []net.IP { return []net.IP{net.ParseIP("127.0.0.1")} }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.Run(ctx) }()
	var pa *Peer
	select {
	case pa = <-f1.peers:
	case <-time.After(10 * time.Second):
		t.Fatal("no tunnel to a")
	}
	waitFor(t, "a connected", func() bool { return c.Status()[0].Connected })

	c.SetEdges([]Edge{edge("a", f1), edge("b", f2)})
	select {
	case <-f2.peers:
	case <-time.After(10 * time.Second):
		t.Fatal("no tunnel to b")
	}
	waitFor(t, "both connected", func() bool { s := c.Status(); return len(s) == 2 && s[0].Connected && s[1].Connected })
	if s := c.Status()[0]; s.Reconnects != 1 || len(f1.peers) != 0 {
		t.Fatalf("a must stay connected: %+v, new peers %d", s, len(f1.peers))
	}
	select {
	case <-pa.Session.Done():
		t.Fatal("tunnel to a closed")
	default:
	}

	c.SetEdges([]Edge{edge("b", f2)})
	select {
	case <-pa.Session.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("removed server a still connected")
	}
	if s := c.Status(); len(s) != 1 || s[0].Name != "b" || !s[0].Connected || s[0].Reconnects != 1 {
		t.Fatalf("status: %+v", s)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run does not end")
	}
	c.SetEdges([]Edge{edge("a", f1)}) // nach Run: nur die Liste
	time.Sleep(200 * time.Millisecond)
	if len(f1.peers) != 0 {
		t.Fatal("started after Run ended")
	}
}

// Verbindungen je Server aendern (Auswahl je Tunnel): eine zweite kommt dazu, die erste bleibt; zurueck auf eine
// beendet nur die zweite.
func TestSetSessions(t *testing.T) {
	f0 := newFixture(t)
	var four atomic.Int64
	four.Store(4)
	f := limitFixture(t, f0, &four)
	c := f.client("secret", false, func(st Stream, h Header) { _ = st.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	var p0 *Peer
	select {
	case p0 = <-f.peers:
	case <-time.After(10 * time.Second):
		t.Fatal("no tunnel")
	}
	c.SetSessions(2)
	var p1 *Peer
	select {
	case p1 = <-f.peers:
	case <-time.After(10 * time.Second):
		t.Fatal("no second session")
	}
	waitFor(t, "two sessions", func() bool { return c.Status()[0].Sessions == 2 })
	if s := c.Status()[0]; s.Slots != 2 || time.Since(s.Changed) > 10*time.Second { // Anzeige "im Aufbau" der Node
		t.Fatalf("slots/changed: %+v", s)
	}
	select {
	case <-p0.Session.Done():
		t.Fatal("first session closed")
	default:
	}
	c.SetSessions(1)
	select {
	case <-p1.Session.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("second session still open")
	}
	waitFor(t, "one session", func() bool { s := c.Status()[0]; return s.Sessions == 1 && s.Wanted == 1 })
	select {
	case <-p0.Session.Done():
		t.Fatal("first session closed")
	default:
	}
}

// Server und Verbindungen im selben Abgleich (Auswahl 1x4 nach 3x1): beide Reihenfolgen, dazu ein neuer Server mit
// gleichzeitiger Erhoehung - der bleibende bzw. neue Server bekommt alle vier Verbindungen. Die Server kennen die hoehere
// Grenze erst kurz danach (Konfiguration alle 10 s): die abgelehnten Slots versuchen es bald erneut, nicht erst in Minuten.
func TestSetSessionsAndEdges(t *testing.T) {
	for _, order := range []string{"sessions-first", "edges-first", "new-edge"} {
		t.Run(order, func(t *testing.T) {
			f0 := newFixture(t)
			var limit atomic.Int64
			limit.Store(1)
			f1, f2 := limitFixture(t, f0, &limit), limitFixture(t, f0, &limit)
			a := Edge{Name: "a", Host: "edge.test", Port: f1.addrQ.(*net.UDPAddr).Port}
			b := Edge{Name: "b", Host: "edge.test", Port: f2.addrQ.(*net.UDPAddr).Port}
			start := []Edge{a, b}
			if order == "new-edge" {
				start = []Edge{a}
			}
			c := NewClient(ClientConfig{Tunnel: "t1", Token: "secret", Node: "test", Edges: start, RootCAs: f1.pool, Handler: func(st Stream, h Header) { _ = st.Close() }})
			c.resolve = func(context.Context, Edge) []net.IP { return []net.IP{net.ParseIP("127.0.0.1")} }
			c.offQuick, c.offWait = 300*time.Millisecond, time.Hour // nur der schnelle Weg darf hier wirken
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go c.Run(ctx)
			waitFor(t, "started", func() bool {
				for _, s := range c.Status() {
					if !s.Connected {
						return false
					}
				}
				return true
			})
			switch order {
			case "sessions-first":
				c.SetSessions(4)
				c.SetEdges([]Edge{b})
			case "edges-first":
				c.SetEdges([]Edge{b})
				c.SetSessions(4)
			case "new-edge":
				c.SetSessions(4)
				c.SetEdges([]Edge{b})
			}
			time.Sleep(200 * time.Millisecond)
			limit.Store(4) // die Server haben die neue Konfiguration
			waitFor(t, "four sessions on b", func() bool {
				s := c.Status()
				return len(s) == 1 && s[0].Name == "b" && s[0].Sessions == 4 && s[0].Wanted == 4
			})
		})
	}
}

// limitFixture: weiterer Test-Server mit dem Zertifikat von f und einer Grenze der Verbindungen je Tunnel, gesetzt vor
// dem Start (sonst liest der Handshake das Feld waehrend des Setzens).
func limitFixture(t *testing.T, f *fixture, limit *atomic.Int64) *fixture {
	t.Helper()
	g := &fixture{peers: make(chan *Peer, 16), pool: f.pool}
	g.srv = &Server{Name: "e", TLS: f.srv.TLS, Auth: f.srv.Auth, Up: func(p *Peer) { g.peers <- p }, Sessions: func(string) int { return int(limit.Load()) }}
	var err error
	if g.addrQ, err = g.srv.ServeQUIC("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if g.addrT, err = g.srv.ServeTCP("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.srv.Close)
	return g
}
