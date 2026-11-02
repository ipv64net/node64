package tunnel

import (
	"context"
	"net"
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
