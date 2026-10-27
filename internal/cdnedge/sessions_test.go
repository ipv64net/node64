package cdnedge

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/tunnel"
)

// Parallele Tunnel-Verbindungen (Business/Company): der Server laesst nur so viele zu, wie ipv64 erlaubt, verteilt
// neue Besucher auf die am wenigsten belastete und nutzt die anderen weiter, wenn eine wegfaellt.
func TestParallelSessions(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	tok := "node-token"
	cfg := &Config{Name: "B", ListenHTTP: freeAddr(t), TunnelListen: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: t.TempDir(),
		Tunnels: []TunnelEntry{{ID: "t1", TokenSHA256: sha256hex(tok), Sessions: 2}}, Hosts: []HostEntry{{Name: "app.test", Tunnel: "t1"}}}
	b := startEdge(t, cfg, pool)
	hold := make(chan struct{})
	node := tunnel.NewClient(tunnel.ClientConfig{Tunnel: "t1", Token: tok, RootCAs: pool, Sessions: 3, // einer mehr als erlaubt
		Edges: []tunnel.Edge{{Name: "B", Host: "127.0.0.1", Port: port(cfg.TunnelListen)}},
		Handler: func(st tunnel.Stream, h tunnel.Header) {
			defer st.Close()
			req, err := http.ReadRequest(bufio.NewReader(st))
			if err != nil {
				return
			}
			if req.URL.Path == "/hold" {
				<-hold
			}
			_, _ = io.WriteString(st, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok")
		}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go node.Run(ctx)
	peers := func() []*tunnel.Peer {
		b.mu.Lock()
		defer b.mu.Unlock()
		return append([]*tunnel.Peer(nil), b.peers["t1"]...)
	}
	for i := 0; i < 200 && len(peers()) < 2; i++ {
		time.Sleep(25 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // dritter Slot wird abgewiesen
	if n := len(peers()); n != 2 {
		t.Fatalf("server sessions: %d, want 2", n)
	}
	st := node.Status()
	if len(st) != 1 || st[0].Sessions != 2 || st[0].Wanted != 2 || !st[0].Connected {
		t.Fatalf("node status: %+v", st)
	}
	// Last verteilen: 6 offene Anfragen gleichzeitig -> beide Verbindungen genutzt
	get := func(path string) (string, error) {
		c, err := net.DialTimeout("tcp", cfg.ListenHTTP, 3*time.Second)
		if err != nil {
			return "", err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(c, "GET "+path+" HTTP/1.1\r\nHost: app.test\r\n\r\n")
		b, err := io.ReadAll(c)
		return string(b), err
	}
	done := make(chan string, 6)
	for range 6 {
		go func() { r, _ := get("/hold"); done <- r }()
	}
	for i := 0; i < 200; i++ {
		p := peers()
		if len(p) == 2 && p[0].Streams.Load()+p[1].Streams.Load() == 6 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if p := peers(); p[0].Streams.Load() < 1 || p[1].Streams.Load() < 1 || p[0].Streams.Load()+p[1].Streams.Load() != 6 {
		t.Fatalf("streams per session: %d / %d, want both used", p[0].Streams.Load(), p[1].Streams.Load())
	}
	close(hold)
	for range 6 {
		if r := <-done; !strings.HasSuffix(r, "ok") {
			t.Fatalf("held request: %q", r)
		}
	}
	// eine Verbindung faellt weg: die andere traegt weiter
	p := peers()
	_ = p[0].Session.Close("test")
	for i := 0; i < 100 && len(peers()) != 1; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if r, err := get("/"); err != nil || !strings.HasSuffix(r, "ok") {
		t.Fatalf("after losing one session: %q %v", r, err)
	}
	// die Node verbindet den Slot neu
	for i := 0; i < 300 && len(peers()) < 2; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if n := len(peers()); n != 2 {
		t.Fatalf("slot not reconnected: %d sessions", n)
	}
}

// Ohne Angabe von ipv64 bleibt es bei einer Verbindung; eine Node mit mehreren Slots nutzt nur den ersten.
func TestParallelSessionsDefaultOne(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	tok := "node-token"
	cfg := &Config{Name: "B", ListenHTTP: freeAddr(t), TunnelListen: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: t.TempDir(),
		Tunnels: []TunnelEntry{{ID: "t1", TokenSHA256: sha256hex(tok)}}}
	b := startEdge(t, cfg, pool)
	node := tunnel.NewClient(tunnel.ClientConfig{Tunnel: "t1", Token: tok, RootCAs: pool, Sessions: 4,
		Edges:   []tunnel.Edge{{Name: "B", Host: "127.0.0.1", Port: port(cfg.TunnelListen)}},
		Handler: func(st tunnel.Stream, _ tunnel.Header) { _ = st.Close() }})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go node.Run(ctx)
	for i := 0; i < 200 && b.peer("t1") == nil; i++ {
		time.Sleep(25 * time.Millisecond)
	}
	time.Sleep(400 * time.Millisecond)
	b.mu.Lock()
	n := len(b.peers["t1"])
	b.mu.Unlock()
	if st := node.Status(); n != 1 || st[0].Sessions != 1 || st[0].Wanted != 1 {
		t.Fatalf("sessions: server %d, node %+v", n, st)
	}
}

// Klasse abgesenkt (z. B. Business 4 -> 2): der Server trennt die Verbindungen ueber der neuen Grenze, die Node
// laesst die Slots danach aus.
func TestParallelSessionsLowered(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	tok := "node-token"
	cfg := &Config{Name: "B", ListenHTTP: freeAddr(t), TunnelListen: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: t.TempDir()}
	b := startEdge(t, cfg, pool)
	b.applyConfig(&apiConfig{Tunnels: []apiTunnel{{ID: "t1", TokenSHA256: sha256hex(tok), Sessions: 3}}})
	node := tunnel.NewClient(tunnel.ClientConfig{Tunnel: "t1", Token: tok, RootCAs: pool, Sessions: 3,
		Edges:   []tunnel.Edge{{Name: "B", Host: "127.0.0.1", Port: port(cfg.TunnelListen)}},
		Handler: func(st tunnel.Stream, _ tunnel.Header) { _ = st.Close() }})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go node.Run(ctx)
	n := func() int {
		b.mu.Lock()
		defer b.mu.Unlock()
		return len(b.peers["t1"])
	}
	for i := 0; i < 200 && n() < 3; i++ {
		time.Sleep(25 * time.Millisecond)
	}
	if n() != 3 {
		t.Fatalf("sessions before: %d, want 3", n())
	}
	b.applyConfig(&apiConfig{Tunnels: []apiTunnel{{ID: "t1", TokenSHA256: sha256hex(tok), Sessions: 1}}})
	for i := 0; i < 200 && n() != 1; i++ {
		time.Sleep(25 * time.Millisecond)
	}
	for i := 0; i < 300; i++ { // die Node versucht die getrennten Slots neu (nach ihrer Wartezeit) und laesst sie aus
		if st := node.Status(); len(st) == 1 && st[0].Wanted == 1 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	b.mu.Lock()
	list := append([]*tunnel.Peer(nil), b.peers["t1"]...)
	b.mu.Unlock()
	if len(list) != 1 || list[0].Slot != 0 {
		t.Fatalf("sessions after lowering: %d", len(list))
	}
	if st := node.Status(); len(st) != 1 || st[0].Sessions != 1 || st[0].Wanted != 1 || !st[0].Connected {
		t.Fatalf("node status: %+v", st)
	}
}
