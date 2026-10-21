package cdnedge

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/tunnel"
)

// Portmapper Modus 1/2: TCP und UDP durch den Tunnel zur Node (direkt bei B, bei A ueber den Nachbarn B), Pause,
// Node ohne Faehigkeit "ports".
func TestPortmapTunnel(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	secret := strings.Repeat("s", 40)
	tok := "node-token"
	cfgB := &Config{Name: "B", ListenHTTP: freeAddr(t), TunnelListen: freeAddr(t), PeerListen: freeAddr(t), PeerSecret: secret,
		TLSCert: cf, TLSKey: kf, Tunnels: []TunnelEntry{{ID: "t1", TokenSHA256: sha256hex(tok)}}, DataDir: t.TempDir(), PortRange: "1024-65535"}
	cfgA := &Config{Name: "A", ListenHTTP: freeAddr(t), PeerListen: freeAddr(t), PeerSecret: secret, TLSCert: cf, TLSKey: kf,
		Peers: []PeerEntry{{Name: "B", Addr: cfgB.PeerListen}}, DataDir: t.TempDir(), PortRange: "1024-65535"}
	b := startEdge(t, cfgB, pool)
	a := startEdge(t, cfgA, pool)
	got := make(chan tunnel.Header, 16)
	handler := func(st tunnel.Stream, h tunnel.Header) {
		got <- h
		defer st.Close()
		switch h.Kind {
		case tunnel.KindTCP: // Stream der Node: Echo mit Kennung
			buf := make([]byte, 100)
			n, _ := st.Read(buf)
			_, _ = io.WriteString(st, "N"+strconv.Itoa(h.Port)+":"+string(buf[:n]))
		case tunnel.KindUDP:
			buf := make([]byte, tunnel.MaxDatagram)
			for {
				n, err := tunnel.ReadDatagram(st, buf)
				if err != nil {
					return
				}
				if err := tunnel.WriteDatagram(st, append([]byte("U"+strconv.Itoa(h.Port)+":"), buf[:n]...)); err != nil {
					return
				}
			}
		}
	}
	node := tunnel.NewClient(tunnel.ClientConfig{Tunnel: "t1", Token: tok, RootCAs: pool, Caps: []string{tunnel.CapPorts},
		Edges: []tunnel.Edge{{Name: "B", Host: "127.0.0.1", Port: port(cfgB.TunnelListen)}}, Handler: handler})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go node.Run(ctx)
	for i := 0; i < 200 && b.peer("t1") == nil; i++ {
		time.Sleep(25 * time.Millisecond)
	}
	if b.peer("t1") == nil {
		t.Fatal("node not connected")
	}
	freeUDP := func() int {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		_, p, _ := net.SplitHostPort(pc.LocalAddr().String())
		n, _ := strconv.Atoi(p)
		return n
	}
	bt, bu, at, au := port(freeAddr(t)), freeUDP(), port(freeAddr(t)), freeUDP()
	conf := func(blocked string, tcp, udp int) *apiConfig {
		return &apiConfig{Tunnels: []apiTunnel{{ID: "t1", TokenSHA256: sha256hex(tok), UserID: 1}}, Hosts: []apiHost{
			{ID: 1, Name: "m1.test", Mode: 1, UserID: 1, Tunnels: []string{"t1"}, Blocked: blocked,
				Mappings: []apiMapping{{Listen: tcp, Transport: "tcp", Port: 2222}, {Listen: udp, Transport: "udp", Port: 51820}}}}}
	}
	b.applyConfig(conf("", bt, bu))
	a.applyConfig(conf("", at, au))
	tcpTalk := func(p int) string {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(p), 3*time.Second)
		if err != nil {
			return "dial: " + err.Error()
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte("hi"))
		bb, _ := io.ReadAll(c)
		return string(bb)
	}
	udpTalk := func(p int, msg string) string {
		c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: p})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = c.Write([]byte(msg))
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		bb := make([]byte, 100)
		n, err := c.Read(bb)
		if err != nil {
			return "err: " + err.Error()
		}
		return string(bb[:n])
	}
	if r := tcpTalk(bt); r != "N2222:hi" {
		t.Fatalf("tcp direct: %q", r)
	}
	if h := <-got; h.Kind != tunnel.KindTCP || h.Host != "m1.test" || h.Port != 2222 || !strings.HasPrefix(h.Client, "127.0.0.1:") {
		t.Fatalf("header: %+v", h)
	}
	if r := udpTalk(bu, "ping"); r != "U51820:ping" {
		t.Fatalf("udp direct: %q", r)
	}
	<-got
	if r := tcpTalk(at); r != "N2222:hi" {
		t.Fatalf("tcp via neighbour: %q", r)
	}
	<-got
	if r := udpTalk(au, "pong"); r != "U51820:pong" {
		t.Fatalf("udp via neighbour: %q", r)
	}
	<-got
	if v := a.stats.of("m1.test").ViaPeer.Load(); v != 2 {
		t.Fatalf("via peer: %d", v)
	}
	if st := b.stats.of("m1.test"); st.Conns.Load() < 2 || st.BytesIn.Load() == 0 || st.BytesOut.Load() == 0 {
		t.Fatalf("stats B: conns %d in %d out %d", st.Conns.Load(), st.BytesIn.Load(), st.BytesOut.Load())
	}
	if st := a.stats.of("m1.test"); st.Conns.Load() != 0 || st.BytesIn.Load() != 0 {
		t.Fatalf("A must not count (B counts): conns %d in %d", st.Conns.Load(), st.BytesIn.Load())
	}
	// Pause: nichts geht mehr zur Node
	b.applyConfig(conf("paused", bt, bu))
	if r := tcpTalk(bt); r != "" {
		t.Fatalf("paused tcp: %q", r)
	}
	if r := udpTalk(bu, "x"); !strings.HasPrefix(r, "err:") {
		t.Fatalf("paused udp: %q", r)
	}
	select {
	case h := <-got:
		t.Fatalf("paused name reached the node: %+v", h)
	default:
	}
}

// Node ohne Faehigkeit "ports" (aeltere Version): der Server oeffnet keinen Stream.
func TestPortmapTunnelNoCap(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	tok := "node-token"
	cfg := &Config{Name: "B", ListenHTTP: freeAddr(t), TunnelListen: freeAddr(t), TLSCert: cf, TLSKey: kf,
		Tunnels: []TunnelEntry{{ID: "t1", TokenSHA256: sha256hex(tok)}}, DataDir: t.TempDir(), PortRange: "1024-65535"}
	b := startEdge(t, cfg, pool)
	streams := make(chan string, 4)
	node := tunnel.NewClient(tunnel.ClientConfig{Tunnel: "t1", Token: tok, RootCAs: pool,
		Edges:   []tunnel.Edge{{Name: "B", Host: "127.0.0.1", Port: port(cfg.TunnelListen)}},
		Handler: func(st tunnel.Stream, h tunnel.Header) { streams <- h.Kind; _ = st.Close() }})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go node.Run(ctx)
	for i := 0; i < 200 && b.peer("t1") == nil; i++ {
		time.Sleep(25 * time.Millisecond)
	}
	p := port(freeAddr(t))
	b.applyConfig(&apiConfig{Tunnels: []apiTunnel{{ID: "t1", TokenSHA256: sha256hex(tok), UserID: 1}}, Hosts: []apiHost{
		{ID: 1, Name: "m1.test", Mode: 1, UserID: 1, Tunnels: []string{"t1"}, Mappings: []apiMapping{{Listen: p, Transport: "tcp", Port: 22}}}}})
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(p), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = c.Read(make([]byte, 1))
	c.Close()
	if err == nil {
		t.Fatal("connection must be closed")
	}
	select {
	case k := <-streams:
		t.Fatalf("stream %q opened to a node without port mappings", k)
	default:
	}
	if b.stats.of("m1.test").NoTunnel.Load() != 1 {
		t.Fatal("no tunnel counter")
	}
}
