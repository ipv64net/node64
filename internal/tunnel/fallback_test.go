package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"
)

// QUIC gesperrt: dieselbe Runde verbindet ueber TCP und zeigt "UDP blockiert"; geht QUIC wieder, wechselt die
// Verbindung von selbst zurueck (erst die neue, dann endet die alte) und die Anzeige stimmt wieder.
func TestTunnelFallbackAndBackToQUIC(t *testing.T) {
	oldEvery, oldBusy := quicProbeEvery, quicSwitchBusy
	quicProbeEvery, quicSwitchBusy = 200*time.Millisecond, time.Minute
	t.Cleanup(func() { quicProbeEvery, quicSwitchBusy = oldEvery, oldBusy })

	conf, pool := testCert(t)
	peers := make(chan *Peer, 8)
	srv := &Server{Name: "e1", TLS: conf, Up: func(p *Peer) { peers <- p }}
	t.Cleanup(srv.Close)
	addrT, err := srv.ServeTCP("127.0.0.1:0") // QUIC (UDP) auf demselben Port laeuft erst spaeter
	if err != nil {
		t.Fatal(err)
	}
	port := addrT.(*net.TCPAddr).Port
	c := NewClient(ClientConfig{Tunnel: "t1", Token: "x", Node: "test", AltPort: -1, Edges: []Edge{{Name: "e1", Host: "edge.test", Port: port}},
		RootCAs: pool, Handler: func(st Stream, h Header) { _ = st.Close() }})
	c.resolve = func(context.Context, Edge) []net.IP { return []net.IP{net.ParseIP("127.0.0.1")} }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	for i := 0; i < 600; i++ {
		if s := c.Status()[0]; s.Connected {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if s := c.Status()[0]; !s.Connected || s.Transport != "tcp" || !s.UDPBlocked {
		t.Fatalf("fallback: %+v", s)
	}
	if _, err := srv.ServeQUIC("127.0.0.1:" + strconv.Itoa(port)); err != nil {
		t.Skip("UDP port taken: ", err)
	}
	waitFor(t, "back on quic", func() bool {
		s := c.Status()[0]
		return s.Connected && s.Transport == "quic" && !s.UDPBlocked
	})
	quic := false
	for len(peers) > 0 {
		if p := <-peers; p.Session.Transport() == "quic" {
			quic = true
		}
	}
	if !quic {
		t.Fatal("server did not see a QUIC session")
	}
}

// Kein Versuch ueber TCP, wenn QUIC am Server (Ablehnung, Grenze) oder an der Namensaufloesung scheitert.
func TestQUICOnlyFailure(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		err  error
		want bool
	}{
		{errors.New("timeout: no recent network activity"), true},
		{errRejected{"bad token"}, false},
		{fmt.Errorf("x: %w", errRejected{"bad token"}), false},
		{errSlotOff, false},
		{fmt.Errorf("edge.test: %w", errNoAddress), false},
		{nil, false},
	} {
		if got := quicOnlyFailure(ctx, c.err); got != c.want {
			t.Errorf("%v: %v", c.err, got)
		}
	}
	done, cancel := context.WithCancel(ctx)
	cancel()
	if quicOnlyFailure(done, errors.New("x")) {
		t.Error("cancelled context")
	}
}
